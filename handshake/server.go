package handshake

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/semp-dev/semp-go/crypto"
	"github.com/semp-dev/semp-go/extensions"
	"github.com/semp-dev/semp-go/keys"
	"github.com/semp-dev/semp-go/session"
)

// Server drives the server side of a SEMP client handshake. It owns the
// server's ephemeral key pair, the proof-of-work decision, and the policy
// hooks (block list lookup, capacity check, capability negotiation).
//
// Lifecycle:
//
//	s := handshake.NewServer(cfg)
//	resp, _ := s.OnInit(initBytes)        // may return PoWRequired bytes
//	// ... optional PoW round trip via OnPoWSolution ...
//	accepted, sess, err := s.OnConfirm(confirmBytes)
//	// transmit accepted; session is ready
type Server struct {
	suite            crypto.Suite
	store            keys.Store
	policy           Policy
	domain           string
	domainKey        keys.Fingerprint
	domainPrivateKey []byte
	capabilities     Capabilities

	// Internal state populated by OnInit and consumed by OnConfirm.
	sessionID          string
	clientNonce        []byte
	serverNonce        []byte
	ephemeralPriv      []byte
	ephemeralPub       []byte
	clientEphemeralPub []byte
	initCanonical      []byte
	responseCanonical  []byte
	sessionKeys        *crypto.SessionKeys

	// Client identity established by OnConfirm.
	clientIdentity string

	// PoW gating state.
	pendingPoW   *PoWRequired
	deferredInit []byte
}

// ServerConfig groups the inputs to NewServer.
type ServerConfig struct {
	// Suite is the algorithm suite the server prefers.
	Suite crypto.Suite

	// Store provides client identity public keys (for verifying the
	// identity_signature inside the encrypted identity proof).
	Store keys.Store

	// Policy supplies operator decisions: block lists, PoW gating, TTL,
	// permissions.
	Policy Policy

	// Domain is the server's domain, e.g. "example.com".
	Domain string

	// DomainKeyID is the fingerprint of the server's domain public key.
	DomainKeyID keys.Fingerprint

	// DomainPrivateKey is the raw Ed25519 private key bytes used to sign
	// every outbound handshake message. Held only in memory.
	DomainPrivateKey []byte

	// Capabilities, if non-zero, overrides DefaultServerCapabilities.
	Capabilities Capabilities
}

// Policy is the set of decisions a server delegates to its operator: should
// this handshake be PoW-gated, is the sender blocked, what TTL should the
// session get, what permissions should be granted on success.
type Policy interface {
	// RequirePoW returns a non-nil challenge if the server requires the
	// client to solve a PoW before proceeding.
	RequirePoW(initNonce, transport string) *PoWRequired

	// BlockedDomain reports whether the given domain is blocked at the
	// pre-handshake level. SEMP servers MUST check block lists before
	// completing a handshake (DESIGN.md §7).
	BlockedDomain(domain string) bool

	// SessionTTL returns the lifetime in seconds for a session granted to
	// the given client identity.
	SessionTTL(identity string) int

	// Permissions returns the granted permissions for the given client
	// identity (e.g. "send", "receive", "create_group").
	Permissions(identity string) []string
}

// NewServer constructs a Server from a ServerConfig.
func NewServer(cfg ServerConfig) *Server {
	caps := cfg.Capabilities
	if len(caps.EncryptionAlgorithms) == 0 {
		caps = DefaultServerCapabilities()
	}
	return &Server{
		suite:            cfg.Suite,
		store:            cfg.Store,
		policy:           cfg.Policy,
		domain:           cfg.Domain,
		domainKey:        cfg.DomainKeyID,
		domainPrivateKey: cfg.DomainPrivateKey,
		capabilities:     caps,
	}
}

// OnInit processes a message 1 (init/client) and returns either:
//   - a serialized PoWRequired (the caller transmits it; the next call to
//     the server is OnPoWSolution),
//   - a serialized ServerResponse (the caller transmits it; the next call
//     is OnConfirm),
//   - or a non-nil error (the caller serializes a Rejected with NewRejection
//     and closes).
func (s *Server) OnInit(data []byte) ([]byte, error) {
	if s == nil || s.suite == nil {
		return nil, errors.New("handshake: nil server or suite")
	}
	var init ClientInit
	if err := json.Unmarshal(data, &init); err != nil {
		return nil, fmt.Errorf("handshake: parse init: %w", err)
	}
	if init.Type != MessageType || init.Step != StepInit || init.Party != PartyClient {
		return nil, errors.New("handshake: init type/step/party mismatch")
	}

	// PoW gating: defer further processing until the client solves the
	// challenge. We stash the original init bytes so we can re-parse them in
	// OnPoWSolution.
	if s.policy != nil {
		if challenge := s.policy.RequirePoW(init.Nonce, init.Transport); challenge != nil {
			signed, err := s.signServerMessage(challenge)
			if err != nil {
				return nil, err
			}
			challenge.ServerSignature = signed
			s.pendingPoW = challenge
			s.deferredInit = append([]byte(nil), data...)
			return CanonicalForHashing(challenge)
		}
	}
	return s.processInit(&init)
}

// OnPoWSolution processes a pow_solution message and either advances the
// handshake (returning the ServerResponse bytes) or returns an error from
// which the caller builds a `pow_failed` Rejected
// (HANDSHAKE.md §2.2b, REPUTATION.md §8.3.4).
func (s *Server) OnPoWSolution(data []byte) ([]byte, error) {
	if s == nil || s.suite == nil {
		return nil, errors.New("handshake: nil server or suite")
	}
	if s.pendingPoW == nil {
		return nil, errors.New("handshake: no PoW challenge outstanding")
	}
	var sol PoWSolution
	if err := json.Unmarshal(data, &sol); err != nil {
		return nil, fmt.Errorf("handshake: parse pow_solution: %w", err)
	}
	if sol.Type != MessageType || sol.Step != StepPoWSolution {
		return nil, errors.New("handshake: pow_solution type/step mismatch")
	}
	if sol.ChallengeID != s.pendingPoW.ChallengeID {
		return nil, errors.New("handshake: pow_solution challenge_id mismatch")
	}
	prefix, err := base64.StdEncoding.DecodeString(s.pendingPoW.Prefix)
	if err != nil {
		return nil, fmt.Errorf("handshake: pow prefix base64: %w", err)
	}
	if err := VerifySolution(prefix, sol.ChallengeID, sol.Nonce, sol.Hash, s.pendingPoW.Difficulty); err != nil {
		return nil, err
	}
	// Single-use: mark the challenge consumed.
	s.pendingPoW = nil
	deferred := s.deferredInit
	s.deferredInit = nil

	if len(deferred) == 0 {
		return nil, errors.New("handshake: missing deferred init bytes")
	}
	var init ClientInit
	if err := json.Unmarshal(deferred, &init); err != nil {
		return nil, fmt.Errorf("handshake: re-parse deferred init: %w", err)
	}
	return s.processInit(&init)
}

// processInit performs the post-PoW work: capability negotiation, ephemeral
// keypair generation, session key derivation, and ServerResponse signing.
func (s *Server) processInit(init *ClientInit) ([]byte, error) {
	// Capability negotiation.
	negotiated, err := NegotiateCapabilities(init.Capabilities, s.capabilities)
	if err != nil {
		return nil, err
	}
	if negotiated.EncryptionAlgorithm != string(s.suite.ID()) {
		return nil, fmt.Errorf("handshake: negotiated suite %q does not match server suite %q",
			negotiated.EncryptionAlgorithm, s.suite.ID())
	}

	// Decode client nonce + ephemeral key.
	clientNonce, err := base64.StdEncoding.DecodeString(init.Nonce)
	if err != nil {
		return nil, fmt.Errorf("handshake: client nonce base64: %w", err)
	}
	clientEphPub, err := base64.StdEncoding.DecodeString(init.ClientEphemeralKey.Key)
	if err != nil {
		return nil, fmt.Errorf("handshake: client ephemeral key base64: %w", err)
	}

	// Recompute and stash canonical(init) — used for the confirmation hash.
	initCanonical, err := CanonicalForHashing(init)
	if err != nil {
		return nil, fmt.Errorf("handshake: canonical init: %w", err)
	}

	// Generate the server's ephemeral keypair, nonce, and session ID.
	ephPub, ephPriv, err := s.suite.KEM().GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("handshake: ephemeral keypair: %w", err)
	}
	serverNonce := make([]byte, 32)
	if _, err := rand.Read(serverNonce); err != nil {
		crypto.Zeroize(ephPriv)
		return nil, fmt.Errorf("handshake: server nonce: %w", err)
	}
	sessionID, err := newULID()
	if err != nil {
		crypto.Zeroize(ephPriv)
		return nil, err
	}

	// Compute the shared secret and derive session keys.
	shared, err := s.suite.KEM().Agree(ephPriv, clientEphPub)
	if err != nil {
		crypto.Zeroize(ephPriv)
		return nil, fmt.Errorf("handshake: ephemeral DH: %w", err)
	}
	defer crypto.Zeroize(shared)
	sessionKeys, err := crypto.DeriveSessionKeys(s.suite.KDF(), shared, clientNonce, serverNonce)
	if err != nil {
		crypto.Zeroize(ephPriv)
		return nil, fmt.Errorf("handshake: derive session keys: %w", err)
	}

	// Inner identity proof: signature over server_eph_pub || server_nonce
	// || client_nonce. Proves the server controls the long-term domain key
	// over its own contribution to the handshake.
	innerProofMessage := make([]byte, 0, len(ephPub)+len(serverNonce)+len(clientNonce))
	innerProofMessage = append(innerProofMessage, ephPub...)
	innerProofMessage = append(innerProofMessage, serverNonce...)
	innerProofMessage = append(innerProofMessage, clientNonce...)
	innerSig, err := s.suite.Signer().Sign(s.domainPrivateKey, innerProofMessage)
	if err != nil {
		crypto.Zeroize(ephPriv)
		sessionKeys.Erase()
		return nil, fmt.Errorf("handshake: server identity proof sign: %w", err)
	}

	resp := ServerResponse{
		Type:        MessageType,
		Step:        StepResponse,
		Party:       PartyServer,
		Version:     "1.0.0",
		SessionID:   sessionID,
		ClientNonce: init.Nonce,
		ServerNonce: base64.StdEncoding.EncodeToString(serverNonce),
		ServerEphemeralKey: EphemeralKey{
			Algorithm: string(s.suite.ID()),
			Key:       base64.StdEncoding.EncodeToString(ephPub),
			KeyID:     string(keys.Compute(ephPub)),
		},
		ServerIdentityProof: ServerIdentityProof{
			Domain:    s.domain,
			KeyID:     string(s.domainKey),
			Signature: base64.StdEncoding.EncodeToString(innerSig),
		},
		Negotiated: negotiated,
		Extensions: extensions.Map{},
	}
	signed, err := s.signServerMessage(&resp)
	if err != nil {
		crypto.Zeroize(ephPriv)
		sessionKeys.Erase()
		return nil, err
	}
	resp.ServerSignature = signed

	respCanonical, err := CanonicalForHashing(&resp)
	if err != nil {
		crypto.Zeroize(ephPriv)
		sessionKeys.Erase()
		return nil, fmt.Errorf("handshake: canonical response: %w", err)
	}

	// Erase the ephemeral private key now that the shared secret is derived.
	crypto.Zeroize(ephPriv)

	// Commit state.
	s.sessionID = sessionID
	s.clientNonce = clientNonce
	s.serverNonce = serverNonce
	s.ephemeralPub = ephPub
	s.ephemeralPriv = nil
	s.clientEphemeralPub = clientEphPub
	s.initCanonical = initCanonical
	s.responseCanonical = respCanonical
	s.sessionKeys = sessionKeys
	return respCanonical, nil
}

// OnConfirm processes message 3 (confirm/client), verifies the encrypted
// identity proof, and returns either the Accepted bytes plus a fully
// initialized Session, or an error from which the caller builds a Rejected.
func (s *Server) OnConfirm(data []byte) (acceptedBytes []byte, sess *session.Session, err error) {
	if s == nil || s.suite == nil {
		return nil, nil, errors.New("handshake: nil server or suite")
	}
	if s.sessionKeys == nil {
		return nil, nil, errors.New("handshake: OnConfirm called before OnInit")
	}
	var conf ClientConfirm
	if err := json.Unmarshal(data, &conf); err != nil {
		return nil, nil, fmt.Errorf("handshake: parse confirm: %w", err)
	}
	if conf.Type != MessageType || conf.Step != StepConfirm || conf.Party != PartyClient {
		return nil, nil, errors.New("handshake: confirm type/step/party mismatch")
	}
	if conf.SessionID != s.sessionID {
		return nil, nil, errors.New("handshake: confirm session_id mismatch")
	}

	// Recompute the expected confirmation hash.
	expectedHash, err := ConfirmationHash(s.initCanonical, s.responseCanonical)
	if err != nil {
		return nil, nil, err
	}
	gotHash, err := base64.StdEncoding.DecodeString(conf.ConfirmationHash)
	if err != nil {
		return nil, nil, fmt.Errorf("handshake: confirmation_hash base64: %w", err)
	}
	if !bytesEqual(expectedHash, gotHash) {
		return nil, nil, errors.New("handshake: confirmation hash mismatch")
	}

	// Decrypt the identity proof.
	wrapped, err := base64.StdEncoding.DecodeString(conf.IdentityProof)
	if err != nil {
		return nil, nil, fmt.Errorf("handshake: identity_proof base64: %w", err)
	}
	aead := s.suite.AEAD()
	if len(wrapped) < aead.NonceSize()+aead.Overhead() {
		return nil, nil, errors.New("handshake: identity_proof truncated")
	}
	nonceSize := aead.NonceSize()
	nonce := wrapped[:nonceSize]
	ct := wrapped[nonceSize:]
	proofBytes, err := aead.Open(s.sessionKeys.EncC2S, nonce, ct, []byte(conf.SessionID))
	if err != nil {
		return nil, nil, fmt.Errorf("handshake: decrypt identity_proof: %w", err)
	}
	var proof IdentityProofBlock
	if err := json.Unmarshal(proofBytes, &proof); err != nil {
		return nil, nil, fmt.Errorf("handshake: parse identity_proof: %w", err)
	}

	// Look up the client's long-term identity public key and verify the
	// identity_signature.
	clientPub, err := s.lookupClientIdentityKey(proof.ClientIdentity, keys.Fingerprint(proof.ClientLongTermKeyID))
	if err != nil {
		return nil, nil, err
	}
	identitySig, err := base64.StdEncoding.DecodeString(proof.IdentitySignature)
	if err != nil {
		return nil, nil, fmt.Errorf("handshake: identity_signature base64: %w", err)
	}
	signedPreimage := append([]byte(conf.SessionID), expectedHash...)
	if err := s.suite.Signer().Verify(clientPub, signedPreimage, identitySig); err != nil {
		return nil, nil, fmt.Errorf("handshake: identity signature verify: %w", err)
	}

	// Identity is bound to the session. Build the Accepted message.
	s.clientIdentity = proof.ClientIdentity
	ttl := 300
	permissions := []string{"send", "receive"}
	if s.policy != nil {
		if v := s.policy.SessionTTL(proof.ClientIdentity); v > 0 {
			ttl = v
		}
		if p := s.policy.Permissions(proof.ClientIdentity); p != nil {
			permissions = p
		}
	}
	acc := Accepted{
		Type:        MessageType,
		Step:        StepAccepted,
		Party:       PartyServer,
		Version:     "1.0.0",
		SessionID:   conf.SessionID,
		SessionTTL:  ttl,
		Permissions: permissions,
		Extensions:  extensions.Map{},
	}
	sigB64, err := s.signServerMessage(&acc)
	if err != nil {
		return nil, nil, err
	}
	acc.ServerSignature = sigB64
	out, err := CanonicalForHashing(&acc)
	if err != nil {
		return nil, nil, fmt.Errorf("handshake: canonical accepted: %w", err)
	}

	// Build the session for the caller. Ownership of sessionKeys transfers
	// to sess; we clear our pointer so that Erase will not double-free.
	now := time.Now()
	sess = session.New(session.RoleClient)
	sess.ID = s.sessionID
	sess.PeerIdentity = proof.ClientIdentity
	sess.State = session.StateActive
	sess.SetKeys(s.sessionKeys)
	sess.TTL = time.Duration(ttl) * time.Second
	sess.EstablishedAt = now
	sess.ExpiresAt = now.Add(sess.TTL)
	s.sessionKeys = nil
	return out, sess, nil
}

// NewRejection builds a signed Rejected message with the given reason code
// and human-readable reason. Servers send this when any handshake step
// fails. The session_id is included if known.
func (s *Server) NewRejection(reasonCode, reason string) ([]byte, error) {
	rej := Rejected{
		Type:       MessageType,
		Step:       StepRejected,
		Party:      PartyServer,
		Version:    "1.0.0",
		SessionID:  s.sessionID,
		ReasonCode: reasonCode,
		Reason:     reason,
		Extensions: extensions.Map{},
	}
	sig, err := s.signServerMessage(&rej)
	if err != nil {
		return nil, err
	}
	rej.ServerSignature = sig
	return CanonicalForHashing(&rej)
}

// SessionID returns the server-assigned session ID once OnInit has produced
// a response. Returns the empty string before that point.
func (s *Server) SessionID() string {
	if s == nil {
		return ""
	}
	return s.sessionID
}

// ClientIdentity returns the client identity confirmed by OnConfirm. Returns
// the empty string before OnConfirm has succeeded.
func (s *Server) ClientIdentity() string {
	if s == nil {
		return ""
	}
	return s.clientIdentity
}

// Erase wipes the server-side ephemeral private key and any retained
// handshake state. After Erase, the server is unusable for further calls
// on the same handshake instance.
func (s *Server) Erase() {
	if s == nil {
		return
	}
	crypto.Zeroize(s.ephemeralPriv)
	crypto.Zeroize(s.clientNonce)
	crypto.Zeroize(s.serverNonce)
	s.ephemeralPriv = nil
	s.clientNonce = nil
	s.serverNonce = nil
	s.initCanonical = nil
	s.responseCanonical = nil
	s.deferredInit = nil
	if s.sessionKeys != nil {
		s.sessionKeys.Erase()
		s.sessionKeys = nil
	}
}

func (s *Server) signServerMessage(msg any) (string, error) {
	return SignServerMessage(s.suite, s.domainPrivateKey, msg)
}

func (s *Server) lookupClientIdentityKey(identity string, keyID keys.Fingerprint) ([]byte, error) {
	if s.store == nil {
		return nil, errors.New("handshake: nil key store")
	}
	records, err := s.store.LookupUserKeys(context.Background(), identity, keys.TypeIdentity)
	if err != nil {
		return nil, fmt.Errorf("handshake: lookup client identity key: %w", err)
	}
	for _, rec := range records {
		if rec.KeyID != keyID {
			continue
		}
		if rec.Revocation != nil {
			return nil, errors.New("handshake: client identity key is revoked")
		}
		return base64.StdEncoding.DecodeString(rec.PublicKey)
	}
	return nil, fmt.Errorf("handshake: client identity key %s not found for %s", keyID, identity)
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
