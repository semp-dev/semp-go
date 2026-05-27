package handshake

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
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
//	resp, _ := s.OnInit(initBytes)        // may return Challenge bytes
//	// ... optional challenge round trip via OnChallengeResponse ...
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

	// TicketIssuer issues and opens resumption tickets per
	// HANDSHAKE.md §2.8 and SESSION.md §2.7. nil disables
	// resumption support: OnConfirm omits the resumption_ticket
	// field on the Accepted message and OnResume rejects.
	ticketIssuer session.TicketIssuer

	// Optional pinned randomness for the server's KEM step, outbound
	// nonce, and session_id. See ServerConfig docs.
	serverEphemeralPriv    []byte
	serverHybridRandomness *crypto.HybridEncapsRandomness
	serverNonceOverride    []byte
	sessionIDOverride      string

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
	clientIdentity    string
	clientDeviceKeyID keys.Fingerprint

	// Challenge gating state.
	pendingChallenge *Challenge
	deferredInit     []byte
}

// ServerConfig groups the inputs to NewServer.
type ServerConfig struct {
	// Suite is the algorithm suite the server prefers.
	Suite crypto.Suite

	// Store provides client identity public keys (for verifying the
	// identity_signature inside the encrypted identity proof).
	Store keys.Store

	// Policy supplies operator decisions: block lists, challenge gating,
	// TTL, permissions.
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

	// TicketIssuer enables resumption support per HANDSHAKE.md §2.8.
	// When non-nil, OnConfirm issues a fresh resumption_ticket on
	// every accepted handshake and OnResume becomes available for
	// short-circuit resumption flows. nil disables resumption: the
	// Accepted message omits resumption_ticket and clients fall back
	// to full handshakes on every reconnect.
	TicketIssuer session.TicketIssuer

	// ServerEphemeralPriv, when non-nil, pins the X25519 ephemeral
	// private key the server uses for its KEM step in OnInit. Used
	// ONLY by the baseline suite. Production callers MUST leave this
	// nil so the ephemeral is drawn from rand.Reader.
	//
	// Narrow uses: stateless-edge deployments that must rebuild
	// server state across two HTTP round-trips by stashing the
	// randomness consumed in OnInit, and cross-language test vectors.
	ServerEphemeralPriv []byte

	// ServerHybridRandomness, when non-nil, pins both the X25519
	// ephemeral private and the ML-KEM-768 encapsulation randomness
	// `m` the server uses for its KEM step in OnInit. Used ONLY by
	// the pq-kyber768-x25519 suite. Same narrow-use caveats as
	// ServerEphemeralPriv.
	ServerHybridRandomness *crypto.HybridEncapsRandomness

	// ServerNonce, when non-nil, pins the 32-byte server nonce OnInit
	// uses for the ServerResponse instead of drawing from rand.Reader.
	// Used in conjunction with ServerEphemeralPriv /
	// ServerHybridRandomness for full server-state determinism across
	// two HTTP round-trips.
	ServerNonce []byte

	// SessionIDOverride, when non-empty, pins the session_id OnInit
	// writes into the ServerResponse instead of generating a fresh
	// ULID. Used alongside the other pin fields to make the entire
	// ServerResponse byte-deterministic for stateless-edge replay.
	SessionIDOverride string
}

// Policy is the set of decisions a server delegates to its operator:
// should this handshake be challenge-gated, is the sender blocked,
// what TTL should the session get, what permissions should be granted
// on success.
type Policy interface {
	// RequireChallenge returns a non-nil Challenge if the server
	// requires the client to solve a challenge before proceeding.
	// The returned Challenge must have ChallengeType, Parameters,
	// and Expires populated. Returns nil when no challenge is needed.
	RequireChallenge(initNonce, transport string) *Challenge

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

// NewServer constructs a Server from a ServerConfig. When
// cfg.Capabilities is zero, the returned server advertises ONLY the
// suite it was constructed with (cfg.Suite.ID()) - any mismatch
// between what the server advertises and what it can actually speak
// would cause Negotiate to pick an unsupported suite and the
// handshake to fail mid-flight. Operators that run a single binary
// behind multiple suites should construct one Server per suite and
// route incoming connections to the right one, or build an explicit
// Capabilities object that lists every suite they have a Server
// configured for.
func NewServer(cfg ServerConfig) *Server {
	caps := cfg.Capabilities
	if len(caps.EncryptionAlgorithms) == 0 {
		suiteID := ""
		if cfg.Suite != nil {
			suiteID = string(cfg.Suite.ID())
		}
		caps = Capabilities{
			EncryptionAlgorithms: []string{suiteID},
			Extensions:           []string{},
		}
	}
	return &Server{
		suite:                  cfg.Suite,
		store:                  cfg.Store,
		policy:                 cfg.Policy,
		domain:                 cfg.Domain,
		domainKey:              cfg.DomainKeyID,
		domainPrivateKey:       cfg.DomainPrivateKey,
		capabilities:           caps,
		ticketIssuer:           cfg.TicketIssuer,
		serverEphemeralPriv:    cfg.ServerEphemeralPriv,
		serverHybridRandomness: cfg.ServerHybridRandomness,
		serverNonceOverride:    cfg.ServerNonce,
		sessionIDOverride:      cfg.SessionIDOverride,
	}
}

// serverEncapsulate dispatches between the entropy-driven Encapsulate
// and the derandomized free-function variants based on which config
// fields (if any) the caller pinned. Returns the same
// (sharedSecret, ciphertext) tuple Encapsulate does.
func (s *Server) serverEncapsulate(clientEphPub []byte) (shared, ct []byte, err error) {
	switch s.suite.ID() {
	case crypto.SuiteIDPQKyber768X25519:
		if s.serverHybridRandomness != nil {
			return crypto.HybridEncapsulateWithRandomness(clientEphPub, *s.serverHybridRandomness)
		}
	case crypto.SuiteIDX25519ChaCha20Poly1305:
		if s.serverEphemeralPriv != nil {
			return crypto.X25519EncapsulateWithRandomness(clientEphPub, s.serverEphemeralPriv)
		}
	}
	return s.suite.KEM().Encapsulate(clientEphPub)
}

// OnInit processes a message 1 (init/client) and returns either:
//   - a serialized Challenge (the caller transmits it; the next call
//     to the server is OnChallengeResponse),
//   - a serialized ServerResponse (the caller transmits it; the next
//     call is OnConfirm),
//   - or a non-nil error (the caller serializes a Rejected with
//     NewRejection and closes).
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

	// Challenge gating: defer further processing until the client
	// solves the challenge. We stash the original init bytes so we
	// can re-parse them in OnChallengeResponse.
	if s.policy != nil {
		if challenge := s.policy.RequireChallenge(init.Nonce, init.Transport); challenge != nil {
			signed, err := s.signServerMessage(challenge)
			if err != nil {
				return nil, err
			}
			challenge.ServerSignature = signed
			s.pendingChallenge = challenge
			s.deferredInit = append([]byte(nil), data...)
			return CanonicalForHashing(challenge)
		}
	}
	return s.processInit(&init)
}

// OnChallengeResponse processes a challenge_response message and
// either advances the handshake (returning the ServerResponse bytes)
// or returns an error from which the caller builds a
// `challenge_failed` Rejected (HANDSHAKE.md §2.2b).
func (s *Server) OnChallengeResponse(data []byte) ([]byte, error) {
	if s == nil || s.suite == nil {
		return nil, errors.New("handshake: nil server or suite")
	}
	if s.pendingChallenge == nil {
		return nil, errors.New("handshake: no challenge outstanding")
	}
	var sol ChallengeResponse
	if err := json.Unmarshal(data, &sol); err != nil {
		return nil, fmt.Errorf("handshake: parse challenge_response: %w", err)
	}
	if sol.Type != MessageType || sol.Step != StepChallengeResponse {
		return nil, errors.New("handshake: challenge_response type/step mismatch")
	}
	if sol.ChallengeID != s.pendingChallenge.ChallengeID {
		return nil, errors.New("handshake: challenge_response challenge_id mismatch")
	}
	// Dispatch based on the pending challenge's type.
	switch s.pendingChallenge.ChallengeType {
	case ChallengeTypeProofOfWork:
		var params PoWChallengeParams
		if err := json.Unmarshal(s.pendingChallenge.Parameters, &params); err != nil {
			return nil, fmt.Errorf("handshake: parse challenge parameters: %w", err)
		}
		var solData PoWSolutionData
		if err := json.Unmarshal(sol.Solution, &solData); err != nil {
			return nil, fmt.Errorf("handshake: parse challenge solution: %w", err)
		}
		prefix, err := base64.StdEncoding.DecodeString(params.Prefix)
		if err != nil {
			return nil, fmt.Errorf("handshake: challenge prefix base64: %w", err)
		}
		if err := VerifySolution(prefix, sol.ChallengeID, solData.Nonce, solData.Hash, params.Difficulty); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("handshake: unsupported challenge type %q", s.pendingChallenge.ChallengeType)
	}
	// Single-use: mark the challenge consumed.
	s.pendingChallenge = nil
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

	// Recompute and stash canonical(init) - used for the confirmation hash.
	initCanonical, err := CanonicalForHashing(init)
	if err != nil {
		return nil, fmt.Errorf("handshake: canonical init: %w", err)
	}

	// Responder-side KEM step: encapsulate under the initiator's
	// ephemeral public key to derive the shared secret and produce
	// the wire blob we send back as "server ephemeral key". For the
	// baseline X25519 suite this is equivalent to the legacy
	// GenerateKeyPair + Agree(ephPriv, clientEphPub) flow; for the
	// hybrid Kyber768+X25519 suite it additionally encapsulates a
	// Kyber shared key under the initiator's Kyber pub and packs
	// (responderX25519Pub || kyberCiphertext) as ephPub. The server
	// holds no ephemeral private key after this call - Encapsulate
	// zeroizes it internally.
	//
	// When the config pins serverEphemeralPriv (baseline) or
	// serverHybridRandomness (PQ), the KEM step is derandomized so
	// stateless-edge deployments can replay it across HTTP round-trips.
	shared, ephPub, err := s.serverEncapsulate(clientEphPub)
	if err != nil {
		return nil, fmt.Errorf("handshake: ephemeral KEM encapsulate: %w", err)
	}
	defer crypto.Zeroize(shared)

	var serverNonce []byte
	if len(s.serverNonceOverride) == 32 {
		serverNonce = append([]byte(nil), s.serverNonceOverride...)
	} else {
		serverNonce = make([]byte, 32)
		if _, err := rand.Read(serverNonce); err != nil {
			return nil, fmt.Errorf("handshake: server nonce: %w", err)
		}
	}
	var sessionID string
	if s.sessionIDOverride != "" {
		sessionID = s.sessionIDOverride
	} else {
		sessionID, err = newULID()
		if err != nil {
			return nil, err
		}
	}

	sessionKeys, err := crypto.DeriveSessionKeys(s.suite.KDF(), shared, clientNonce, serverNonce)
	if err != nil {
		return nil, fmt.Errorf("handshake: derive session keys: %w", err)
	}

	// Inner identity proof: signature over server_eph_pub || server_nonce
	// || client_nonce. Proves the server controls the long-term domain key
	// over its own contribution to the handshake. For the hybrid suite
	// the "server_eph_pub" bytes are the wire-level ciphertext blob
	// (responderX25519Pub || kyberCiphertext); that's what the client
	// will feed into Decapsulate, so signing those exact bytes gives
	// the client a binding between the server's identity and the
	// shared-secret-deriving blob it will process.
	rawProofMsg := make([]byte, 0, len(ephPub)+len(serverNonce)+len(clientNonce))
	rawProofMsg = append(rawProofMsg, ephPub...)
	rawProofMsg = append(rawProofMsg, serverNonce...)
	rawProofMsg = append(rawProofMsg, clientNonce...)
	innerProofMessage := crypto.PrefixedMessage(crypto.SigCtxIdentity, rawProofMsg)
	innerSig, err := s.suite.Signer().Sign(s.domainPrivateKey, innerProofMessage)
	if err != nil {
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
		sessionKeys.Erase()
		return nil, err
	}
	resp.ServerSignature = signed

	respCanonical, err := CanonicalForHashing(&resp)
	if err != nil {
		sessionKeys.Erase()
		return nil, fmt.Errorf("handshake: canonical response: %w", err)
	}

	// Commit state. The server no longer holds an ephemeral private
	// key - Encapsulate zeroized it internally - so ephemeralPriv is
	// left nil on the Server struct.
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
	signedPreimage := crypto.PrefixedMessage(crypto.SigCtxIdentity, append([]byte(conf.SessionID), expectedHash...))
	if err := s.suite.Signer().Verify(clientPub, signedPreimage, identitySig); err != nil {
		return nil, nil, fmt.Errorf("handshake: identity signature verify: %w", err)
	}

	// Identity is bound to the session. Build the Accepted message.
	s.clientIdentity = proof.ClientIdentity
	s.clientDeviceKeyID = keys.Fingerprint(proof.ClientLongTermKeyID)
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
	// Issue a resumption ticket per HANDSHAKE.md §2.8 if the server
	// supports it. The ticket binds the just-authenticated identity
	// to K_resumption so a later resume attempt can derive a fresh
	// session schedule per §2.8.3.
	if s.ticketIssuer != nil && len(s.sessionKeys.Resumption) > 0 {
		expires := time.Now().UTC().Add(session.MaxTicketLifetime)
		ticketBytes, err := s.ticketIssuer.Issue(context.Background(), proof.ClientIdentity, s.sessionKeys.Resumption, expires)
		if err != nil {
			return nil, nil, fmt.Errorf("handshake: issue resumption ticket: %w", err)
		}
		acc.ResumptionTicket = &ResumptionTicket{
			Value:     base64.StdEncoding.EncodeToString(ticketBytes),
			ExpiresAt: expires,
		}
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

// ClientDeviceKeyID returns the fingerprint of the client's long-
// term identity / device key from the identity proof in the
// confirm message. For a primary device this is the user's primary
// identity key; for a delegated device this is the device's own key
// (which the home server uses to look up the device certificate
// and enforce scope per CLIENT.md §2.4). Returns the empty
// fingerprint before OnConfirm has succeeded.
func (s *Server) ClientDeviceKeyID() keys.Fingerprint {
	if s == nil {
		return ""
	}
	return s.clientDeviceKeyID
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
			return nil, errors.New("handshake: identity verification failed")
		}
		return base64.StdEncoding.DecodeString(rec.PublicKey)
	}
	return nil, errors.New("handshake: identity verification failed")
}

func bytesEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// OnResume processes a Resume request per HANDSHAKE.md §2.8 and
// returns the canonical Accepted bytes plus the resumed
// *session.Session on success. On any failure it returns a typed
// error; the driver maps it to a Rejected with reason_code
// "resumption_failed" (or one of the identity-invalidation codes
// from §4.1 when the identity in the ticket has been revoked).
//
// The resumed session uses fresh ephemeral DH mixed with the
// resumption secret recovered from the ticket per §2.8.3, so it has
// forward secrecy independent of long-term ticket compromise. The
// authenticated identity carries forward from the original handshake;
// no fresh identity proof is required.
//
// Servers without a TicketIssuer configured MUST return an error
// here so the driver rejects with resumption_failed.
func (s *Server) OnResume(data []byte) (acceptedBytes []byte, sess *session.Session, err error) {
	if s == nil || s.suite == nil {
		return nil, nil, errors.New("handshake: nil server or suite")
	}
	if s.ticketIssuer == nil {
		return nil, nil, errors.New("handshake: server has no TicketIssuer; resumption disabled")
	}
	var resume Resume
	if err := json.Unmarshal(data, &resume); err != nil {
		return nil, nil, fmt.Errorf("handshake: parse resume: %w", err)
	}
	if resume.Type != MessageType || resume.Step != StepResume || resume.Party != PartyClient {
		return nil, nil, errors.New("handshake: resume type/step/party mismatch")
	}
	if resume.Nonce == "" {
		return nil, nil, errors.New("handshake: resume missing nonce")
	}
	if resume.ResumptionTicket == "" {
		return nil, nil, errors.New("handshake: resume missing resumption_ticket")
	}
	if resume.ClientEphemeralKey.Key == "" {
		return nil, nil, errors.New("handshake: resume missing client_ephemeral_key")
	}

	// Decode the opaque ticket bytes and open via TicketIssuer. Map
	// every issuer error to a generic "ticket failure" so the
	// outbound rejection does not leak which underlying reason
	// triggered the failure (corrupt vs expired vs consumed).
	ticketRaw, err := base64.StdEncoding.DecodeString(resume.ResumptionTicket)
	if err != nil {
		return nil, nil, fmt.Errorf("handshake: resumption_ticket base64: %w", err)
	}
	now := time.Now().UTC()
	ctx := context.Background()
	identity, resumptionSecret, _, err := s.ticketIssuer.Open(ctx, ticketRaw, now)
	if err != nil {
		return nil, nil, fmt.Errorf("handshake: open resumption ticket: %w", err)
	}
	defer crypto.Zeroize(resumptionSecret)

	// Mark consumed BEFORE we proceed: even if subsequent steps
	// fail, the ticket is single-use per §2.8.4. A failure after
	// this point still leaves the ticket dead, which is the safe
	// default.
	if err := s.ticketIssuer.Consume(ctx, ticketRaw); err != nil {
		return nil, nil, fmt.Errorf("handshake: mark ticket consumed: %w", err)
	}

	// Decode client's nonce and ephemeral pub.
	clientNonce, err := base64.StdEncoding.DecodeString(resume.Nonce)
	if err != nil {
		return nil, nil, fmt.Errorf("handshake: resume client nonce base64: %w", err)
	}
	clientEphPub, err := base64.StdEncoding.DecodeString(resume.ClientEphemeralKey.Key)
	if err != nil {
		return nil, nil, fmt.Errorf("handshake: resume client ephemeral base64: %w", err)
	}

	// Server-side KEM step: encapsulate against the client's
	// ephemeral pub, derive ephemeral_shared_secret. Server holds no
	// ephemeral private key after this call.
	ephShared, ephPub, err := s.suite.KEM().Encapsulate(clientEphPub)
	if err != nil {
		return nil, nil, fmt.Errorf("handshake: resume ephemeral KEM encapsulate: %w", err)
	}
	defer crypto.Zeroize(ephShared)

	// Fresh server nonce.
	serverNonce := make([]byte, 32)
	if _, err := rand.Read(serverNonce); err != nil {
		return nil, nil, fmt.Errorf("handshake: resume server nonce: %w", err)
	}

	// Derive resumed-session keys per §2.8.3: IKM = eph_shared || K_resumption.
	resumedKeys, err := crypto.DeriveResumedSessionKeys(s.suite.KDF(), ephShared, resumptionSecret, clientNonce, serverNonce)
	if err != nil {
		return nil, nil, fmt.Errorf("handshake: derive resumed keys: %w", err)
	}

	// Build a fresh session_id for the resumed session per §2.8.2
	// example. Identity carries forward from the ticket.
	newSessionID, err := newULID()
	if err != nil {
		resumedKeys.Erase()
		return nil, nil, err
	}

	// Issue a fresh ticket bound to the resumed session's K_resumption
	// so a future resume attempt can chain off this session per
	// §2.8.4.
	ticketExpires := now.Add(session.MaxTicketLifetime)
	newTicketBytes, err := s.ticketIssuer.Issue(ctx, identity, resumedKeys.Resumption, ticketExpires)
	if err != nil {
		resumedKeys.Erase()
		return nil, nil, fmt.Errorf("handshake: issue replacement ticket: %w", err)
	}

	ttl := 300
	permissions := []string{"send", "receive"}
	if s.policy != nil {
		if v := s.policy.SessionTTL(identity); v > 0 {
			ttl = v
		}
		if p := s.policy.Permissions(identity); p != nil {
			permissions = p
		}
	}
	acc := Accepted{
		Type:        MessageType,
		Step:        StepAccepted,
		Party:       PartyServer,
		Version:     "1.0.0",
		SessionID:   newSessionID,
		SessionTTL:  ttl,
		Permissions: permissions,
		ServerNonce: base64.StdEncoding.EncodeToString(serverNonce),
		ServerEphemeralKey: &EphemeralKey{
			Algorithm: string(s.suite.ID()),
			Key:       base64.StdEncoding.EncodeToString(ephPub),
			KeyID:     string(keys.Compute(ephPub)),
		},
		ResumptionTicket: &ResumptionTicket{
			Value:     base64.StdEncoding.EncodeToString(newTicketBytes),
			ExpiresAt: ticketExpires,
		},
		Extensions: extensions.Map{},
	}
	sigB64, err := s.signServerMessage(&acc)
	if err != nil {
		resumedKeys.Erase()
		return nil, nil, err
	}
	acc.ServerSignature = sigB64
	out, err := CanonicalForHashing(&acc)
	if err != nil {
		resumedKeys.Erase()
		return nil, nil, fmt.Errorf("handshake: canonical resumed accepted: %w", err)
	}

	sess = session.New(session.RoleClient)
	sess.ID = newSessionID
	sess.PeerIdentity = identity
	sess.State = session.StateActive
	sess.SetKeys(resumedKeys)
	sess.TTL = time.Duration(ttl) * time.Second
	now = time.Now()
	sess.EstablishedAt = now
	sess.ExpiresAt = now.Add(sess.TTL)

	// Commit the new identity onto the Server so subsequent
	// accessors (ClientIdentity / SessionID) reflect the resumed
	// session, mirroring OnConfirm's commit pattern.
	s.sessionID = newSessionID
	s.clientIdentity = identity
	return out, sess, nil
}
