package handshake

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"semp.dev/semp-go/crypto"
	"semp.dev/semp-go/extensions"
	"semp.dev/semp-go/keys"
	"semp.dev/semp-go/session"
)

// FederationType identifies the federation mode requested by the initiator
// (HANDSHAKE.md §5.2.1).
type FederationType string

// FederationType values.
const (
	FederationFull    FederationType = "full"
	FederationRelay   FederationType = "relay"
	FederationLimited FederationType = "limited"
)

// ServerInit is the message 1 sent by an initiating server in a federation
// handshake (HANDSHAKE.md §5.2). Unlike the client init, the server init
// includes the originating server's domain identity in plaintext.
//
// The Extensions field is intentionally NOT marked omitempty: the canonical
// form of an init message MUST always include `"extensions":{}` so that the
// confirmation hash computed by the responder reproduces byte for byte.
type ServerInit struct {
	Type                string          `json:"type"`  // SEMP_HANDSHAKE
	Step                Step            `json:"step"`  // StepInit
	Party               Party           `json:"party"` // PartyServer
	Version             string          `json:"version"`
	Nonce               string          `json:"nonce"`
	ServerID            string          `json:"server_id"`
	ServerDomain        string          `json:"server_domain"`
	FederationType      FederationType  `json:"federation_type"`
	ServerEphemeralKey  EphemeralKey    `json:"server_ephemeral_key"`
	ServerIdentityProof FederationProof `json:"server_identity_proof"`
	DomainProof         DomainProof     `json:"domain_proof"`
	Capabilities        Capabilities    `json:"capabilities"`
	ServerSignature     string          `json:"server_signature"`
	Extensions          extensions.Map  `json:"extensions"`
}

// FederationProof is the abbreviated identity proof used in federation
// init/response messages. The signature is over the canonical bytes
// `eph_pub || nonce_bytes` (init) or `eph_pub || responder_nonce ||
// initiator_nonce` (response). It binds the long-term domain key to the
// ephemeral key without depending on the surrounding message envelope.
type FederationProof struct {
	KeyID     string `json:"key_id"`
	Signature string `json:"signature"`
}

// DomainProof is one of the domain ownership verification methods accepted
// in a federation handshake (HANDSHAKE.md §5.3).
type DomainProof struct {
	// Method is one of "dns-txt", "certificate", "well-known".
	Method string `json:"method"`
	// Data is the verification payload, format determined by Method.
	Data string `json:"data"`
}

// Domain verification methods.
const (
	DomainVerifyDNSTXT     = "dns-txt"
	DomainVerifyCert       = "certificate"
	DomainVerifyWellKnown  = "well-known"
	DomainVerifyTestTrust  = "test-trust" // test fixture only; never accept in production
)

// FederationResponse is message 2 in the federation handshake. It mirrors
// the client `ServerResponse` but carries `server_id`, `server_domain`,
// `domain_verification_result`, and `federation_policy` instead of the
// client-oriented identity proof.
type FederationResponse struct {
	Type                     string                   `json:"type"`
	Step                     Step                     `json:"step"`
	Party                    Party                    `json:"party"`
	Version                  string                   `json:"version"`
	SessionID                string                   `json:"session_id"`
	ClientNonce              string                   `json:"client_nonce"` // initiator nonce, echoed
	ServerNonce              string                   `json:"server_nonce"` // responder nonce
	ServerID                 string                   `json:"server_id"`
	ServerDomain             string                   `json:"server_domain"`
	ServerEphemeralKey       EphemeralKey             `json:"server_ephemeral_key"`
	ServerIdentityProof      FederationProof          `json:"server_identity_proof"`
	DomainVerificationResult DomainVerificationResult `json:"domain_verification_result"`
	Negotiated               Negotiated               `json:"negotiated"`
	FederationPolicy         FederationPolicy         `json:"federation_policy"`
	ServerSignature          string                   `json:"server_signature"`
	Extensions               extensions.Map           `json:"extensions"`
}

// DomainVerificationResult reports the responder's check of the initiator's
// DomainProof, per HANDSHAKE.md §5.4.
type DomainVerificationResult struct {
	// Status is "verified" on success or a short failure tag like
	// "rejected" or "unverified" otherwise. The detail field carries the
	// machine-readable reason on failure.
	Status string `json:"status"`
	// Method echoes the verification method that was attempted.
	Method string `json:"method"`
	// Detail is an optional human-readable explanation. Operator-facing
	// only; do not parse programmatically.
	Detail string `json:"detail,omitempty"`
}

// Status values for DomainVerificationResult.
const (
	DomainStatusVerified   = "verified"
	DomainStatusRejected   = "rejected"
	DomainStatusUnverified = "unverified"
)

// FederationPolicy is the operator-defined policy block returned by the
// responder in message 2 (HANDSHAKE.md §5.4). The initiator MUST decide
// whether to accept it before sending message 3.
type FederationPolicy struct {
	// MessageRetention is a duration string (e.g. "7d", "30d", "0") describing
	// how long the responder retains delivered envelopes.
	MessageRetention string `json:"message_retention"`
	// UserDiscovery declares whether per-user discovery is permitted on
	// this federation. Values: "allowed", "denied".
	UserDiscovery string `json:"user_discovery"`
	// RelayAllowed declares whether the responder will accept envelopes
	// the initiator forwards on behalf of a third party.
	RelayAllowed bool `json:"relay_allowed"`
}

// FederationConfirm is message 3 in the federation handshake.
type FederationConfirm struct {
	Type                 string               `json:"type"`
	Step                 Step                 `json:"step"`
	Party                Party                `json:"party"`
	Version              string               `json:"version"`
	SessionID            string               `json:"session_id"`
	ConfirmationHash     string               `json:"confirmation_hash"`
	FederationAcceptance FederationAcceptance `json:"federation_acceptance"`
	ServerSignature      string               `json:"server_signature"`
	Extensions           extensions.Map       `json:"extensions"`
}

// FederationAcceptance is the initiator's acceptance of the policy returned
// in message 2 (HANDSHAKE.md §5.5). If `Accepted` is false, the initiator
// MUST also include a Reason and the responder MUST treat the handshake as
// rejected by the initiator.
type FederationAcceptance struct {
	Accepted           bool   `json:"accepted"`
	PolicyAcknowledged bool   `json:"policy_acknowledged"`
	Reason             string `json:"reason,omitempty"`
}

// FederationAccepted is the responder's success outcome (HANDSHAKE.md §5.6).
// SessionTTL is the lifetime in seconds; the spec example does not show it
// but SESSION.md requires every active session to have a TTL, so we surface
// it through the same field used by the client handshake.
type FederationAccepted struct {
	Type            string         `json:"type"`
	Step            Step           `json:"step"`
	Party           Party          `json:"party"`
	Version         string         `json:"version"`
	SessionID       string         `json:"session_id"`
	Status          string         `json:"status"`      // always "accepted"
	SessionTTL      int            `json:"session_ttl"` // seconds
	ServerSignature string         `json:"server_signature"`
	Extensions      extensions.Map `json:"extensions"`
}

// DomainVerifier checks a DomainProof presented by the initiator during the
// federation handshake. Implementations talk to DNS, validate certificate
// chains, or fetch well-known URIs as appropriate.
//
// Verify returns nil if the proof is valid for the given domain and proof
// values, and an error otherwise. The returned error message is surfaced
// in DomainVerificationResult.Detail; callers SHOULD avoid leaking secrets
// through it.
type DomainVerifier interface {
	Verify(ctx context.Context, domain string, proof DomainProof, initNonce string) error
}

// TrustingDomainVerifier accepts every proof unconditionally. It is intended
// for tests and single-process deployments where domain ownership is already
// established out of band. Production deployments MUST NOT use it.
type TrustingDomainVerifier struct{}

// Verify implements DomainVerifier.
func (TrustingDomainVerifier) Verify(_ context.Context, _ string, _ DomainProof, _ string) error {
	return nil
}

// ResolveCollision implements the simultaneous-handshake collision rule
// from SESSION.md §2.5.2: when two federation servers initiate handshakes
// to each other at the same time, the session whose `session_id` sorts
// LOWER lexicographically MUST be abandoned and the OTHER session proceeds.
//
// ResolveCollision returns the winning session_id (the one that proceeds).
// Both peers, given the same pair of IDs, MUST agree on the winner without
// any external coordination — strings.Compare provides exactly this property.
//
// Reference: SESSION.md §2.5.2.
func ResolveCollision(idA, idB string) string {
	if strings.Compare(idA, idB) > 0 {
		return idA
	}
	return idB
}

// =============================================================================
// Initiator
// =============================================================================

// Initiator drives the side of a federation handshake that opens the
// connection. Symmetric to handshake.Client but uses the federation message
// types and exposes federation-specific fields (server_domain, domain_proof).
//
// Lifecycle:
//
//	i := handshake.NewInitiator(handshake.InitiatorConfig{...})
//	initBytes, _ := i.Init()
//	respBytes := transport.send(initBytes)
//	confirmBytes, sess, _ := i.OnResponse(respBytes)
//	acceptedBytes := transport.send(confirmBytes)
//	_ = i.OnAccepted(acceptedBytes, sess)
//	// federation session is now active
type Initiator struct {
	suite            crypto.Suite
	store            keys.Store
	localDomain      string
	localServerID    string
	localDomainKey   keys.Fingerprint
	localDomainPriv  []byte
	federationType   FederationType
	domainProof      DomainProof
	policyAcceptance PolicyAcceptor
	capabilities     Capabilities
	peerDomain       string

	// State populated by Init.
	nonce         []byte
	ephemeralPub  []byte
	ephemeralPriv []byte
	initCanonical []byte

	// State populated by OnResponse.
	responseCanonical []byte
	sessionKeys       *crypto.SessionKeys
	sessionID         string
	negotiated        Negotiated
}

// PolicyAcceptor is invoked by the initiator on the responder's federation
// policy block. Returning nil accepts the policy. Returning an error rejects
// it; the rejection reason is forwarded to the responder in the
// federation_acceptance.reason field.
type PolicyAcceptor func(FederationPolicy) error

// AcceptAllPolicies is a PolicyAcceptor that accepts every policy. Suitable
// for tests; production deployments SHOULD inspect message_retention,
// user_discovery, and relay_allowed before agreeing.
func AcceptAllPolicies(_ FederationPolicy) error { return nil }

// InitiatorConfig groups the inputs to NewInitiator.
type InitiatorConfig struct {
	Suite crypto.Suite

	// Store provides the responder's domain public key for verifying
	// message 2.
	Store keys.Store

	// LocalDomain is the initiator's own domain (e.g. "example.com").
	LocalDomain string

	// LocalServerID identifies the specific server instance within the
	// local domain. Defaults to a fresh ULID-shaped value if empty.
	LocalServerID string

	// LocalDomainKeyID is the fingerprint of the initiator's domain key.
	LocalDomainKeyID keys.Fingerprint

	// LocalDomainPrivateKey is the raw Ed25519 private key bytes used to
	// sign every outbound handshake message. Held only in memory.
	LocalDomainPrivateKey []byte

	// PeerDomain is the responder's domain. Used to look up the
	// responder's published domain public key in Store.
	PeerDomain string

	// FederationType is the federation mode requested by the initiator.
	// Defaults to FederationFull when empty.
	FederationType FederationType

	// DomainProof is the verification payload the initiator presents to
	// the responder. The format is determined by DomainProof.Method.
	DomainProof DomainProof

	// PolicyAcceptor decides whether to accept the responder's federation
	// policy. Defaults to AcceptAllPolicies.
	PolicyAcceptor PolicyAcceptor

	// Capabilities, if non-zero, overrides DefaultClientCapabilities.
	Capabilities Capabilities
}

// NewInitiator constructs a federation Initiator from a config.
func NewInitiator(cfg InitiatorConfig) *Initiator {
	caps := cfg.Capabilities
	if len(caps.EncryptionAlgorithms) == 0 {
		caps = DefaultClientCapabilities()
	}
	fed := cfg.FederationType
	if fed == "" {
		fed = FederationFull
	}
	pa := cfg.PolicyAcceptor
	if pa == nil {
		pa = AcceptAllPolicies
	}
	return &Initiator{
		suite:            cfg.Suite,
		store:            cfg.Store,
		localDomain:      cfg.LocalDomain,
		localServerID:    cfg.LocalServerID,
		localDomainKey:   cfg.LocalDomainKeyID,
		localDomainPriv:  cfg.LocalDomainPrivateKey,
		federationType:   fed,
		domainProof:      cfg.DomainProof,
		policyAcceptance: pa,
		capabilities:     caps,
		peerDomain:       cfg.PeerDomain,
	}
}

// Init produces the federation init bytes (message 1). It generates a
// fresh ephemeral X25519 key pair and 32-byte nonce, computes the inner
// identity proof signature over `eph_pub || nonce`, and signs the whole
// message with the local domain key.
func (i *Initiator) Init() ([]byte, error) {
	if i == nil || i.suite == nil {
		return nil, errors.New("handshake: nil initiator or suite")
	}
	if i.localServerID == "" {
		id, err := newULID()
		if err != nil {
			return nil, err
		}
		i.localServerID = id
	}
	i.nonce = make([]byte, 32)
	if _, err := rand.Read(i.nonce); err != nil {
		return nil, fmt.Errorf("handshake: nonce: %w", err)
	}
	ephPub, ephPriv, err := i.suite.KEM().GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("handshake: ephemeral keypair: %w", err)
	}
	i.ephemeralPub = ephPub
	i.ephemeralPriv = ephPriv

	// Inner identity proof: signature over eph_pub || nonce with domain separation.
	rawInner := make([]byte, 0, len(ephPub)+len(i.nonce))
	rawInner = append(rawInner, ephPub...)
	rawInner = append(rawInner, i.nonce...)
	innerMsg := crypto.PrefixedMessage(crypto.SigCtxIdentity, rawInner)
	innerSig, err := i.suite.Signer().Sign(i.localDomainPriv, innerMsg)
	if err != nil {
		return nil, fmt.Errorf("handshake: inner identity sign: %w", err)
	}

	msg := ServerInit{
		Type:           MessageType,
		Step:           StepInit,
		Party:          PartyServer,
		Version:        "1.0.0",
		Nonce:          base64.StdEncoding.EncodeToString(i.nonce),
		ServerID:       i.localServerID,
		ServerDomain:   i.localDomain,
		FederationType: i.federationType,
		ServerEphemeralKey: EphemeralKey{
			Algorithm: string(i.suite.ID()),
			Key:       base64.StdEncoding.EncodeToString(ephPub),
			KeyID:     string(keys.Compute(ephPub)),
		},
		ServerIdentityProof: FederationProof{
			KeyID:     string(i.localDomainKey),
			Signature: base64.StdEncoding.EncodeToString(innerSig),
		},
		DomainProof:  i.domainProof,
		Capabilities: i.capabilities,
		Extensions:   extensions.Map{},
	}
	sig, err := SignServerMessage(i.suite, i.localDomainPriv, &msg)
	if err != nil {
		return nil, err
	}
	msg.ServerSignature = sig
	canonicalBytes, err := CanonicalForHashing(&msg)
	if err != nil {
		return nil, fmt.Errorf("handshake: canonical init: %w", err)
	}
	i.initCanonical = canonicalBytes
	return canonicalBytes, nil
}

// OnResponse processes the responder's message 2, derives the session
// secret, runs the federation policy check, and returns the confirm bytes
// (message 3) plus a partially-initialized Session.
//
// The ephemeral private key is erased before return.
func (i *Initiator) OnResponse(data []byte) ([]byte, *session.Session, error) {
	if i == nil || i.suite == nil {
		return nil, nil, errors.New("handshake: nil initiator or suite")
	}
	if i.initCanonical == nil {
		return nil, nil, errors.New("handshake: OnResponse called before Init")
	}
	var resp FederationResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, nil, fmt.Errorf("handshake: parse federation response: %w", err)
	}
	if resp.Type != MessageType || resp.Step != StepResponse || resp.Party != PartyServer {
		return nil, nil, errors.New("handshake: federation response type/step/party mismatch")
	}
	if resp.ServerDomain != i.peerDomain {
		return nil, nil, fmt.Errorf("handshake: response server_domain %q != configured peer %q",
			resp.ServerDomain, i.peerDomain)
	}
	expectedNonce := base64.StdEncoding.EncodeToString(i.nonce)
	if resp.ClientNonce != expectedNonce {
		return nil, nil, errors.New("handshake: response client_nonce mismatch")
	}
	if resp.DomainVerificationResult.Status != DomainStatusVerified {
		return nil, nil, fmt.Errorf("handshake: peer rejected our domain proof: %s", resp.DomainVerificationResult.Detail)
	}

	peerDomainPub, err := i.lookupPeerDomainKey()
	if err != nil {
		return nil, nil, err
	}
	if err := VerifyServerMessage(i.suite, peerDomainPub, &resp, resp.ServerSignature); err != nil {
		return nil, nil, err
	}

	// Verify the inner identity proof: sig over eph_pub || server_nonce || client_nonce.
	serverEphPub, err := base64.StdEncoding.DecodeString(resp.ServerEphemeralKey.Key)
	if err != nil {
		return nil, nil, fmt.Errorf("handshake: server ephemeral key base64: %w", err)
	}
	serverNonce, err := base64.StdEncoding.DecodeString(resp.ServerNonce)
	if err != nil {
		return nil, nil, fmt.Errorf("handshake: server nonce base64: %w", err)
	}
	rawInnerV := make([]byte, 0, len(serverEphPub)+len(serverNonce)+len(i.nonce))
	rawInnerV = append(rawInnerV, serverEphPub...)
	rawInnerV = append(rawInnerV, serverNonce...)
	rawInnerV = append(rawInnerV, i.nonce...)
	innerMsgV := crypto.PrefixedMessage(crypto.SigCtxIdentity, rawInnerV)
	innerSig, err := base64.StdEncoding.DecodeString(resp.ServerIdentityProof.Signature)
	if err != nil {
		return nil, nil, fmt.Errorf("handshake: inner identity_proof base64: %w", err)
	}
	if err := i.suite.Signer().Verify(peerDomainPub, innerMsgV, innerSig); err != nil {
		return nil, nil, fmt.Errorf("handshake: peer inner identity_signature verify: %w", err)
	}

	// Shared secret + session key derivation. The salt order is
	// (initiator_nonce || responder_nonce), matching the client
	// handshake. The responder's wire blob is a KEM ciphertext that
	// the initiator decapsulates with its ephemeral private key. For
	// baseline X25519 this is equivalent to the legacy Agree flow;
	// for the hybrid suite it additionally performs Kyber768
	// decapsulation so the combined shared secret is K_kyber || K_x25519.
	shared, err := i.suite.KEM().Decapsulate(serverEphPub, i.ephemeralPriv)
	if err != nil {
		return nil, nil, fmt.Errorf("handshake: ephemeral KEM: %w", err)
	}
	defer crypto.Zeroize(shared)
	sessionKeys, err := crypto.DeriveSessionKeys(i.suite.KDF(), shared, i.nonce, serverNonce)
	if err != nil {
		return nil, nil, fmt.Errorf("handshake: derive session keys: %w", err)
	}

	crypto.Zeroize(i.ephemeralPriv)
	i.ephemeralPriv = nil

	// Federation policy check.
	acceptance := FederationAcceptance{Accepted: true, PolicyAcknowledged: true}
	if err := i.policyAcceptance(resp.FederationPolicy); err != nil {
		acceptance = FederationAcceptance{
			Accepted:           false,
			PolicyAcknowledged: false,
			Reason:             err.Error(),
		}
	}

	respCanonical, err := CanonicalForHashing(&resp)
	if err != nil {
		sessionKeys.Erase()
		return nil, nil, fmt.Errorf("handshake: canonical response: %w", err)
	}
	confirmHash, err := ConfirmationHash(i.initCanonical, respCanonical)
	if err != nil {
		sessionKeys.Erase()
		return nil, nil, err
	}

	confirmMsg := FederationConfirm{
		Type:                 MessageType,
		Step:                 StepConfirm,
		Party:                PartyServer,
		Version:              "1.0.0",
		SessionID:            resp.SessionID,
		ConfirmationHash:     base64.StdEncoding.EncodeToString(confirmHash),
		FederationAcceptance: acceptance,
		Extensions:           extensions.Map{},
	}
	sig, err := SignServerMessage(i.suite, i.localDomainPriv, &confirmMsg)
	if err != nil {
		sessionKeys.Erase()
		return nil, nil, err
	}
	confirmMsg.ServerSignature = sig
	confirmBytes, err := CanonicalForHashing(&confirmMsg)
	if err != nil {
		sessionKeys.Erase()
		return nil, nil, fmt.Errorf("handshake: canonical confirm: %w", err)
	}

	i.responseCanonical = respCanonical
	i.sessionKeys = sessionKeys
	i.sessionID = resp.SessionID
	i.negotiated = resp.Negotiated

	sess := session.New(session.RoleFederation)
	sess.ID = resp.SessionID
	sess.PeerIdentity = resp.ServerDomain
	sess.State = session.StateHandshaking
	sess.SetKeys(sessionKeys)
	return confirmBytes, sess, nil
}

// OnAccepted finalizes the federation session after the responder confirms
// it (message 4 with step "accepted").
func (i *Initiator) OnAccepted(data []byte, sess *session.Session) error {
	if i == nil || i.suite == nil {
		return errors.New("handshake: nil initiator or suite")
	}
	if sess == nil {
		return errors.New("handshake: nil session")
	}
	var acc FederationAccepted
	if err := json.Unmarshal(data, &acc); err != nil {
		return fmt.Errorf("handshake: parse federation accepted: %w", err)
	}
	if acc.Type != MessageType || acc.Step != StepAccepted || acc.Party != PartyServer {
		return errors.New("handshake: federation accepted type/step/party mismatch")
	}
	if acc.SessionID != i.sessionID {
		return errors.New("handshake: federation accepted session_id mismatch")
	}
	peerDomainPub, err := i.lookupPeerDomainKey()
	if err != nil {
		return err
	}
	if err := VerifyServerMessage(i.suite, peerDomainPub, &acc, acc.ServerSignature); err != nil {
		return err
	}
	ttl := acc.SessionTTL
	if ttl <= 0 {
		ttl = 3600 // SESSION.md §3.1: federation defaults are typically longer
	}
	now := time.Now()
	sess.State = session.StateActive
	sess.EstablishedAt = now
	sess.TTL = time.Duration(ttl) * time.Second
	sess.ExpiresAt = now.Add(sess.TTL)
	return nil
}

// OnRejected processes a rejected message and returns it as an error
// carrying the reason code.
func (i *Initiator) OnRejected(data []byte) error {
	if i == nil {
		return errors.New("handshake: nil initiator")
	}
	var rej Rejected
	if err := json.Unmarshal(data, &rej); err != nil {
		return fmt.Errorf("handshake: parse rejected: %w", err)
	}
	if rej.Type != MessageType || rej.Step != StepRejected || rej.Party != PartyServer {
		return errors.New("handshake: rejected type/step/party mismatch")
	}
	return &handshakeRejection{Code: rej.ReasonCode, Reason: rej.Reason, SessionID: rej.SessionID}
}

// SessionID returns the responder-assigned session ID once OnResponse has
// succeeded.
func (i *Initiator) SessionID() string {
	if i == nil {
		return ""
	}
	return i.sessionID
}

// Erase wipes initiator state.
func (i *Initiator) Erase() {
	if i == nil {
		return
	}
	crypto.Zeroize(i.ephemeralPriv)
	crypto.Zeroize(i.nonce)
	i.ephemeralPriv = nil
	i.ephemeralPub = nil
	i.nonce = nil
	i.initCanonical = nil
	i.responseCanonical = nil
	if i.sessionKeys != nil {
		i.sessionKeys.Erase()
		i.sessionKeys = nil
	}
}

func (i *Initiator) lookupPeerDomainKey() ([]byte, error) {
	if i.store == nil {
		return nil, errors.New("handshake: nil key store")
	}
	rec, err := i.store.LookupDomainKey(context.Background(), i.peerDomain)
	if err != nil {
		return nil, fmt.Errorf("handshake: lookup peer domain key: %w", err)
	}
	if rec == nil {
		return nil, errors.New("handshake: peer domain key not found")
	}
	return base64.StdEncoding.DecodeString(rec.PublicKey)
}

// =============================================================================
// Responder
// =============================================================================

// Responder drives the receiving side of a federation handshake. Symmetric
// to handshake.Server but uses the federation message types.
//
// Collision rule: when two federation servers simultaneously initiate
// handshakes to each other, the session whose `session_id` sorts lower
// lexicographically MUST be abandoned (SESSION.md §2.5.2). This rule is
// implemented in ResolveCollision; integration with a server-wide session
// tracker is the deployment's responsibility.
type Responder struct {
	suite            crypto.Suite
	store            keys.Store
	policy           FederationPolicy
	verifier         DomainVerifier
	localDomain      string
	localServerID    string
	localDomainKey   keys.Fingerprint
	localDomainPriv  []byte
	capabilities     Capabilities
	sessionTTL       int

	// State populated by OnInit.
	sessionID         string
	peerDomain        string
	peerNonce         []byte
	serverNonce       []byte
	clientEphemeralPub []byte
	initCanonical     []byte
	responseCanonical []byte
	sessionKeys       *crypto.SessionKeys
}

// ResponderConfig groups the inputs to NewResponder.
type ResponderConfig struct {
	Suite crypto.Suite

	// Store provides the initiator's domain public key for verification.
	Store keys.Store

	// Verifier validates the initiator's DomainProof. Defaults to
	// TrustingDomainVerifier if nil — TESTS ONLY.
	Verifier DomainVerifier

	// LocalDomain is the responder's own domain.
	LocalDomain string

	// LocalServerID identifies the specific server instance within the
	// local domain. Defaults to a fresh ULID if empty.
	LocalServerID string

	// LocalDomainKeyID is the fingerprint of the responder's domain key.
	LocalDomainKeyID keys.Fingerprint

	// LocalDomainPrivateKey is the raw Ed25519 private key bytes used to
	// sign every outbound handshake message.
	LocalDomainPrivateKey []byte

	// Policy is the federation policy block returned in message 2.
	Policy FederationPolicy

	// SessionTTL is the lifetime in seconds for federation sessions
	// granted by this responder. Defaults to 3600.
	SessionTTL int

	// Capabilities, if non-zero, overrides DefaultServerCapabilities.
	Capabilities Capabilities
}

// NewResponder constructs a federation Responder from a config. When
// cfg.Capabilities is zero, the responder advertises ONLY the suite
// it was constructed with (cfg.Suite.ID()); see NewServer for the
// rationale.
func NewResponder(cfg ResponderConfig) *Responder {
	caps := cfg.Capabilities
	if len(caps.EncryptionAlgorithms) == 0 {
		suiteID := ""
		if cfg.Suite != nil {
			suiteID = string(cfg.Suite.ID())
		}
		caps = Capabilities{
			EncryptionAlgorithms: []string{suiteID},
			Compression:          []string{"none"},
			Features:             []string{},
		}
	}
	verifier := cfg.Verifier
	if verifier == nil {
		verifier = TrustingDomainVerifier{}
	}
	ttl := cfg.SessionTTL
	if ttl <= 0 {
		ttl = 3600
	}
	return &Responder{
		suite:           cfg.Suite,
		store:           cfg.Store,
		policy:          cfg.Policy,
		verifier:        verifier,
		localDomain:     cfg.LocalDomain,
		localServerID:   cfg.LocalServerID,
		localDomainKey:  cfg.LocalDomainKeyID,
		localDomainPriv: cfg.LocalDomainPrivateKey,
		capabilities:    caps,
		sessionTTL:      ttl,
	}
}

// OnInit processes a federation init (message 1) and returns the response
// bytes (message 2). The responder verifies the initiator's outer signature,
// the inner identity proof signature, and the domain proof, then negotiates
// capabilities and derives session keys.
func (r *Responder) OnInit(data []byte) ([]byte, error) {
	if r == nil || r.suite == nil {
		return nil, errors.New("handshake: nil responder or suite")
	}
	var init ServerInit
	if err := json.Unmarshal(data, &init); err != nil {
		return nil, fmt.Errorf("handshake: parse federation init: %w", err)
	}
	if init.Type != MessageType || init.Step != StepInit || init.Party != PartyServer {
		return nil, errors.New("handshake: federation init type/step/party mismatch")
	}
	if init.ServerDomain == "" {
		return nil, errors.New("handshake: empty initiator server_domain")
	}

	// Verify the outer signature against the initiator's published
	// domain public key.
	peerDomainPub, err := r.lookupPeerDomainKey(init.ServerDomain)
	if err != nil {
		return nil, err
	}
	if err := VerifyServerMessage(r.suite, peerDomainPub, &init, init.ServerSignature); err != nil {
		return nil, err
	}

	// Verify the inner identity proof: sig over eph_pub || nonce.
	clientEphPub, err := base64.StdEncoding.DecodeString(init.ServerEphemeralKey.Key)
	if err != nil {
		return nil, fmt.Errorf("handshake: peer ephemeral key base64: %w", err)
	}
	clientNonce, err := base64.StdEncoding.DecodeString(init.Nonce)
	if err != nil {
		return nil, fmt.Errorf("handshake: peer nonce base64: %w", err)
	}
	rawInnerR := make([]byte, 0, len(clientEphPub)+len(clientNonce))
	rawInnerR = append(rawInnerR, clientEphPub...)
	rawInnerR = append(rawInnerR, clientNonce...)
	innerMsgR := crypto.PrefixedMessage(crypto.SigCtxIdentity, rawInnerR)
	innerSig, err := base64.StdEncoding.DecodeString(init.ServerIdentityProof.Signature)
	if err != nil {
		return nil, fmt.Errorf("handshake: inner identity_proof base64: %w", err)
	}
	if err := r.suite.Signer().Verify(peerDomainPub, innerMsgR, innerSig); err != nil {
		return nil, fmt.Errorf("handshake: peer inner identity_signature verify: %w", err)
	}

	// Verify the domain proof.
	verificationResult := DomainVerificationResult{
		Status: DomainStatusVerified,
		Method: init.DomainProof.Method,
	}
	if err := r.verifier.Verify(context.Background(), init.ServerDomain, init.DomainProof, init.Nonce); err != nil {
		// We still need to send a response — the spec requires explicit
		// rejection rather than silent close. The caller decides whether
		// to use this response or convert it to a Rejected.
		verificationResult = DomainVerificationResult{
			Status: DomainStatusRejected,
			Method: init.DomainProof.Method,
			Detail: err.Error(),
		}
		// Mark the verifier failure as fatal: don't set up session keys.
		return nil, fmt.Errorf("handshake: domain proof verification failed: %w", err)
	}

	// Capability negotiation.
	negotiated, err := NegotiateCapabilities(init.Capabilities, r.capabilities)
	if err != nil {
		return nil, err
	}
	if negotiated.EncryptionAlgorithm != string(r.suite.ID()) {
		return nil, fmt.Errorf("handshake: negotiated suite %q does not match responder suite %q",
			negotiated.EncryptionAlgorithm, r.suite.ID())
	}

	// Recompute canonical(init) for the confirmation hash.
	initCanonical, err := CanonicalForHashing(&init)
	if err != nil {
		return nil, fmt.Errorf("handshake: canonical init: %w", err)
	}

	// Responder-side KEM step: encapsulate under the initiator's
	// ephemeral public key. Works for both baseline X25519 (returns
	// a fresh X25519 ephemeral pub as the ciphertext) and the hybrid
	// Kyber768+X25519 suite (returns responderX25519Pub || kyberCt).
	shared, ephPub, err := r.suite.KEM().Encapsulate(clientEphPub)
	if err != nil {
		return nil, fmt.Errorf("handshake: ephemeral KEM encapsulate: %w", err)
	}
	defer crypto.Zeroize(shared)

	serverNonce := make([]byte, 32)
	if _, err := rand.Read(serverNonce); err != nil {
		return nil, fmt.Errorf("handshake: server nonce: %w", err)
	}
	sessionID, err := newULID()
	if err != nil {
		return nil, err
	}
	if r.localServerID == "" {
		id, err := newULID()
		if err != nil {
			return nil, err
		}
		r.localServerID = id
	}

	sessionKeys, err := crypto.DeriveSessionKeys(r.suite.KDF(), shared, clientNonce, serverNonce)
	if err != nil {
		return nil, fmt.Errorf("handshake: derive session keys: %w", err)
	}

	// Inner identity proof: sig over eph_pub || server_nonce || client_nonce.
	rawProof := make([]byte, 0, len(ephPub)+len(serverNonce)+len(clientNonce))
	rawProof = append(rawProof, ephPub...)
	rawProof = append(rawProof, serverNonce...)
	rawProof = append(rawProof, clientNonce...)
	innerProofMsg := crypto.PrefixedMessage(crypto.SigCtxIdentity, rawProof)
	innerProofSig, err := r.suite.Signer().Sign(r.localDomainPriv, innerProofMsg)
	if err != nil {
		sessionKeys.Erase()
		return nil, fmt.Errorf("handshake: inner identity sign: %w", err)
	}

	resp := FederationResponse{
		Type:        MessageType,
		Step:        StepResponse,
		Party:       PartyServer,
		Version:     "1.0.0",
		SessionID:   sessionID,
		ClientNonce: init.Nonce,
		ServerNonce: base64.StdEncoding.EncodeToString(serverNonce),
		ServerID:    r.localServerID,
		ServerDomain: r.localDomain,
		ServerEphemeralKey: EphemeralKey{
			Algorithm: string(r.suite.ID()),
			Key:       base64.StdEncoding.EncodeToString(ephPub),
			KeyID:     string(keys.Compute(ephPub)),
		},
		ServerIdentityProof: FederationProof{
			KeyID:     string(r.localDomainKey),
			Signature: base64.StdEncoding.EncodeToString(innerProofSig),
		},
		DomainVerificationResult: verificationResult,
		Negotiated:               negotiated,
		FederationPolicy:         r.policy,
		Extensions:               extensions.Map{},
	}
	signed, err := SignServerMessage(r.suite, r.localDomainPriv, &resp)
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

	// The responder holds no ephemeral private key after Encapsulate;
	// the hybrid KEM zeroed it internally.

	// Commit state.
	r.sessionID = sessionID
	r.peerDomain = init.ServerDomain
	r.peerNonce = clientNonce
	r.serverNonce = serverNonce
	r.clientEphemeralPub = clientEphPub
	r.initCanonical = initCanonical
	r.responseCanonical = respCanonical
	r.sessionKeys = sessionKeys
	return respCanonical, nil
}

// OnConfirm processes message 3 and returns the accepted bytes plus a
// fully-initialized Session. If the initiator did not accept the federation
// policy, OnConfirm returns an error and no session is established.
func (r *Responder) OnConfirm(data []byte) ([]byte, *session.Session, error) {
	if r == nil || r.suite == nil {
		return nil, nil, errors.New("handshake: nil responder or suite")
	}
	if r.sessionKeys == nil {
		return nil, nil, errors.New("handshake: OnConfirm called before OnInit")
	}
	var conf FederationConfirm
	if err := json.Unmarshal(data, &conf); err != nil {
		return nil, nil, fmt.Errorf("handshake: parse federation confirm: %w", err)
	}
	if conf.Type != MessageType || conf.Step != StepConfirm || conf.Party != PartyServer {
		return nil, nil, errors.New("handshake: federation confirm type/step/party mismatch")
	}
	if conf.SessionID != r.sessionID {
		return nil, nil, errors.New("handshake: federation confirm session_id mismatch")
	}

	// Confirmation hash.
	expectedHash, err := ConfirmationHash(r.initCanonical, r.responseCanonical)
	if err != nil {
		return nil, nil, err
	}
	gotHash, err := base64.StdEncoding.DecodeString(conf.ConfirmationHash)
	if err != nil {
		return nil, nil, fmt.Errorf("handshake: confirmation_hash base64: %w", err)
	}
	if !bytesEqual(expectedHash, gotHash) {
		return nil, nil, errors.New("handshake: federation confirmation hash mismatch")
	}

	// Verify the outer signature against the initiator's published key.
	peerDomainPub, err := r.lookupPeerDomainKey(r.peerDomain)
	if err != nil {
		return nil, nil, err
	}
	if err := VerifyServerMessage(r.suite, peerDomainPub, &conf, conf.ServerSignature); err != nil {
		return nil, nil, err
	}

	// Federation acceptance check.
	if !conf.FederationAcceptance.Accepted || !conf.FederationAcceptance.PolicyAcknowledged {
		return nil, nil, fmt.Errorf("handshake: initiator declined federation policy: %s",
			conf.FederationAcceptance.Reason)
	}

	// Build the accepted message.
	acc := FederationAccepted{
		Type:       MessageType,
		Step:       StepAccepted,
		Party:      PartyServer,
		Version:    "1.0.0",
		SessionID:  conf.SessionID,
		Status:     "accepted",
		SessionTTL: r.sessionTTL,
		Extensions: extensions.Map{},
	}
	sigB64, err := SignServerMessage(r.suite, r.localDomainPriv, &acc)
	if err != nil {
		return nil, nil, err
	}
	acc.ServerSignature = sigB64
	out, err := CanonicalForHashing(&acc)
	if err != nil {
		return nil, nil, fmt.Errorf("handshake: canonical federation accepted: %w", err)
	}

	now := time.Now()
	sess := session.New(session.RoleFederation)
	sess.ID = r.sessionID
	sess.PeerIdentity = r.peerDomain
	sess.State = session.StateActive
	sess.SetKeys(r.sessionKeys)
	sess.TTL = time.Duration(r.sessionTTL) * time.Second
	sess.EstablishedAt = now
	sess.ExpiresAt = now.Add(sess.TTL)
	r.sessionKeys = nil
	return out, sess, nil
}

// NewRejection builds a signed Rejected message for the federation
// handshake. Reuses the client `Rejected` schema since the format is
// identical (HANDSHAKE.md §5.6).
func (r *Responder) NewRejection(reasonCode, reason string) ([]byte, error) {
	rej := Rejected{
		Type:       MessageType,
		Step:       StepRejected,
		Party:      PartyServer,
		Version:    "1.0.0",
		SessionID:  r.sessionID,
		ReasonCode: reasonCode,
		Reason:     reason,
		Extensions: extensions.Map{},
	}
	sig, err := SignServerMessage(r.suite, r.localDomainPriv, &rej)
	if err != nil {
		return nil, err
	}
	rej.ServerSignature = sig
	return CanonicalForHashing(&rej)
}

// SessionID returns the session ID assigned by OnInit.
func (r *Responder) SessionID() string {
	if r == nil {
		return ""
	}
	return r.sessionID
}

// PeerDomain returns the initiator's domain after OnInit has succeeded.
func (r *Responder) PeerDomain() string {
	if r == nil {
		return ""
	}
	return r.peerDomain
}

// Erase wipes responder state.
func (r *Responder) Erase() {
	if r == nil {
		return
	}
	crypto.Zeroize(r.serverNonce)
	crypto.Zeroize(r.peerNonce)
	r.serverNonce = nil
	r.peerNonce = nil
	r.initCanonical = nil
	r.responseCanonical = nil
	if r.sessionKeys != nil {
		r.sessionKeys.Erase()
		r.sessionKeys = nil
	}
}

func (r *Responder) lookupPeerDomainKey(domain string) ([]byte, error) {
	if r.store == nil {
		return nil, errors.New("handshake: nil key store")
	}
	rec, err := r.store.LookupDomainKey(context.Background(), domain)
	if err != nil {
		return nil, fmt.Errorf("handshake: lookup peer domain key: %w", err)
	}
	if rec == nil {
		return nil, fmt.Errorf("handshake: peer domain key not found for %s", domain)
	}
	return base64.StdEncoding.DecodeString(rec.PublicKey)
}
