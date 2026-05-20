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

// ServerInit is the message 1 sent by an initiating server in a federation
// handshake (HANDSHAKE.md section 5.2). Unlike the client init, the server
// init includes the originating server's domain identity in plaintext.
//
// The Extensions field is intentionally NOT marked omitempty: the canonical
// form of an init message MUST always include `"extensions":{}` so that the
// confirmation hash computed by the responder reproduces byte for byte.
//
// SEMP defines a single federation mode (HANDSHAKE.md section 5.2.2). The
// wire no longer carries a `federation_type` field; per-peer restrictions
// are local operator policy rather than a negotiated protocol mode.
type ServerInit struct {
	Type                string          `json:"type"`  // SEMP_HANDSHAKE
	Step                Step            `json:"step"`  // StepInit
	Party               Party           `json:"party"` // PartyServer
	Version             string          `json:"version"`
	Nonce               string          `json:"nonce"`
	ServerID            string          `json:"server_id"`
	ServerDomain        string          `json:"server_domain"`
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

// FederationAccepted is the responder's success outcome (HANDSHAKE.md
// §5.6) and also the success response to a FederationResume request
// (HANDSHAKE.md §2.8.7). SessionTTL is the lifetime in seconds; the
// spec example does not show it but SESSION.md requires every active
// session to have a TTL, so we surface it through the same field used
// by the client handshake.
//
// The resumption-only fields (ServerNonce, ServerEphemeralKey,
// ResumptionTicket) are present when Accepted responds to a Resume
// request and omitted (omitempty) in the full-handshake case so the
// canonical bytes of a full-handshake FederationAccepted are
// unchanged.
type FederationAccepted struct {
	Type       string `json:"type"`
	Step       Step   `json:"step"`
	Party      Party  `json:"party"`
	Version    string `json:"version"`
	SessionID  string `json:"session_id"`
	Status     string `json:"status"`      // always "accepted"
	SessionTTL int    `json:"session_ttl"` // seconds

	// Resumption-only fields, present when responding to FederationResume.
	ServerNonce        string             `json:"server_nonce,omitempty"`
	ServerEphemeralKey *EphemeralKey      `json:"server_ephemeral_key,omitempty"`
	ResumptionTicket   *ResumptionTicket  `json:"resumption_ticket,omitempty"`

	ServerSignature string         `json:"server_signature"`
	Extensions      extensions.Map `json:"extensions"`
}

// FederationResume is the federation-side resume request per
// HANDSHAKE.md §2.8.7. Symmetric to handshake.Resume (the client
// resume) but with the federation identity fields ServerID,
// ServerDomain, and PeerConfigurationRevision attached so the
// responder can route the resume to the right peer state and surface
// configuration drift via SEMP_CONFIGURATION_UPDATE per
// DISCOVERY.md §3.5.4.
//
// Party is "server" because both sides of a federation handshake
// are servers; the initiator is still the side that sends the resume.
//
// FederationResume MUST NOT carry application data per §2.8.6
// ("No 0-RTT Data"); a responder that observes envelope-bearing
// fields in a resume message MUST reject with reason_code
// "resumption_failed".
type FederationResume struct {
	Type                       string         `json:"type"`  // SEMP_HANDSHAKE
	Step                       Step           `json:"step"`  // StepResume
	Party                      Party          `json:"party"` // PartyServer
	Version                    string         `json:"version"`
	Nonce                      string         `json:"nonce"`
	ServerID                   string         `json:"server_id"`
	ServerDomain               string         `json:"server_domain"`
	PeerConfigurationRevision  int            `json:"peer_configuration_revision,omitempty"`
	ResumptionTicket           string         `json:"resumption_ticket"` // base64 opaque bytes
	ClientEphemeralKey         EphemeralKey   `json:"client_ephemeral_key"`
	Transport                  string         `json:"transport"`
	Extensions                 extensions.Map `json:"extensions"`
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
// any external coordination - strings.Compare provides exactly this property.
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

	// Populated by LoadResumptionSecret in the federation resume
	// flow. Mixed into the resumed-session HKDF input keying material
	// per HANDSHAKE.md §2.8.3 by OnResumeAccepted, then zeroized.
	resumptionSecret []byte
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
		Type:         MessageType,
		Step:         StepInit,
		Party:        PartyServer,
		Version:      "1.0.0",
		Nonce:        base64.StdEncoding.EncodeToString(i.nonce),
		ServerID:     i.localServerID,
		ServerDomain: i.localDomain,
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
	crypto.Zeroize(i.resumptionSecret)
	i.resumptionSecret = nil
}

// LoadResumptionSecret pre-loads the K_resumption secret recovered
// from the prior federation session's keys. The caller invokes this
// before Resume so OnResumeAccepted can mix it into the resumed-
// session HKDF input keying material per HANDSHAKE.md §2.8.3. The
// secret is erased after the resumed key derivation completes.
func (i *Initiator) LoadResumptionSecret(secret []byte) {
	if i == nil {
		return
	}
	crypto.Zeroize(i.resumptionSecret)
	if len(secret) == 0 {
		i.resumptionSecret = nil
		return
	}
	i.resumptionSecret = append([]byte(nil), secret...)
}

// Resume produces the bytes of a FederationResume message
// (HANDSHAKE.md §2.8.7) to send to the peer responder. ticket is the
// opaque ticket bytes recovered from the prior FederationAccepted
// message's resumption_ticket.value (already base64-decoded). The
// caller MAY pass the cached peerConfigurationRevision (DISCOVERY.md
// §3.5) so the responder can detect cache drift; pass 0 to omit.
//
// Resume generates a fresh nonce and ephemeral key pair so the
// resumed session derives forward-secure keys per §2.8.3 even if
// the ticket is later compromised. Domain-ownership proof is NOT
// repeated; the ticket stands in for it per §2.8.7.
func (i *Initiator) Resume(ticket []byte, peerConfigurationRevision int) ([]byte, error) {
	if i == nil || i.suite == nil {
		return nil, errors.New("handshake: nil initiator or suite")
	}
	if len(ticket) == 0 {
		return nil, errors.New("handshake: empty federation resumption ticket")
	}
	if i.localServerID == "" {
		return nil, errors.New("handshake: empty local server_id")
	}
	if i.localDomain == "" {
		return nil, errors.New("handshake: empty local server_domain")
	}

	i.nonce = make([]byte, 32)
	if _, err := rand.Read(i.nonce); err != nil {
		return nil, fmt.Errorf("handshake: federation resume nonce: %w", err)
	}
	ephPub, ephPriv, err := i.suite.KEM().GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("handshake: federation resume ephemeral keypair: %w", err)
	}
	i.ephemeralPub = ephPub
	i.ephemeralPriv = ephPriv

	msg := FederationResume{
		Type:                      MessageType,
		Step:                      StepResume,
		Party:                     PartyServer,
		Version:                   "1.0.0",
		Nonce:                     base64.StdEncoding.EncodeToString(i.nonce),
		ServerID:                  i.localServerID,
		ServerDomain:              i.localDomain,
		PeerConfigurationRevision: peerConfigurationRevision,
		ResumptionTicket:          base64.StdEncoding.EncodeToString(ticket),
		ClientEphemeralKey: EphemeralKey{
			Algorithm: string(i.suite.ID()),
			Key:       base64.StdEncoding.EncodeToString(ephPub),
			KeyID:     string(keys.Compute(ephPub)),
		},
		Transport:  "websocket",
		Extensions: extensions.Map{},
	}
	out, err := CanonicalForHashing(&msg)
	if err != nil {
		return nil, fmt.Errorf("handshake: canonical federation resume: %w", err)
	}
	return out, nil
}

// OnResumeAccepted processes the responder's FederationAccepted
// response to a FederationResume request, derives the resumed
// session keys per HANDSHAKE.md §2.8.3, verifies the responder's
// signature, and returns the established *session.Session and the
// new opaque ticket bytes the responder issued for chaining a
// future resume.
//
// On any failure the caller MUST treat the resume as failed and
// fall back to a full federation handshake per §2.8.5.
func (i *Initiator) OnResumeAccepted(data []byte) (*session.Session, []byte, error) {
	if i == nil || i.suite == nil {
		return nil, nil, errors.New("handshake: nil initiator or suite")
	}
	if len(i.ephemeralPriv) == 0 {
		return nil, nil, errors.New("handshake: OnResumeAccepted called before Resume")
	}
	var acc FederationAccepted
	if err := json.Unmarshal(data, &acc); err != nil {
		return nil, nil, fmt.Errorf("handshake: parse resumed federation accepted: %w", err)
	}
	if acc.Type != MessageType || acc.Step != StepAccepted || acc.Party != PartyServer {
		return nil, nil, errors.New("handshake: resumed federation accepted type/step/party mismatch")
	}
	if acc.ServerEphemeralKey == nil || acc.ServerNonce == "" {
		return nil, nil, errors.New("handshake: resumed federation accepted missing server_ephemeral_key or server_nonce")
	}
	if acc.ResumptionTicket == nil {
		return nil, nil, errors.New("handshake: resumed federation accepted missing resumption_ticket")
	}

	// Verify the responder's signature against the published peer
	// domain key before consuming any cryptographic material.
	peerPub, err := i.lookupPeerDomainKey()
	if err != nil {
		return nil, nil, err
	}
	if err := VerifyServerMessage(i.suite, peerPub, &acc, acc.ServerSignature); err != nil {
		return nil, nil, err
	}

	serverNonce, err := base64.StdEncoding.DecodeString(acc.ServerNonce)
	if err != nil {
		return nil, nil, fmt.Errorf("handshake: federation server nonce base64: %w", err)
	}
	serverEphPub, err := base64.StdEncoding.DecodeString(acc.ServerEphemeralKey.Key)
	if err != nil {
		return nil, nil, fmt.Errorf("handshake: federation server ephemeral key base64: %w", err)
	}
	ephShared, err := i.suite.KEM().Decapsulate(serverEphPub, i.ephemeralPriv)
	if err != nil {
		return nil, nil, fmt.Errorf("handshake: federation resume ephemeral KEM decapsulate: %w", err)
	}
	defer crypto.Zeroize(ephShared)
	crypto.Zeroize(i.ephemeralPriv)
	i.ephemeralPriv = nil

	if len(i.resumptionSecret) == 0 {
		return nil, nil, errors.New("handshake: federation resumption secret not loaded; call LoadResumptionSecret before Resume")
	}
	resumedKeys, err := crypto.DeriveResumedSessionKeys(i.suite.KDF(), ephShared, i.resumptionSecret, i.nonce, serverNonce)
	if err != nil {
		return nil, nil, fmt.Errorf("handshake: derive resumed federation keys: %w", err)
	}
	crypto.Zeroize(i.resumptionSecret)
	i.resumptionSecret = nil
	crypto.Zeroize(i.nonce)
	i.nonce = nil

	newTicket, err := base64.StdEncoding.DecodeString(acc.ResumptionTicket.Value)
	if err != nil {
		resumedKeys.Erase()
		return nil, nil, fmt.Errorf("handshake: federation new ticket base64: %w", err)
	}

	sess := session.New(session.RoleFederation)
	sess.ID = acc.SessionID
	sess.PeerIdentity = i.peerDomain
	sess.State = session.StateActive
	sess.SetKeys(resumedKeys)
	sess.TTL = time.Duration(acc.SessionTTL) * time.Second
	now := time.Now()
	sess.EstablishedAt = now
	sess.ExpiresAt = now.Add(sess.TTL)
	return sess, newTicket, nil
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

	// TicketIssuer issues and opens federation resumption tickets
	// per HANDSHAKE.md §2.8.7. nil disables federation resumption.
	ticketIssuer session.TicketIssuer

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
	// TrustingDomainVerifier if nil - TESTS ONLY.
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

	// TicketIssuer enables federation resumption per HANDSHAKE.md
	// §2.8.7. When non-nil, OnConfirm issues a fresh
	// resumption_ticket on every accepted federation handshake and
	// OnResume becomes available for short-circuit resumption flows.
	// nil disables resumption: the FederationAccepted message omits
	// resumption_ticket and initiators fall back to full handshakes
	// on every reconnect.
	TicketIssuer session.TicketIssuer
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
			Extensions:           []string{},
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
		ticketIssuer:    cfg.TicketIssuer,
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
		// We still need to send a response - the spec requires explicit
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
	// Issue a federation resumption ticket per HANDSHAKE.md §2.8.7
	// when an issuer is configured. The ticket binds the peer domain
	// identity to K_resumption with a 7-day expiry per SESSION.md
	// §2.7.
	if r.ticketIssuer != nil && len(r.sessionKeys.Resumption) > 0 {
		expires := time.Now().UTC().Add(session.MaxTicketLifetime)
		ticketBytes, ticketErr := r.ticketIssuer.Issue(context.Background(), r.peerDomain, r.sessionKeys.Resumption, expires)
		if ticketErr != nil {
			return nil, nil, fmt.Errorf("handshake: issue federation resumption ticket: %w", ticketErr)
		}
		acc.ResumptionTicket = &ResumptionTicket{
			Value:     base64.StdEncoding.EncodeToString(ticketBytes),
			ExpiresAt: expires,
		}
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

// OnResume processes a federation Resume request per HANDSHAKE.md
// §2.8.7 and returns the canonical FederationAccepted bytes plus the
// resumed *session.Session on success. On any failure it returns a
// typed error; the driver maps it to a Rejected with reason_code
// "resumption_failed" (or one of the identity-invalidation codes
// from §4.1 when the peer's domain key has been revoked).
//
// Domain-ownership proof is NOT repeated on resumption per §2.8.7:
// the ticket, issued after the original full handshake verified
// domain ownership, stands in for it. The resumed session uses
// fresh ephemeral DH mixed with K_resumption per §2.8.3, so it has
// forward secrecy independent of long-term ticket compromise.
func (r *Responder) OnResume(data []byte) (acceptedBytes []byte, sess *session.Session, err error) {
	if r == nil || r.suite == nil {
		return nil, nil, errors.New("handshake: nil responder or suite")
	}
	if r.ticketIssuer == nil {
		return nil, nil, errors.New("handshake: responder has no TicketIssuer; federation resumption disabled")
	}
	var resume FederationResume
	if err := json.Unmarshal(data, &resume); err != nil {
		return nil, nil, fmt.Errorf("handshake: parse federation resume: %w", err)
	}
	if resume.Type != MessageType || resume.Step != StepResume || resume.Party != PartyServer {
		return nil, nil, errors.New("handshake: federation resume type/step/party mismatch")
	}
	if resume.Nonce == "" || resume.ResumptionTicket == "" || resume.ClientEphemeralKey.Key == "" {
		return nil, nil, errors.New("handshake: federation resume missing required field")
	}
	if resume.ServerDomain == "" {
		return nil, nil, errors.New("handshake: federation resume missing server_domain")
	}

	// Open the opaque ticket. Map every issuer error to a generic
	// failure so the outbound rejection does not leak which underlying
	// reason triggered (corrupt vs expired vs consumed).
	ticketRaw, err := base64.StdEncoding.DecodeString(resume.ResumptionTicket)
	if err != nil {
		return nil, nil, fmt.Errorf("handshake: federation resumption_ticket base64: %w", err)
	}
	now := time.Now().UTC()
	ctx := context.Background()
	ticketIdentity, resumptionSecret, _, err := r.ticketIssuer.Open(ctx, ticketRaw, now)
	if err != nil {
		return nil, nil, fmt.Errorf("handshake: open federation resumption ticket: %w", err)
	}
	defer crypto.Zeroize(resumptionSecret)

	// Cross-check: the ticket's bound identity (peer domain at issue
	// time) MUST equal the server_domain field in the resume request.
	// Without this check, an attacker who steals a ticket for one
	// domain could replay it claiming to be a different domain.
	if ticketIdentity != resume.ServerDomain {
		return nil, nil, fmt.Errorf("handshake: federation ticket bound to %q, request claims %q",
			ticketIdentity, resume.ServerDomain)
	}

	// Mark consumed BEFORE we proceed. Single-use is irreversible
	// even on later failure.
	if err := r.ticketIssuer.Consume(ctx, ticketRaw); err != nil {
		return nil, nil, fmt.Errorf("handshake: mark federation ticket consumed: %w", err)
	}

	clientNonce, err := base64.StdEncoding.DecodeString(resume.Nonce)
	if err != nil {
		return nil, nil, fmt.Errorf("handshake: federation resume client nonce base64: %w", err)
	}
	clientEphPub, err := base64.StdEncoding.DecodeString(resume.ClientEphemeralKey.Key)
	if err != nil {
		return nil, nil, fmt.Errorf("handshake: federation resume client ephemeral base64: %w", err)
	}

	ephShared, ephPub, err := r.suite.KEM().Encapsulate(clientEphPub)
	if err != nil {
		return nil, nil, fmt.Errorf("handshake: federation resume ephemeral KEM encapsulate: %w", err)
	}
	defer crypto.Zeroize(ephShared)

	serverNonce := make([]byte, 32)
	if _, err := rand.Read(serverNonce); err != nil {
		return nil, nil, fmt.Errorf("handshake: federation resume server nonce: %w", err)
	}

	resumedKeys, err := crypto.DeriveResumedSessionKeys(r.suite.KDF(), ephShared, resumptionSecret, clientNonce, serverNonce)
	if err != nil {
		return nil, nil, fmt.Errorf("handshake: derive resumed federation keys: %w", err)
	}

	newSessionID, err := newULID()
	if err != nil {
		resumedKeys.Erase()
		return nil, nil, err
	}

	ticketExpires := now.Add(session.MaxTicketLifetime)
	newTicketBytes, err := r.ticketIssuer.Issue(ctx, ticketIdentity, resumedKeys.Resumption, ticketExpires)
	if err != nil {
		resumedKeys.Erase()
		return nil, nil, fmt.Errorf("handshake: issue federation replacement ticket: %w", err)
	}

	acc := FederationAccepted{
		Type:        MessageType,
		Step:        StepAccepted,
		Party:       PartyServer,
		Version:     "1.0.0",
		SessionID:   newSessionID,
		Status:      "accepted",
		SessionTTL:  r.sessionTTL,
		ServerNonce: base64.StdEncoding.EncodeToString(serverNonce),
		ServerEphemeralKey: &EphemeralKey{
			Algorithm: string(r.suite.ID()),
			Key:       base64.StdEncoding.EncodeToString(ephPub),
			KeyID:     string(keys.Compute(ephPub)),
		},
		ResumptionTicket: &ResumptionTicket{
			Value:     base64.StdEncoding.EncodeToString(newTicketBytes),
			ExpiresAt: ticketExpires,
		},
		Extensions: extensions.Map{},
	}
	sigB64, err := SignServerMessage(r.suite, r.localDomainPriv, &acc)
	if err != nil {
		resumedKeys.Erase()
		return nil, nil, err
	}
	acc.ServerSignature = sigB64
	out, err := CanonicalForHashing(&acc)
	if err != nil {
		resumedKeys.Erase()
		return nil, nil, fmt.Errorf("handshake: canonical resumed federation accepted: %w", err)
	}

	sess = session.New(session.RoleFederation)
	sess.ID = newSessionID
	sess.PeerIdentity = ticketIdentity
	sess.State = session.StateActive
	sess.SetKeys(resumedKeys)
	sess.TTL = time.Duration(r.sessionTTL) * time.Second
	now = time.Now()
	sess.EstablishedAt = now
	sess.ExpiresAt = now.Add(sess.TTL)

	r.sessionID = newSessionID
	r.peerDomain = ticketIdentity
	return out, sess, nil
}
