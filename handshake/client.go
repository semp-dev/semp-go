package handshake

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"semp.dev/semp-go/crypto"
	"semp.dev/semp-go/extensions"
	"semp.dev/semp-go/keys"
	"semp.dev/semp-go/session"
)

// Client drives the client side of a SEMP client handshake. It owns the
// ephemeral key pair and the partial state needed to derive the session
// secret. The state machine never performs network I/O directly; the caller
// moves bytes between this struct and the underlying transport.
//
// Lifecycle:
//
//	c := handshake.NewClient(suite, store, identity, identityKeyID,
//	    serverDomain)
//	initBytes, _ := c.Init()
//	// transmit initBytes; read the server's response
//	confirmBytes, sess, _ := c.OnResponse(responseBytes)
//	// transmit confirmBytes; read the server's accepted/rejected
//	_ = c.OnAccepted(acceptedBytes, sess)
//	// session is now usable
//
// If the server returns a challenge message before the response, the
// caller MUST call OnChallenge and transmit the resulting
// challenge_response before reading the actual response.
type Client struct {
	suite        crypto.Suite
	store        keys.PrivateStore
	identity     string
	identityKey  keys.Fingerprint
	serverDomain string
	transport    string
	capabilities Capabilities

	// Populated by Init.
	nonce         []byte
	ephemeralPub  []byte
	ephemeralPriv []byte
	initCanonical []byte

	// Populated by OnResponse.
	responseCanonical []byte
	sessionKeys       *crypto.SessionKeys
	negotiated        Negotiated
	sessionID         string
}

// ClientConfig groups the inputs to NewClient. The store provides the
// long-term identity private key and the (cached) server domain public key
// the client uses to verify message 2.
type ClientConfig struct {
	// Suite is the algorithm suite the client offers as its preferred
	// option. Capabilities below are computed from this if Capabilities is
	// zero-valued.
	Suite crypto.Suite

	// Store holds the client's identity private key (LoadPrivateKey) and
	// the server's domain public key (LookupDomainKey).
	Store keys.PrivateStore

	// Identity is the user's full address, e.g. "alice@example.com".
	Identity string

	// IdentityKeyID is the fingerprint of the user's long-term identity
	// public key. The corresponding private key MUST be retrievable from
	// Store via LoadPrivateKey(IdentityKeyID).
	IdentityKeyID keys.Fingerprint

	// ServerDomain is the home server's domain, used by OnResponse to look
	// up the server's published domain public key for signature verification.
	ServerDomain string

	// Transport is the wire transport in use; recorded in the init message.
	// Defaults to "websocket" when empty.
	Transport string

	// Capabilities, if non-zero, overrides DefaultClientCapabilities.
	Capabilities Capabilities
}

// NewClient constructs a Client from a ClientConfig.
func NewClient(cfg ClientConfig) *Client {
	caps := cfg.Capabilities
	if len(caps.EncryptionAlgorithms) == 0 {
		caps = DefaultClientCapabilities()
	}
	transport := cfg.Transport
	if transport == "" {
		transport = "websocket"
	}
	return &Client{
		suite:        cfg.Suite,
		store:        cfg.Store,
		identity:     cfg.Identity,
		identityKey:  cfg.IdentityKeyID,
		serverDomain: cfg.ServerDomain,
		transport:    transport,
		capabilities: caps,
	}
}

// Init produces the message 1 (init/client) bytes (HANDSHAKE.md §2.2).
//
// Init generates a fresh 32-byte nonce, a fresh ephemeral X25519 key pair,
// builds the ClientInit struct, and returns its canonical-JSON form. The
// ephemeral private key, nonce, and canonical bytes are retained in c for
// use by OnResponse; the caller must invoke c.Erase if the handshake is
// abandoned.
func (c *Client) Init() ([]byte, error) {
	if c == nil || c.suite == nil {
		return nil, errors.New("handshake: nil client or suite")
	}
	c.nonce = make([]byte, 32)
	if _, err := rand.Read(c.nonce); err != nil {
		return nil, fmt.Errorf("handshake: nonce: %w", err)
	}
	ephPub, ephPriv, err := c.suite.KEM().GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("handshake: ephemeral keypair: %w", err)
	}
	c.ephemeralPub = ephPub
	c.ephemeralPriv = ephPriv

	msg := ClientInit{
		Type:      MessageType,
		Step:      StepInit,
		Party:     PartyClient,
		Version:   "1.0.0",
		Nonce:     base64.StdEncoding.EncodeToString(c.nonce),
		Transport: c.transport,
		ClientEphemeralKey: EphemeralKey{
			Algorithm: string(c.suite.ID()),
			Key:       base64.StdEncoding.EncodeToString(ephPub),
			KeyID:     string(keys.Compute(ephPub)),
		},
		Capabilities: c.capabilities,
		Extensions:   extensions.Map{},
	}
	canonicalBytes, err := CanonicalForHashing(&msg)
	if err != nil {
		return nil, fmt.Errorf("handshake: canonical init: %w", err)
	}
	c.initCanonical = canonicalBytes
	return canonicalBytes, nil
}

// OnChallenge processes a challenge message and returns the bytes of
// the challenge_response message to send next.
//
// The server's signature on the challenge message is verified before
// any solving work begins. If verification fails the handshake MUST
// be aborted (HANDSHAKE.md §2.2a).
//
// If the challenge_type is not recognized, OnChallenge returns an error
// and the client MUST abort the handshake — per the spec a client that
// does not recognize the challenge_type MUST NOT proceed.
func (c *Client) OnChallenge(data []byte) ([]byte, error) {
	if c == nil || c.suite == nil {
		return nil, errors.New("handshake: nil client or suite")
	}
	var req Challenge
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("handshake: parse challenge: %w", err)
	}
	if req.Type != MessageType || req.Step != StepChallenge {
		return nil, errors.New("handshake: challenge type/step mismatch")
	}
	if req.ChallengeType != ChallengeTypeProofOfWork {
		return nil, fmt.Errorf("handshake: unsupported challenge type %q", req.ChallengeType)
	}
	// Verify the server signature before doing any solving work.
	domainPub, err := c.lookupServerDomainKey()
	if err != nil {
		return nil, err
	}
	if err := VerifyServerMessage(c.suite, domainPub, &req, req.ServerSignature); err != nil {
		return nil, err
	}
	// Unmarshal the PoW-specific parameters.
	var params PoWChallengeParams
	if err := json.Unmarshal(req.Parameters, &params); err != nil {
		return nil, fmt.Errorf("handshake: parse challenge parameters: %w", err)
	}
	if params.Algorithm != PoWAlgorithm {
		return nil, fmt.Errorf("handshake: unsupported PoW algorithm %q", params.Algorithm)
	}
	// challenge_invalid gate (HANDSHAKE.md section 2.2a.2). A conformant
	// initiator MUST abort with reason_code "challenge_invalid" when the
	// difficulty exceeds the protocol cap or when the expiry window is
	// shorter than the floor for the chosen difficulty.
	if params.Difficulty > MaxPoWDifficulty {
		return nil, fmt.Errorf("handshake: challenge_invalid: difficulty %d exceeds protocol cap %d",
			params.Difficulty, MaxPoWDifficulty)
	}
	if floor := MinExpiryForDifficulty(params.Difficulty); !req.Expires.IsZero() && time.Until(req.Expires) < floor {
		return nil, fmt.Errorf("handshake: challenge_invalid: expires window shorter than %s floor for difficulty %d",
			floor, params.Difficulty)
	}
	prefix, err := base64.StdEncoding.DecodeString(params.Prefix)
	if err != nil {
		return nil, fmt.Errorf("handshake: challenge prefix base64: %w", err)
	}
	nonceB64, hashHex, err := SolveChallenge(prefix, req.ChallengeID, params.Difficulty, req.Expires)
	if err != nil {
		return nil, fmt.Errorf("handshake: solve challenge: %w", err)
	}
	solData, err := json.Marshal(PoWSolutionData{Nonce: nonceB64, Hash: hashHex})
	if err != nil {
		return nil, fmt.Errorf("handshake: marshal solution: %w", err)
	}
	out := ChallengeResponse{
		Type:          MessageType,
		Step:          StepChallengeResponse,
		Party:         PartyClient,
		Version:       "1.0.0",
		ChallengeID:   req.ChallengeID,
		ChallengeType: req.ChallengeType,
		Solution:      solData,
	}
	return CanonicalForHashing(&out)
}

// OnResponse processes the server's response (message 2), derives the
// session secret, and returns the confirm (message 3) bytes plus a partially
// initialized Session that the caller will finalize on OnAccepted.
//
// Steps performed (HANDSHAKE.md §2.3 – §2.5, SESSION.md §2.1):
//
//  1. Parse the response and verify it echoes our nonce.
//  2. Look up the server's domain public key via the store and verify
//     server_signature.
//  3. Decode the server's ephemeral public key.
//  4. Compute shared secret = X25519(ephemeralPriv, server_ephemeral_pub).
//  5. Derive five session keys with salt = client_nonce || server_nonce.
//  6. Compute confirmation_hash = SHA-256(canonical(init) || canonical(response)).
//  7. Sign session_id || confirmation_hash with the client's identity key.
//  8. AEAD-encrypt the identity proof block under K_enc_c2s.
//  9. Marshal the confirm message and return.
//
// The ephemeral private key is erased before return.
func (c *Client) OnResponse(data []byte) (confirm []byte, sess *session.Session, err error) {
	if c == nil || c.suite == nil {
		return nil, nil, errors.New("handshake: nil client or suite")
	}
	if c.initCanonical == nil {
		return nil, nil, errors.New("handshake: OnResponse called before Init")
	}
	var resp ServerResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, nil, fmt.Errorf("handshake: parse response: %w", err)
	}
	if resp.Type != MessageType || resp.Step != StepResponse || resp.Party != PartyServer {
		return nil, nil, errors.New("handshake: response type/step/party mismatch")
	}
	expectedNonce := base64.StdEncoding.EncodeToString(c.nonce)
	if resp.ClientNonce != expectedNonce {
		return nil, nil, errors.New("handshake: response client_nonce mismatch")
	}

	domainPub, err := c.lookupServerDomainKey()
	if err != nil {
		return nil, nil, err
	}
	if err := VerifyServerMessage(c.suite, domainPub, &resp, resp.ServerSignature); err != nil {
		return nil, nil, err
	}

	// Server ephemeral public key.
	if resp.ServerEphemeralKey.Algorithm != string(c.suite.ID()) {
		return nil, nil, fmt.Errorf("handshake: server suite %q does not match client suite %q",
			resp.ServerEphemeralKey.Algorithm, c.suite.ID())
	}
	serverEphPub, err := base64.StdEncoding.DecodeString(resp.ServerEphemeralKey.Key)
	if err != nil {
		return nil, nil, fmt.Errorf("handshake: server ephemeral key base64: %w", err)
	}
	serverNonce, err := base64.StdEncoding.DecodeString(resp.ServerNonce)
	if err != nil {
		return nil, nil, fmt.Errorf("handshake: server nonce base64: %w", err)
	}

	// Shared secret + session key derivation. For both the baseline
	// X25519 suite and the hybrid Kyber768+X25519 suite, the
	// responder-produced wire blob is treated as a KEM ciphertext
	// that the initiator decapsulates with its private key. For
	// X25519 this is equivalent to the legacy Agree(priv, pub) call;
	// for the hybrid it additionally runs the Kyber768 decapsulation.
	shared, err := c.suite.KEM().Decapsulate(serverEphPub, c.ephemeralPriv)
	if err != nil {
		return nil, nil, fmt.Errorf("handshake: ephemeral KEM: %w", err)
	}
	defer crypto.Zeroize(shared)
	sessionKeys, err := crypto.DeriveSessionKeys(c.suite.KDF(), shared, c.nonce, serverNonce)
	if err != nil {
		return nil, nil, fmt.Errorf("handshake: derive session keys: %w", err)
	}

	// Erase the ephemeral private key now that the shared secret is in hand
	// (SESSION.md §2.2).
	crypto.Zeroize(c.ephemeralPriv)
	c.ephemeralPriv = nil

	// Confirmation hash.
	respCanonical, err := CanonicalForHashing(&resp)
	if err != nil {
		sessionKeys.Erase()
		return nil, nil, fmt.Errorf("handshake: canonical response: %w", err)
	}
	confirmHash, err := ConfirmationHash(c.initCanonical, respCanonical)
	if err != nil {
		sessionKeys.Erase()
		return nil, nil, err
	}

	// Identity proof: signature over session_id || confirmation_hash.
	identityPriv, err := c.store.LoadPrivateKey(context.Background(), c.identityKey)
	if err != nil {
		sessionKeys.Erase()
		return nil, nil, fmt.Errorf("handshake: load identity private key: %w", err)
	}
	defer crypto.Zeroize(identityPriv)
	signed := crypto.PrefixedMessage(crypto.SigCtxIdentity, append([]byte(resp.SessionID), confirmHash...))
	identitySig, err := c.suite.Signer().Sign(identityPriv, signed)
	if err != nil {
		sessionKeys.Erase()
		return nil, nil, fmt.Errorf("handshake: identity sign: %w", err)
	}
	proof := IdentityProofBlock{
		ClientID:            "client-" + resp.SessionID,
		ClientIdentity:      c.identity,
		ClientLongTermKeyID: string(c.identityKey),
		IdentitySignature:   base64.StdEncoding.EncodeToString(identitySig),
		Auth: AuthBlock{
			Method: "identity_key",
			Params: map[string]any{},
		},
	}
	proofBytes, err := json.Marshal(&proof)
	if err != nil {
		sessionKeys.Erase()
		return nil, nil, fmt.Errorf("handshake: marshal identity proof: %w", err)
	}

	// Encrypt under K_enc_c2s with a fresh nonce; the wire form prepends
	// the nonce to the ciphertext, then base64 the whole thing.
	aead := c.suite.AEAD()
	proofNonce, err := crypto.FreshNonce(aead)
	if err != nil {
		sessionKeys.Erase()
		return nil, nil, fmt.Errorf("handshake: identity proof nonce: %w", err)
	}
	proofCT, err := aead.Seal(sessionKeys.EncC2S, proofNonce, proofBytes, []byte(resp.SessionID))
	if err != nil {
		sessionKeys.Erase()
		return nil, nil, fmt.Errorf("handshake: encrypt identity proof: %w", err)
	}
	wrappedProof := append(proofNonce, proofCT...)

	confirmMsg := ClientConfirm{
		Type:             MessageType,
		Step:             StepConfirm,
		Party:            PartyClient,
		Version:          "1.0.0",
		SessionID:        resp.SessionID,
		ConfirmationHash: base64.StdEncoding.EncodeToString(confirmHash),
		IdentityProof:    base64.StdEncoding.EncodeToString(wrappedProof),
		Extensions:       extensions.Map{},
	}
	confirmBytes, err := CanonicalForHashing(&confirmMsg)
	if err != nil {
		sessionKeys.Erase()
		return nil, nil, fmt.Errorf("handshake: canonical confirm: %w", err)
	}

	// Stash state for OnAccepted.
	c.responseCanonical = respCanonical
	c.sessionKeys = sessionKeys
	c.sessionID = resp.SessionID
	c.negotiated = resp.Negotiated

	// Build a partially populated Session. The handshake is not yet
	// established — OnAccepted will set State and timing fields.
	sess = session.New(session.RoleClient)
	sess.ID = resp.SessionID
	sess.PeerIdentity = c.serverDomain
	sess.State = session.StateHandshaking
	sess.SetKeys(sessionKeys)
	return confirmBytes, sess, nil
}

// OnAccepted processes the server's accepted message and finalizes sess.
// After OnAccepted returns nil, sess is in StateActive and may be used to
// send envelopes (HANDSHAKE.md §2.7, SESSION.md §2.6).
func (c *Client) OnAccepted(data []byte, sess *session.Session) error {
	if c == nil || c.suite == nil {
		return errors.New("handshake: nil client or suite")
	}
	if sess == nil {
		return errors.New("handshake: nil session")
	}
	var acc Accepted
	if err := json.Unmarshal(data, &acc); err != nil {
		return fmt.Errorf("handshake: parse accepted: %w", err)
	}
	if acc.Type != MessageType || acc.Step != StepAccepted || acc.Party != PartyServer {
		return errors.New("handshake: accepted type/step/party mismatch")
	}
	if acc.SessionID != c.sessionID {
		return errors.New("handshake: accepted session_id mismatch")
	}
	domainPub, err := c.lookupServerDomainKey()
	if err != nil {
		return err
	}
	if err := VerifyServerMessage(c.suite, domainPub, &acc, acc.ServerSignature); err != nil {
		return err
	}
	ttl := acc.SessionTTL
	if ttl <= 0 {
		// Per HANDSHAKE.md §2.7.1, an accepted message without session_ttl
		// is treated as 300 seconds and SHOULD log a warning.
		ttl = 300
	}
	now := time.Now()
	sess.State = session.StateActive
	sess.EstablishedAt = now
	sess.TTL = time.Duration(ttl) * time.Second
	sess.ExpiresAt = now.Add(sess.TTL)
	return nil
}

// OnRejected processes the server's rejected message and returns the
// corresponding *semp.Error wrapped in a Go error so callers can branch on
// the reason code via errors.As / errors.Is.
func (c *Client) OnRejected(data []byte) error {
	if c == nil {
		return errors.New("handshake: nil client")
	}
	var rej Rejected
	if err := json.Unmarshal(data, &rej); err != nil {
		return fmt.Errorf("handshake: parse rejected: %w", err)
	}
	if rej.Type != MessageType || rej.Step != StepRejected || rej.Party != PartyServer {
		return errors.New("handshake: rejected type/step/party mismatch")
	}
	// We do not require a verified signature here: a malformed or unsigned
	// rejection is still a rejection. The caller can choose to escalate
	// based on whether the signature verifies.
	return &handshakeRejection{Code: rej.ReasonCode, Reason: rej.Reason, SessionID: rej.SessionID}
}

// Erase wipes the ephemeral private key and any retained state. Callers
// MUST invoke Erase if the handshake is abandoned without completing.
func (c *Client) Erase() {
	if c == nil {
		return
	}
	crypto.Zeroize(c.ephemeralPriv)
	crypto.Zeroize(c.nonce)
	c.ephemeralPriv = nil
	c.ephemeralPub = nil
	c.nonce = nil
	c.initCanonical = nil
	c.responseCanonical = nil
	if c.sessionKeys != nil {
		c.sessionKeys.Erase()
		c.sessionKeys = nil
	}
}

func (c *Client) lookupServerDomainKey() ([]byte, error) {
	if c.store == nil {
		return nil, errors.New("handshake: nil key store")
	}
	rec, err := c.store.LookupDomainKey(context.Background(), c.serverDomain)
	if err != nil {
		return nil, fmt.Errorf("handshake: lookup server domain key: %w", err)
	}
	if rec == nil {
		return nil, errors.New("handshake: server domain key not found")
	}
	pub, err := base64.StdEncoding.DecodeString(rec.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("handshake: decode server domain key: %w", err)
	}
	return pub, nil
}

// handshakeRejection is the error type returned by OnRejected. It carries
// the reason_code so callers can branch on it via errors.As, and otherwise
// behaves like a plain error.
type handshakeRejection struct {
	Code      string
	Reason    string
	SessionID string
}

func (e *handshakeRejection) Error() string {
	return fmt.Sprintf("handshake: rejected: %s: %s", e.Code, e.Reason)
}
