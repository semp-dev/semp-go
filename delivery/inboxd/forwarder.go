package inboxd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/semp-dev/semp-go/crypto"
	"github.com/semp-dev/semp-go/delivery"
	"github.com/semp-dev/semp-go/envelope"
	"github.com/semp-dev/semp-go/handshake"
	"github.com/semp-dev/semp-go/keys"
	"github.com/semp-dev/semp-go/session"
	"github.com/semp-dev/semp-go/transport"
)

// PeerRegistry maps a remote domain to the set of endpoints and key
// material a Forwarder needs to open a federation session to that peer.
//
// PeerRegistry is a deliberately minimal substitute for a real discovery
// layer. A production server would consult DNS SRV/TXT records, the
// remote's well-known URI, and SEMP_DISCOVERY responses; the demo binary
// ships with a static peer map on the command line.
type PeerRegistry struct {
	mu    sync.RWMutex
	peers map[string]PeerConfig
}

// NewPeerRegistry returns a fresh empty registry.
func NewPeerRegistry() *PeerRegistry {
	return &PeerRegistry{peers: make(map[string]PeerConfig)}
}

// PeerConfig is the per-peer routing information a Forwarder needs.
type PeerConfig struct {
	// Domain is the peer's domain (e.g. "b.example").
	Domain string

	// Endpoint is the peer's federation endpoint URL
	// (e.g. "ws://127.0.0.1:18082/v1/federate" for the demo binary).
	Endpoint string

	// DomainSigningKey is the peer's long-term Ed25519 signing public
	// key. Used to verify the peer's ServerResponse / Accepted messages
	// during the federation handshake.
	DomainSigningKey []byte
}

// Put registers a peer in the registry.
func (r *PeerRegistry) Put(cfg PeerConfig) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.peers[cfg.Domain] = cfg
}

// Lookup returns the PeerConfig for domain, or (zero, false) if unknown.
func (r *PeerRegistry) Lookup(domain string) (PeerConfig, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	cfg, ok := r.peers[domain]
	return cfg, ok
}

// Dialer opens a bidirectional message stream to a peer's federation
// endpoint. The Forwarder uses it to avoid depending on a specific
// transport package. In the demo binary this is a tiny shim over
// transport/ws.Dial; tests can provide their own in-memory dialer.
type Dialer func(ctx context.Context, endpoint string) (transport.Conn, error)

// Forwarder establishes and caches federation sessions to remote peers
// and forwards envelopes across them. Each (localDomain, peerDomain)
// pair gets at most one live session at a time; the forwarder re-runs
// the federation handshake if the cached session has expired or been
// torn down.
//
// Forwarder is safe for concurrent use.
type Forwarder struct {
	// Suite is the cryptographic suite used for all outbound federation
	// handshakes. Must match the suite used elsewhere in the process.
	Suite crypto.Suite

	// LocalDomain is the sender's domain.
	LocalDomain string

	// LocalDomainKeyID is the fingerprint of the local server's
	// signing key (used as the federation initiator identity).
	LocalDomainKeyID keys.Fingerprint

	// LocalDomainPrivateKey is the local server's long-term signing
	// private key. Used by the federation Initiator.
	LocalDomainPrivateKey []byte

	// Peers is the static peer registry. New peers can be added at
	// runtime via Peers.Put.
	Peers *PeerRegistry

	// Dial is the function used to open a transport.Conn to a peer's
	// federation endpoint. Must not be nil.
	Dial Dialer

	// Store is the keys.Store handed to the federation Initiator. The
	// Forwarder will temporarily register each peer's domain key in this
	// store before opening a session so the Initiator can verify the
	// peer's signatures.
	Store SharedStore

	mu       sync.Mutex
	sessions map[string]*forwarderSession // keyed by peer domain
}

// SharedStore is the subset of keys.Store operations the Forwarder
// needs: lookups are delegated to the Initiator via the Store field;
// writes are used only to publish peer domain keys before opening a
// handshake. Any keys.Store that the local server also owns will work.
type SharedStore interface {
	keys.Store
	PutDomainKey(domain string, pub []byte) keys.Fingerprint
}

// forwarderSession is the cached per-peer federation session state.
type forwarderSession struct {
	conn transport.Conn
	sess *session.Session
}

// NewForwarder constructs a Forwarder. cfg provides the static
// configuration (suite, keys, peer registry, dialer); the internal
// session cache is initialized fresh.
func NewForwarder(cfg ForwarderConfig) *Forwarder {
	peers := cfg.Peers
	if peers == nil {
		peers = NewPeerRegistry()
	}
	return &Forwarder{
		Suite:                 cfg.Suite,
		LocalDomain:           cfg.LocalDomain,
		LocalDomainKeyID:      cfg.LocalDomainKeyID,
		LocalDomainPrivateKey: cfg.LocalDomainPrivateKey,
		Peers:                 peers,
		Dial:                  cfg.Dial,
		Store:                 cfg.Store,
		sessions:              make(map[string]*forwarderSession),
	}
}

// ForwarderConfig groups the inputs to NewForwarder. It mirrors the
// exported Forwarder fields but doesn't carry the sync.Mutex, which
// makes it safe to pass by value.
type ForwarderConfig struct {
	Suite                 crypto.Suite
	LocalDomain           string
	LocalDomainKeyID      keys.Fingerprint
	LocalDomainPrivateKey []byte
	Peers                 *PeerRegistry
	Dial                  Dialer
	Store                 SharedStore
}

// Close tears down every cached federation session. Call this during
// server shutdown.
func (f *Forwarder) Close() {
	f.mu.Lock()
	defer f.mu.Unlock()
	for dom, fs := range f.sessions {
		if fs.conn != nil {
			_ = fs.conn.Close()
		}
		delete(f.sessions, dom)
	}
}

// Forward re-binds seal.session_mac under the federation session's
// K_env_mac and ships env across that session. The domain signature
// on the envelope is NOT touched — it's the original sender-domain
// proof of provenance and stays valid across the hop.
//
// The returned SubmissionResponse is the peer's verbatim reply. On
// transport or handshake error, Forward returns the error without
// caching the failed session.
func (f *Forwarder) Forward(ctx context.Context, peerDomain string, env *envelope.Envelope) (*delivery.SubmissionResponse, error) {
	if env == nil {
		return nil, errors.New("inboxd: nil envelope")
	}
	if f.Dial == nil {
		return nil, errors.New("inboxd: forwarder has no Dial")
	}
	peerCfg, ok := f.Peers.Lookup(peerDomain)
	if !ok {
		return nil, fmt.Errorf("inboxd: no peer config for %s", peerDomain)
	}

	fs, err := f.getSession(ctx, peerCfg)
	if err != nil {
		return nil, err
	}

	// Update the postmark session_id so the peer references the
	// federation session when verifying. This MUST happen before
	// re-signing, because session_id is in the postmark and therefore
	// covered by both proofs' canonical input bytes.
	env.Postmark.SessionID = fs.sess.ID

	// Re-sign with our local domain key. Subtle point: the sender's
	// home server and the federation initiator are the SAME server in
	// this architecture, so "re-signing with our domain key" is
	// functionally identical to "the sender's domain signed this
	// envelope" — the provenance proof is unchanged. The signature
	// value over the canonical bytes is different because session_id
	// changed, but the key behind the signature is still a.example's
	// domain key. A multi-hop relay that did NOT originate the
	// envelope would not be able to do this; in the federated delivery
	// model the sending side always re-signs for the hop it controls.
	//
	// envelope.Sign recomputes both seal.signature (with the domain
	// key) and seal.session_mac (with the federation K_env_mac).
	if err := envelope.Sign(env, f.Suite, f.LocalDomainPrivateKey, fs.sess.EnvMAC()); err != nil {
		return nil, fmt.Errorf("inboxd: re-sign forwarded envelope: %w", err)
	}

	wire, err := envelope.Encode(env)
	if err != nil {
		return nil, fmt.Errorf("inboxd: encode forwarded envelope: %w", err)
	}
	if err := fs.conn.Send(ctx, wire); err != nil {
		f.dropSession(peerDomain)
		return nil, fmt.Errorf("inboxd: send forwarded envelope: %w", err)
	}
	respRaw, err := fs.conn.Recv(ctx)
	if err != nil {
		f.dropSession(peerDomain)
		return nil, fmt.Errorf("inboxd: recv federation submission response: %w", err)
	}
	var resp delivery.SubmissionResponse
	if err := json.Unmarshal(respRaw, &resp); err != nil {
		return nil, fmt.Errorf("inboxd: parse federation submission response: %w", err)
	}
	return &resp, nil
}

// getSession returns a cached federation session for peerCfg.Domain,
// opening one via the federation handshake if necessary.
func (f *Forwarder) getSession(ctx context.Context, peerCfg PeerConfig) (*forwarderSession, error) {
	f.mu.Lock()
	fs, ok := f.sessions[peerCfg.Domain]
	f.mu.Unlock()
	if ok && fs.sess.Active(nowFunc()) {
		return fs, nil
	}
	// Open a fresh federation session.
	if f.Store == nil {
		return nil, errors.New("inboxd: forwarder has no Store for peer key material")
	}
	// Publish the peer's domain signing key so the Initiator can verify
	// the peer's signatures during the handshake.
	f.Store.PutDomainKey(peerCfg.Domain, peerCfg.DomainSigningKey)

	conn, err := f.Dial(ctx, peerCfg.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("inboxd: dial peer %s: %w", peerCfg.Endpoint, err)
	}
	initiator := handshake.NewInitiator(handshake.InitiatorConfig{
		Suite:                 f.Suite,
		Store:                 f.Store,
		LocalDomain:           f.LocalDomain,
		LocalDomainKeyID:      f.LocalDomainKeyID,
		LocalDomainPrivateKey: f.LocalDomainPrivateKey,
		PeerDomain:            peerCfg.Domain,
		DomainProof: handshake.DomainProof{
			Method: handshake.DomainVerifyTestTrust,
			Data:   f.LocalDomain,
		},
	})
	sess, err := handshake.RunInitiator(ctx, conn, initiator)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("inboxd: federation handshake with %s: %w", peerCfg.Domain, err)
	}
	newFS := &forwarderSession{conn: conn, sess: sess}
	f.mu.Lock()
	// Check again in case another goroutine raced us; prefer the newer
	// session and close any duplicate.
	if existing, ok := f.sessions[peerCfg.Domain]; ok && existing.sess.Active(nowFunc()) {
		f.mu.Unlock()
		_ = conn.Close()
		return existing, nil
	}
	f.sessions[peerCfg.Domain] = newFS
	f.mu.Unlock()
	return newFS, nil
}

// dropSession removes the cached session for peerDomain, closing its
// underlying connection. Used when a forward fails and we cannot tell
// whether the remote side still considers the session active.
func (f *Forwarder) dropSession(peerDomain string) {
	f.mu.Lock()
	fs, ok := f.sessions[peerDomain]
	if ok {
		delete(f.sessions, peerDomain)
	}
	f.mu.Unlock()
	if ok && fs.conn != nil {
		_ = fs.conn.Close()
	}
}

// nowFunc is a package-level indirection so tests can freeze time.
// Currently unused for that purpose but here for symmetry with the
// handshake package.
var nowFunc = time.Now

// FetchKeys forwards a SEMP_KEYS request over the cached federation
// session with peerDomain. It opens a fresh session if none is cached.
//
// Unlike Forward, FetchKeys does NOT touch any envelope — it simply
// marshals the request, writes it to the federation stream, and parses
// the response. The peer is expected to be running inboxd in
// ModeFederation, which handles SEMP_KEYS on the federation path.
//
// The peer's response is returned verbatim; the caller is responsible
// for verifying any signatures on the enclosed key records.
func (f *Forwarder) FetchKeys(ctx context.Context, peerDomain string, req *keys.Request) (*keys.Response, error) {
	if req == nil {
		return nil, errors.New("inboxd: nil SEMP_KEYS request")
	}
	if f.Dial == nil {
		return nil, errors.New("inboxd: forwarder has no Dial")
	}
	peerCfg, ok := f.Peers.Lookup(peerDomain)
	if !ok {
		return nil, fmt.Errorf("inboxd: no peer config for %s", peerDomain)
	}
	fs, err := f.getSession(ctx, peerCfg)
	if err != nil {
		return nil, err
	}
	reqBytes, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("inboxd: marshal SEMP_KEYS request: %w", err)
	}
	if err := fs.conn.Send(ctx, reqBytes); err != nil {
		f.dropSession(peerDomain)
		return nil, fmt.Errorf("inboxd: send SEMP_KEYS request: %w", err)
	}
	respRaw, err := fs.conn.Recv(ctx)
	if err != nil {
		f.dropSession(peerDomain)
		return nil, fmt.Errorf("inboxd: recv SEMP_KEYS response: %w", err)
	}
	var resp keys.Response
	if err := json.Unmarshal(respRaw, &resp); err != nil {
		return nil, fmt.Errorf("inboxd: parse SEMP_KEYS response: %w", err)
	}
	return &resp, nil
}
