package inboxd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	semp "semp.dev/semp-go"
	"semp.dev/semp-go/crypto"
	"semp.dev/semp-go/delivery"
	"semp.dev/semp-go/discovery"
	"semp.dev/semp-go/envelope"
	"semp.dev/semp-go/handshake"
	"semp.dev/semp-go/keys"
	"semp.dev/semp-go/session"
	"semp.dev/semp-go/transport"
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
	//
	// An empty Endpoint means "look up at connect time via the
	// Forwarder's Resolver". The resolved endpoint is cached back
	// into the registry on the first successful lookup.
	Endpoint string

	// DomainSigningKey is the peer's long-term Ed25519 signing public
	// key. Used to verify the peer's ServerResponse / Accepted messages
	// during the federation handshake.
	//
	// A real deployment would fetch this via DANE, SEMP_KEYS, or a
	// pinned list; the demo binary supplies it from a shared seed.
	// It is NOT fetched via discovery because the well-known URI
	// does not carry signing keys.
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
// Each cached federation session has a background goroutine that
// watches the session's TTL and fires an in-session rekey via
// session.Rekeyer at RekeyThreshold * TTL (default 80% per
// SESSION.md §3.1). This keeps long-lived federation hops alive past
// their initial TTL without a full handshake.
//
// Forwarder is safe for concurrent use. Per-session wire access is
// serialized by an internal mutex so auto-rekey slots between
// Forward/FetchKeys calls without interleaving.
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

	// Resolver, if non-nil, is used to look up federation endpoints
	// for peers whose PeerConfig.Endpoint is empty. The resolver
	// walks the DISCOVERY.md §5.1 flow (DNS SRV/TXT, well-known
	// URI, MX fallback) and returns a discovery.Result from which
	// FederationEndpointFunc extracts a URL.
	//
	// If Resolver is nil, PeerConfigs without an Endpoint cause
	// Forward/FetchKeys to return an error.
	Resolver discovery.Resolver

	// FederationEndpointFunc converts a discovery result into the
	// federation endpoint URL the Forwarder should dial. It is
	// called only when PeerConfig.Endpoint is empty and Resolver
	// has produced a status=semp result.
	//
	// When nil, DefaultFederationEndpointFunc is used, which picks
	// the first ws:// endpoint from the discovered Configuration
	// and returns it verbatim. Operators whose federation endpoint
	// differs from the client endpoint path should supply their own
	// (e.g. to substitute "/v1/ws" with "/v1/federate" as the demo
	// binaries do).
	FederationEndpointFunc FederationEndpointFunc

	// rekeyThreshold is the fraction of TTL at which the auto-rekey
	// goroutine fires. Defaults to 0.8 per SESSION.md §3.1.
	rekeyThreshold float64

	// disableAutoRekey, when true, prevents the background goroutine
	// from being spawned. Used by tests that want to observe raw
	// session lifecycle without rekey interference.
	disableAutoRekey bool

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
//
// wireMu serializes access to conn.Send/Recv so the background
// auto-rekey goroutine and the foreground Forward/FetchKeys callers
// don't interleave on the same stream. Every wire operation on conn
// MUST take wireMu before touching the socket.
type forwarderSession struct {
	conn   transport.Conn
	sess   *session.Session
	wireMu sync.Mutex
	// cancel stops the per-session auto-rekey goroutine. Called when
	// the session is dropped or the forwarder is closed.
	cancel context.CancelFunc
}

// FederationEndpointFunc converts a discovery result into the
// federation endpoint URL the Forwarder should dial. The result's
// Configuration (if non-nil) is the full well-known capability
// document; DNS-only resolution leaves it nil and the caller must
// fall back to Result.Server + some convention (e.g. a pinned
// "/v1/federate" suffix).
//
// An error return blocks the session open: the caller treats it as
// "no usable federation endpoint for this peer" and fails the
// forward with a meaningful error.
type FederationEndpointFunc func(result *discovery.Result) (string, error)

// DefaultFederationEndpointFunc is the out-of-the-box endpoint
// picker. It expects the result to carry a well-known Configuration
// and returns the first ws://-scheme endpoint verbatim. This
// matches a server that serves client and federation traffic on
// the same endpoint (which DISCOVERY.md's endpoints map implicitly
// assumes — the spec does not separate client and federation
// endpoints).
//
// Operators whose federation endpoint path differs from the client
// endpoint (e.g. the cmd/semp-server demo binary, which splits
// "/v1/ws" and "/v1/federate") MUST supply their own
// FederationEndpointFunc.
func DefaultFederationEndpointFunc(result *discovery.Result) (string, error) {
	if result == nil {
		return "", errors.New("inboxd: nil discovery result")
	}
	if result.Configuration == nil {
		return "", fmt.Errorf("inboxd: discovery result for %s has no well-known configuration", result.Address)
	}
	for _, scheme := range []string{"wss", "ws"} {
		for transport, url := range result.Configuration.Endpoints {
			if transport == "ws" && hasScheme(url, scheme) {
				return url, nil
			}
		}
	}
	// No ws-scheme match; return whatever is at the "ws" key.
	if ep, ok := result.Configuration.Endpoints["ws"]; ok {
		return ep, nil
	}
	return "", fmt.Errorf("inboxd: discovery result for %s has no ws endpoint", result.Address)
}

// hasScheme reports whether url starts with the given scheme
// followed by "://". Cheap string prefix check.
func hasScheme(url, scheme string) bool {
	prefix := scheme + "://"
	return len(url) >= len(prefix) && url[:len(prefix)] == prefix
}

// NewForwarder constructs a Forwarder. cfg provides the static
// configuration (suite, keys, peer registry, dialer); the internal
// session cache is initialized fresh.
func NewForwarder(cfg ForwarderConfig) *Forwarder {
	peers := cfg.Peers
	if peers == nil {
		peers = NewPeerRegistry()
	}
	threshold := cfg.RekeyThreshold
	if threshold <= 0 {
		threshold = 0.8
	}
	return &Forwarder{
		Suite:                  cfg.Suite,
		LocalDomain:            cfg.LocalDomain,
		LocalDomainKeyID:       cfg.LocalDomainKeyID,
		LocalDomainPrivateKey:  cfg.LocalDomainPrivateKey,
		Peers:                  peers,
		Dial:                   cfg.Dial,
		Store:                  cfg.Store,
		Resolver:               cfg.Resolver,
		FederationEndpointFunc: cfg.FederationEndpointFunc,
		rekeyThreshold:         threshold,
		disableAutoRekey:       cfg.DisableAutoRekey,
		sessions:               make(map[string]*forwarderSession),
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

	// Resolver enables discovery-driven peer endpoint resolution.
	// When set, PeerConfigs with an empty Endpoint are looked up
	// on first use via the DISCOVERY.md §5.1 flow.
	Resolver discovery.Resolver

	// FederationEndpointFunc converts a discovery result to the
	// federation endpoint URL. Defaults to DefaultFederationEndpointFunc.
	FederationEndpointFunc FederationEndpointFunc

	// RekeyThreshold is the fraction of TTL at which the background
	// auto-rekey goroutine fires. SESSION.md §3.1 recommends 0.8.
	// Zero means "use the default". Tests can set this lower (e.g.
	// 0.2) to observe rekey happening within a short-lived session.
	RekeyThreshold float64

	// DisableAutoRekey skips spawning the per-session auto-rekey
	// goroutine. Intended for tests that want to inspect raw session
	// lifecycle without rekey interference.
	DisableAutoRekey bool
}

// Close tears down every cached federation session, stopping each
// session's background auto-rekey goroutine before closing the
// underlying connection. Call this during server shutdown.
func (f *Forwarder) Close() {
	f.mu.Lock()
	sessions := f.sessions
	f.sessions = make(map[string]*forwarderSession)
	f.mu.Unlock()
	for _, fs := range sessions {
		if fs.cancel != nil {
			fs.cancel()
		}
		if fs.conn != nil {
			_ = fs.conn.Close()
		}
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
		// Unknown peer — auto-register with just the domain name.
		// getSession will resolve the endpoint via DNS SRV / well-known
		// discovery, and the domain signing key will be fetched lazily
		// by the Store's LookupDomainKey implementation.
		peerCfg = PeerConfig{Domain: peerDomain}
		f.Peers.Put(peerCfg)
	}

	fs, err := f.getSession(ctx, peerCfg)
	if err != nil {
		return nil, err
	}

	respRaw, dropNeeded, err := f.forwardOnSession(ctx, fs, env)
	if dropNeeded {
		f.dropSession(peerDomain)
	}
	if err != nil {
		return nil, err
	}
	var resp delivery.SubmissionResponse
	if err := json.Unmarshal(respRaw, &resp); err != nil {
		return nil, fmt.Errorf("inboxd: parse federation submission response: %w", err)
	}
	return &resp, nil
}

// forwardOnSession performs one send/recv round trip on fs under
// fs.wireMu. It returns the raw response bytes, a flag that tells the
// caller whether the session should be dropped (true for transport
// errors), and an error. Kept separate from Forward so the wire lock
// defers cleanly without juggling unlock/drop/relock.
func (f *Forwarder) forwardOnSession(ctx context.Context, fs *forwarderSession, env *envelope.Envelope) ([]byte, bool, error) {
	fs.wireMu.Lock()
	defer fs.wireMu.Unlock()

	// Update the postmark session_id so the peer references the
	// federation session when verifying. This MUST happen before
	// re-signing, because session_id is in the postmark and therefore
	// covered by both proofs' canonical input bytes.
	env.Postmark.SessionID = fs.sess.ID

	// Re-sign with our local domain key. The sender's home server and
	// the federation initiator are the SAME server in this
	// architecture, so "re-signing with our domain key" is
	// functionally identical to "the sender's domain signed this
	// envelope" — the provenance proof is unchanged.
	if err := envelope.Sign(env, f.Suite, f.LocalDomainPrivateKey, fs.sess.EnvMAC()); err != nil {
		return nil, false, fmt.Errorf("inboxd: re-sign forwarded envelope: %w", err)
	}
	wire, err := envelope.Encode(env)
	if err != nil {
		return nil, false, fmt.Errorf("inboxd: encode forwarded envelope: %w", err)
	}
	if err := fs.conn.Send(ctx, wire); err != nil {
		return nil, true, fmt.Errorf("inboxd: send forwarded envelope: %w", err)
	}
	respRaw, err := fs.conn.Recv(ctx)
	if err != nil {
		return nil, true, fmt.Errorf("inboxd: recv federation submission response: %w", err)
	}
	return respRaw, false, nil
}

// getSession returns a cached federation session for peerCfg.Domain,
// opening one via the federation handshake if necessary. When a fresh
// session is opened, a background auto-rekey goroutine is spawned
// (unless disableAutoRekey is set) and cancelled when the session is
// dropped.
//
// If peerCfg.Endpoint is empty, the Resolver (if configured) is
// consulted to look up the federation endpoint for the peer domain.
// The resolved endpoint is cached back into the registry via
// Peers.Put so subsequent calls hit the static path.
func (f *Forwarder) getSession(ctx context.Context, peerCfg PeerConfig) (*forwarderSession, error) {
	f.mu.Lock()
	fs, ok := f.sessions[peerCfg.Domain]
	f.mu.Unlock()
	if ok && f.sessionActive(fs) {
		return fs, nil
	}
	// Open a fresh federation session.
	if f.Store == nil {
		return nil, errors.New("inboxd: forwarder has no Store for peer key material")
	}

	// Resolve the federation endpoint if we don't have one cached
	// on the PeerConfig.
	if peerCfg.Endpoint == "" {
		resolved, err := f.resolveFederationEndpoint(ctx, peerCfg.Domain)
		if err != nil {
			return nil, err
		}
		peerCfg.Endpoint = resolved
		f.Peers.Put(peerCfg)
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
	bgCtx, cancel := context.WithCancel(context.Background())
	newFS := &forwarderSession{
		conn:   conn,
		sess:   sess,
		cancel: cancel,
	}
	f.mu.Lock()
	// Check again in case another goroutine raced us; prefer the newer
	// session and close any duplicate.
	if existing, ok := f.sessions[peerCfg.Domain]; ok {
		f.mu.Unlock()
		if f.sessionActive(existing) {
			cancel()
			_ = conn.Close()
			return existing, nil
		}
		f.mu.Lock()
	}
	f.sessions[peerCfg.Domain] = newFS
	f.mu.Unlock()

	if !f.disableAutoRekey {
		go f.autoRekey(bgCtx, peerCfg.Domain, newFS)
	}
	return newFS, nil
}

// resolveFederationEndpoint uses the Forwarder's Resolver and
// FederationEndpointFunc to look up a federation endpoint URL for
// a peer whose PeerConfig.Endpoint is empty. It returns an error
// when no Resolver is configured, when discovery does not find a
// SEMP-capable endpoint for the domain, or when the endpoint func
// rejects the resolved result.
func (f *Forwarder) resolveFederationEndpoint(ctx context.Context, peerDomain string) (string, error) {
	if f.Resolver == nil {
		return "", fmt.Errorf("inboxd: peer %s has no endpoint and no Resolver is configured", peerDomain)
	}
	result, err := f.Resolver.Resolve(ctx, peerDomain)
	if err != nil {
		return "", fmt.Errorf("inboxd: resolve peer %s: %w", peerDomain, err)
	}
	if result == nil {
		return "", fmt.Errorf("inboxd: resolver returned nil result for %s", peerDomain)
	}
	if result.Status != semp.DiscoverySEMP {
		return "", fmt.Errorf("inboxd: peer %s discovery status %s (not semp)", peerDomain, result.Status)
	}
	endpointFunc := f.FederationEndpointFunc
	if endpointFunc == nil {
		endpointFunc = DefaultFederationEndpointFunc
	}
	endpoint, err := endpointFunc(result)
	if err != nil {
		return "", fmt.Errorf("inboxd: derive federation endpoint for %s: %w", peerDomain, err)
	}
	if endpoint == "" {
		return "", fmt.Errorf("inboxd: federation endpoint func returned empty URL for %s", peerDomain)
	}
	return endpoint, nil
}

// dropSession removes the cached session for peerDomain, stopping its
// auto-rekey goroutine and closing its underlying connection. Used
// when a forward/fetch fails and we cannot tell whether the remote
// side still considers the session active.
func (f *Forwarder) dropSession(peerDomain string) {
	f.mu.Lock()
	fs, ok := f.sessions[peerDomain]
	if ok {
		delete(f.sessions, peerDomain)
	}
	f.mu.Unlock()
	if ok {
		if fs.cancel != nil {
			fs.cancel()
		}
		if fs.conn != nil {
			_ = fs.conn.Close()
		}
	}
}

// SessionSnapshot returns a shallow copy of the session state cached
// for peerDomain, or nil if no session is cached. Intended for tests
// and operator-visible diagnostics — callers must not mutate the
// returned *session.Session, and the copy does NOT carry live keys
// (only metadata: ID, TTL, ExpiresAt, RekeyCount, LastRekeyAt,
// PreviousID).
//
// The snapshot is taken under the session's wire lock so it cannot
// race with an in-flight forward or rekey.
func (f *Forwarder) SessionSnapshot(peerDomain string) *session.Session {
	f.mu.Lock()
	fs, ok := f.sessions[peerDomain]
	f.mu.Unlock()
	if !ok {
		return nil
	}
	fs.wireMu.Lock()
	defer fs.wireMu.Unlock()
	if fs.sess == nil {
		return nil
	}
	snap := *fs.sess
	return &snap
}

// autoRekey runs as a background goroutine per cached federation
// session. It sleeps until RekeyThreshold * TTL has elapsed since
// the session's last establishment or rekey, takes fs.wireMu to
// serialize with Forward/FetchKeys, runs session.Rekeyer.Rekey, and
// loops. Exits when ctx is cancelled (dropSession or Close) or when
// the session becomes inactive.
//
// A failing rekey drops the session entirely: the peer will need to
// re-handshake on the next Forward/FetchKeys call. This matches the
// spec's "rekey MUST NOT be initiated after the session has expired"
// rule (SESSION.md §3.1) in spirit: if rekey fails, the session is
// treated as dead.
func (f *Forwarder) autoRekey(ctx context.Context, peerDomain string, fs *forwarderSession) {
	for {
		// Compute the wake-up time for the next rekey attempt.
		fs.wireMu.Lock()
		sess := fs.sess
		if sess == nil || sess.TTL <= 0 || !sess.Active(nowFunc()) {
			fs.wireMu.Unlock()
			return
		}
		wakeAt := sess.ExpiresAt.Add(-time.Duration(float64(sess.TTL) * (1.0 - f.rekeyThreshold)))
		fs.wireMu.Unlock()

		sleep := time.Until(wakeAt)
		if sleep < 0 {
			sleep = 0
		}
		timer := time.NewTimer(sleep)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}

		// Take the wire lock and attempt the rekey. The rekeyer's
		// session argument is the same pointer the foreground
		// callers see, so ApplyRekey mutates it in place.
		fs.wireMu.Lock()
		if fs.sess == nil || !fs.sess.Active(nowFunc()) {
			fs.wireMu.Unlock()
			return
		}
		rekeyer := &session.Rekeyer{
			Suite:              f.Suite,
			Session:            fs.sess,
			InitiatorDirection: session.DirectionC2S,
		}
		if err := rekeyer.Rekey(ctx, fs.conn); err != nil {
			fs.wireMu.Unlock()
			// Rekey failed: drop the session so the next caller
			// runs a fresh handshake. The goroutine exits.
			f.dropSession(peerDomain)
			return
		}
		fs.wireMu.Unlock()
		// Loop: compute the next wake-up based on the new ExpiresAt.
	}
}

// sessionActive is a race-safe wrapper around fs.sess.Active: it
// takes fs.wireMu before reading the session fields, which is
// necessary because the autoRekey goroutine mutates the session
// state under the same lock.
func (f *Forwarder) sessionActive(fs *forwarderSession) bool {
	if fs == nil {
		return false
	}
	fs.wireMu.Lock()
	defer fs.wireMu.Unlock()
	return fs.sess != nil && fs.sess.Active(nowFunc())
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
		peerCfg = PeerConfig{Domain: peerDomain}
		f.Peers.Put(peerCfg)
	}
	fs, err := f.getSession(ctx, peerCfg)
	if err != nil {
		return nil, err
	}
	respRaw, dropNeeded, err := f.fetchKeysOnSession(ctx, fs, req)
	if dropNeeded {
		f.dropSession(peerDomain)
	}
	if err != nil {
		return nil, err
	}
	var resp keys.Response
	if err := json.Unmarshal(respRaw, &resp); err != nil {
		return nil, fmt.Errorf("inboxd: parse SEMP_KEYS response: %w", err)
	}
	return &resp, nil
}

// fetchKeysOnSession is the FetchKeys counterpart of forwardOnSession:
// one send/recv round trip on fs under fs.wireMu.
func (f *Forwarder) fetchKeysOnSession(ctx context.Context, fs *forwarderSession, req *keys.Request) ([]byte, bool, error) {
	fs.wireMu.Lock()
	defer fs.wireMu.Unlock()
	reqBytes, err := json.Marshal(req)
	if err != nil {
		return nil, false, fmt.Errorf("inboxd: marshal SEMP_KEYS request: %w", err)
	}
	if err := fs.conn.Send(ctx, reqBytes); err != nil {
		return nil, true, fmt.Errorf("inboxd: send SEMP_KEYS request: %w", err)
	}
	respRaw, err := fs.conn.Recv(ctx)
	if err != nil {
		return nil, true, fmt.Errorf("inboxd: recv SEMP_KEYS response: %w", err)
	}
	return respRaw, false, nil
}
