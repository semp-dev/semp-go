package delivery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	semp "github.com/semp-dev/semp-go"
	"github.com/semp-dev/semp-go/crypto"
	"github.com/semp-dev/semp-go/discovery"
	"github.com/semp-dev/semp-go/envelope"
	"github.com/semp-dev/semp-go/handshake"
	"github.com/semp-dev/semp-go/keys"
	"github.com/semp-dev/semp-go/session"
	"github.com/semp-dev/semp-go/transport"
)

// EndpointResolver returns the federation endpoint URL the Forwarder
// should dial for peerDomain. Implementations cover the full range of
// peer-endpoint sourcing: a discovery-driven lookup over DNS SRV plus
// the well-known URI per DISCOVERY.md §5.1 (see
// EndpointResolverFromDiscovery), a static map for operators that
// pre-pin known peers, or a hybrid that consults the static map first
// and falls back to discovery.
//
// Returning an error blocks the federation handshake. The Forwarder
// surfaces it to whoever asked for the forward.
type EndpointResolver func(ctx context.Context, peerDomain string) (string, error)

// Dialer opens a bidirectional message stream to a peer's federation
// endpoint. Production code passes a tiny shim over transport/ws.Dial
// or transport/h2.Dial; tests pass an in-memory dialer.
type Dialer func(ctx context.Context, endpoint string) (transport.Conn, error)

// FederationEndpointFunc converts a discovery result into the
// federation endpoint URL to dial. Used by
// EndpointResolverFromDiscovery to bridge a discovery.Resolver into
// the EndpointResolver shape the Forwarder requires.
//
// An error return blocks session open: the caller treats it as "no
// usable federation endpoint for this peer" and fails the forward
// with a meaningful error.
type FederationEndpointFunc func(result *discovery.Result) (string, error)

// DefaultFederationEndpointFunc is the out-of-the-box endpoint picker
// used by EndpointResolverFromDiscovery when no explicit selector is
// supplied. It prefers transports in the spec's recommended order:
// QUIC > WebSocket > HTTP/2.
//
// If the discovery result carries no well-known configuration but
// does carry a DNS-resolved server name, it falls back to HTTP/2 at
// "/v1/h2/federate" on that server, since every conformant SEMP
// server MUST accept HTTP/2 connections per TRANSPORT.md §4 and
// federation traffic terminates at /v1/h2/federate per
// TRANSPORT.md §4.2.
func DefaultFederationEndpointFunc(result *discovery.Result) (string, error) {
	if result == nil {
		return "", errors.New("delivery: nil discovery result")
	}
	if result.Configuration != nil {
		fed := result.Configuration.Endpoints.Federation
		if fed != nil {
			for _, tid := range []string{"quic", "ws"} {
				if ep, ok := fed[tid]; ok {
					return ep, nil
				}
			}
			if ep, ok := fed["h2"]; ok {
				return ep, nil
			}
		}
	}
	if result.Server != "" {
		return "https://" + strings.TrimSuffix(result.Server, ".") + "/v1/h2/federate", nil
	}
	return "", fmt.Errorf("delivery: discovery result for %s has no endpoint", result.Address)
}

// EndpointResolverFromDiscovery wraps a discovery.Resolver into the
// EndpointResolver shape. endpointFunc selects which entry in the
// resolved configuration's federation endpoints to dial; pass nil for
// DefaultFederationEndpointFunc.
//
// Operators that want to pre-pin a known peer endpoint (and skip DNS
// or well-known fetches) compose their own EndpointResolver directly,
// without going through this helper. Both shapes are equally valid;
// neither is privileged by the protocol.
func EndpointResolverFromDiscovery(r discovery.Resolver, endpointFunc FederationEndpointFunc) EndpointResolver {
	if endpointFunc == nil {
		endpointFunc = DefaultFederationEndpointFunc
	}
	return func(ctx context.Context, peerDomain string) (string, error) {
		if r == nil {
			return "", fmt.Errorf("delivery: nil discovery.Resolver for peer %s", peerDomain)
		}
		result, err := r.Resolve(ctx, peerDomain)
		if err != nil {
			return "", fmt.Errorf("delivery: resolve peer %s: %w", peerDomain, err)
		}
		if result == nil {
			return "", fmt.Errorf("delivery: discovery.Resolver returned nil result for %s", peerDomain)
		}
		if result.Status != semp.DiscoverySEMP {
			return "", fmt.Errorf("delivery: peer %s discovery status %s (not semp)", peerDomain, result.Status)
		}
		endpoint, err := endpointFunc(result)
		if err != nil {
			return "", fmt.Errorf("delivery: derive federation endpoint for %s: %w", peerDomain, err)
		}
		if endpoint == "" {
			return "", fmt.Errorf("delivery: federation endpoint func returned empty URL for %s", peerDomain)
		}
		return endpoint, nil
	}
}

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
//
// Forwarder is protocol-pure: the two pluggable inputs it requires
// (Store and EndpointResolver) cover everything the spec defines for
// federation peer addressing. Peer signing keys live in Store and are
// expected to be populated either by the operator at startup or by a
// KEY.md fetcher running alongside the Forwarder. Peer endpoint URLs
// come from EndpointResolver, which the operator constructs from
// either a discovery.Resolver (DNS SRV plus well-known URI) or a
// static peer map, or both.
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

	// Store is the keys.Store handed to the federation Initiator.
	// Peer signing keys MUST be discoverable through
	// Store.LookupDomainKey before the first Forward / FetchKeys call
	// for that peer; this is a precondition the operator satisfies by
	// pre-seeding the store at startup or by running a KEY.md fetcher
	// alongside the Forwarder.
	Store keys.Store

	// EndpointResolver returns the federation endpoint URL for a peer
	// domain. Required.
	EndpointResolver EndpointResolver

	// Dial is the function used to open a transport.Conn to the URL
	// EndpointResolver returns. Required.
	Dial Dialer

	// rekeyThreshold is the fraction of TTL at which the auto-rekey
	// goroutine fires. Defaults to 0.8 per SESSION.md §3.1.
	rekeyThreshold float64

	// disableAutoRekey, when true, prevents the background goroutine
	// from being spawned. Used by tests that want to observe raw
	// session lifecycle without rekey interference.
	disableAutoRekey bool

	mu         sync.Mutex
	sessions   map[string]*forwarderSession // keyed by peer domain
	connecting map[string]chan struct{}     // per-domain connection-in-progress guard
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

// ForwarderConfig groups the inputs to NewForwarder. It mirrors the
// exported Forwarder fields but doesn't carry the sync.Mutex, which
// makes it safe to pass by value.
type ForwarderConfig struct {
	Suite                 crypto.Suite
	LocalDomain           string
	LocalDomainKeyID      keys.Fingerprint
	LocalDomainPrivateKey []byte
	Store                 keys.Store
	EndpointResolver      EndpointResolver
	Dial                  Dialer

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

// NewForwarder constructs a Forwarder. cfg provides the static
// configuration (suite, keys, store, endpoint resolver, dialer); the
// internal session cache is initialized fresh.
func NewForwarder(cfg ForwarderConfig) *Forwarder {
	threshold := cfg.RekeyThreshold
	if threshold <= 0 {
		threshold = 0.8
	}
	return &Forwarder{
		Suite:                 cfg.Suite,
		LocalDomain:           cfg.LocalDomain,
		LocalDomainKeyID:      cfg.LocalDomainKeyID,
		LocalDomainPrivateKey: cfg.LocalDomainPrivateKey,
		Store:                 cfg.Store,
		EndpointResolver:      cfg.EndpointResolver,
		Dial:                  cfg.Dial,
		rekeyThreshold:        threshold,
		disableAutoRekey:      cfg.DisableAutoRekey,
		sessions:              make(map[string]*forwarderSession),
		connecting:            make(map[string]chan struct{}),
	}
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
// on the envelope is NOT touched; it's the original sender-domain
// proof of provenance and stays valid across the hop.
//
// The returned SubmissionResponse is the peer's verbatim reply. On
// transport or handshake error, Forward returns the error without
// caching the failed session.
func (f *Forwarder) Forward(ctx context.Context, peerDomain string, env *envelope.Envelope) (*SubmissionResponse, error) {
	if env == nil {
		return nil, errors.New("delivery: nil envelope")
	}
	fs, err := f.getSession(ctx, peerDomain)
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
	var resp SubmissionResponse
	if err := json.Unmarshal(respRaw, &resp); err != nil {
		return nil, fmt.Errorf("delivery: parse federation submission response: %w", err)
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
	// envelope" - the provenance proof is unchanged.
	if err := envelope.Sign(env, f.Suite, f.LocalDomainPrivateKey, fs.sess.EnvMAC()); err != nil {
		return nil, false, fmt.Errorf("delivery: re-sign forwarded envelope: %w", err)
	}
	wire, err := envelope.Encode(env)
	if err != nil {
		return nil, false, fmt.Errorf("delivery: encode forwarded envelope: %w", err)
	}
	if err := fs.conn.Send(ctx, wire); err != nil {
		return nil, true, fmt.Errorf("delivery: send forwarded envelope: %w", err)
	}
	respRaw, err := fs.conn.Recv(ctx)
	if err != nil {
		return nil, true, fmt.Errorf("delivery: recv federation submission response: %w", err)
	}
	return respRaw, false, nil
}

// getSession returns a cached federation session for peerDomain,
// opening one via the federation handshake if necessary. When a fresh
// session is opened, a background auto-rekey goroutine is spawned
// (unless disableAutoRekey is set) and cancelled when the session is
// dropped.
//
// The peer endpoint URL is obtained via EndpointResolver. The peer's
// domain signing key is expected to be discoverable through
// f.Store.LookupDomainKey by the time the federation Initiator runs;
// the Forwarder does not write into Store and does not fetch keys
// itself.
func (f *Forwarder) getSession(ctx context.Context, peerDomain string) (*forwarderSession, error) {
	if f.Dial == nil {
		return nil, errors.New("delivery: forwarder has no Dial")
	}
	if f.EndpointResolver == nil {
		return nil, errors.New("delivery: forwarder has no EndpointResolver")
	}
	if f.Store == nil {
		return nil, errors.New("delivery: forwarder has no Store")
	}

	var connectCh chan struct{}
	for {
		f.mu.Lock()
		if fs, ok := f.sessions[peerDomain]; ok && f.sessionActive(fs) {
			f.mu.Unlock()
			return fs, nil
		}
		if ch, ok := f.connecting[peerDomain]; ok {
			f.mu.Unlock()
			<-ch // wait for the in-flight connect to finish
			continue
		}
		connectCh = make(chan struct{})
		f.connecting[peerDomain] = connectCh
		f.mu.Unlock()
		break
	}
	defer func() {
		f.mu.Lock()
		delete(f.connecting, peerDomain)
		f.mu.Unlock()
		close(connectCh)
	}()

	endpoint, err := f.EndpointResolver(ctx, peerDomain)
	if err != nil {
		return nil, err
	}
	if endpoint == "" {
		return nil, fmt.Errorf("delivery: EndpointResolver returned empty URL for %s", peerDomain)
	}

	conn, err := f.Dial(ctx, endpoint)
	if err != nil {
		return nil, fmt.Errorf("delivery: dial peer %s: %w", endpoint, err)
	}
	initiator := handshake.NewInitiator(handshake.InitiatorConfig{
		Suite:                 f.Suite,
		Store:                 f.Store,
		LocalDomain:           f.LocalDomain,
		LocalDomainKeyID:      f.LocalDomainKeyID,
		LocalDomainPrivateKey: f.LocalDomainPrivateKey,
		PeerDomain:            peerDomain,
		DomainProof: handshake.DomainProof{
			Method: handshake.DomainVerifyTestTrust,
			Data:   f.LocalDomain,
		},
	})
	sess, err := handshake.RunInitiator(ctx, conn, initiator)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("delivery: federation handshake with %s: %w", peerDomain, err)
	}
	bgCtx, cancel := context.WithCancel(context.Background())
	newFS := &forwarderSession{
		conn:   conn,
		sess:   sess,
		cancel: cancel,
	}
	f.mu.Lock()
	f.sessions[peerDomain] = newFS
	f.mu.Unlock()

	if !f.disableAutoRekey {
		go f.autoRekey(bgCtx, peerDomain, newFS)
	}
	return newFS, nil
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
// and operator-visible diagnostics; callers must not mutate the
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
// rule (SESSION.md §3.1) in spirit; if rekey fails, the session is
// treated as dead.
func (f *Forwarder) autoRekey(ctx context.Context, peerDomain string, fs *forwarderSession) {
	for {
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
			f.dropSession(peerDomain)
			return
		}
		fs.wireMu.Unlock()
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
var nowFunc = time.Now

// FetchKeys forwards a SEMP_KEYS request over the cached federation
// session with peerDomain. It opens a fresh session if none is cached.
//
// Unlike Forward, FetchKeys does NOT touch any envelope; it simply
// marshals the request, writes it to the federation stream, and parses
// the response. The peer is expected to be a SEMP server running in
// federation mode that handles SEMP_KEYS on the federation path.
//
// The peer's response is returned verbatim; the caller is responsible
// for verifying any signatures on the enclosed key records.
func (f *Forwarder) FetchKeys(ctx context.Context, peerDomain string, req *keys.Request) (*keys.Response, error) {
	if req == nil {
		return nil, errors.New("delivery: nil SEMP_KEYS request")
	}
	fs, err := f.getSession(ctx, peerDomain)
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
		return nil, fmt.Errorf("delivery: parse SEMP_KEYS response: %w", err)
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
		return nil, false, fmt.Errorf("delivery: marshal SEMP_KEYS request: %w", err)
	}
	if err := fs.conn.Send(ctx, reqBytes); err != nil {
		return nil, true, fmt.Errorf("delivery: send SEMP_KEYS request: %w", err)
	}
	respRaw, err := fs.conn.Recv(ctx)
	if err != nil {
		return nil, true, fmt.Errorf("delivery: recv SEMP_KEYS response: %w", err)
	}
	return respRaw, false, nil
}
