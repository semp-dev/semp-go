package h2

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"semp.dev/semp-go/transport"
)

// DefaultIdleTimeout is the default duration after which a server-side
// persistent session is closed if no POST arrives. A fresh value fires
// on every new POST carrying the session's Semp-Session-Id header.
const DefaultIdleTimeout = 60 * time.Second

// -----------------------------------------------------------------------------
// Client-side transport.Conn
// -----------------------------------------------------------------------------

// persistentClient adapts an *h2.Client to transport.Conn by interleaving
// Send and Recv calls into POST round trips. Each Send issues one POST and
// stores the response body; the next Recv returns that stored body.
//
// The adapter is turn-based: callers MUST follow the pattern
//
//	Send → Recv → Send → Recv → …
//
// which is exactly what the SEMP handshake and inboxd request-response
// flows do. This matches the HTTP/2 binding in TRANSPORT.md §4.2.3 where
// every client message is one POST and every server message is the
// corresponding POST response body, correlated across calls by the
// Semp-Session-Id header that h2.Client threads automatically.
//
// persistentClient is NOT safe for concurrent Send/Recv — the underlying
// *h2.Client is single-threaded and the turn buffer is a one-element slot.
type persistentClient struct {
	client *Client
	peer   string

	// pendingMu guards pending. Only one response is ever buffered at a
	// time because the contract is strict Send → Recv alternation.
	pendingMu sync.Mutex
	pending   []byte
	hasPending bool

	closeOnce sync.Once
	closed    chan struct{}
}

func newPersistentClient(cli *Client, peer string) *persistentClient {
	return &persistentClient{
		client: cli,
		peer:   peer,
		closed: make(chan struct{}),
	}
}

// Send POSTs msg to the remote endpoint and buffers the response body for
// the next Recv call. Returns an error if a previous response has not yet
// been consumed by Recv, or if the underlying POST fails.
func (pc *persistentClient) Send(ctx context.Context, msg []byte) error {
	if pc == nil || pc.client == nil {
		return errors.New("h2: nil persistent client")
	}
	select {
	case <-pc.closed:
		return errors.New("h2: persistent client closed")
	default:
	}

	pc.pendingMu.Lock()
	if pc.hasPending {
		pc.pendingMu.Unlock()
		return errors.New("h2: Send called before previous Recv — persistent client is turn-based")
	}
	pc.pendingMu.Unlock()

	resp, err := pc.client.Do(ctx, msg)
	if err != nil {
		return err
	}

	pc.pendingMu.Lock()
	pc.pending = resp
	pc.hasPending = true
	pc.pendingMu.Unlock()
	return nil
}

// Recv returns the response body buffered by the most recent Send. It
// blocks briefly only to observe Close; actual network I/O happened
// during Send.
func (pc *persistentClient) Recv(ctx context.Context) ([]byte, error) {
	if pc == nil {
		return nil, errors.New("h2: nil persistent client")
	}
	select {
	case <-pc.closed:
		return nil, io.EOF
	default:
	}

	pc.pendingMu.Lock()
	defer pc.pendingMu.Unlock()
	if !pc.hasPending {
		return nil, errors.New("h2: Recv called without a buffered response — call Send first")
	}
	body := pc.pending
	pc.pending = nil
	pc.hasPending = false
	return body, nil
}

// Close marks the client as closed; subsequent Send or Recv calls return
// errors. The underlying *http.Client is shared with the embedded
// h2.Client and is not torn down — callers that want to release the HTTP
// transport should do so themselves.
func (pc *persistentClient) Close() error {
	if pc == nil {
		return nil
	}
	pc.closeOnce.Do(func() { close(pc.closed) })
	return nil
}

// Peer returns the remote endpoint URL.
func (pc *persistentClient) Peer() string {
	if pc == nil {
		return ""
	}
	return pc.peer
}

// SessionID exposes the Semp-Session-Id the underlying h2.Client captured
// from the most recent response. Primarily useful for diagnostics.
func (pc *persistentClient) SessionID() string {
	if pc == nil || pc.client == nil {
		return ""
	}
	return pc.client.SessionID()
}

// -----------------------------------------------------------------------------
// Server-side virtualConn + session registry
// -----------------------------------------------------------------------------

// turn is one client-POST-driven exchange: the HTTP handler pushes the
// request body and waits on replyCh for the accept callback to populate
// a response.
type turn struct {
	req     []byte
	replyCh chan turnReply
}

// turnReply is what the accept goroutine hands back to the HTTP handler
// via turn.replyCh. Exactly one of body or err is populated.
type turnReply struct {
	body []byte
	err  error
}

// virtualConn is the server-side transport.Conn that sits behind a
// sequence of HTTP/2 POSTs sharing one Semp-Session-Id. From the accept
// callback's perspective it looks like a plain bidirectional message
// stream; under the hood each Recv pops a turn submitted by a POST
// handler and each Send hands the reply back to that handler.
//
// virtualConn is strictly turn-based: accept MUST alternate
// Recv → Send → Recv → Send. Two Recvs in a row abandon the first turn
// and return an error to its HTTP handler.
type virtualConn struct {
	sessionID string
	peer      string

	// turns is the inbound queue of (req, replyCh) pairs pushed by the
	// HTTP handler. Buffered 1 so a single pending turn can sit waiting
	// for the accept callback to pick it up.
	turns chan *turn

	// pending holds the turn whose reply we still owe. Guarded by
	// pendingMu.
	pendingMu sync.Mutex
	pending   *turn

	closeOnce sync.Once
	closed    chan struct{}

	// Idle reaper.
	idleTimeout time.Duration
	idleTimer   *time.Timer
	idleMu      sync.Mutex

	// onClose runs once inside Close(), after vc.closed has been
	// closed. NewPersistentHandler uses this to remove the session
	// from the shared registry without needing a separate goroutine.
	onClose func()
}

func newVirtualConn(sessionID, peer string, idleTimeout time.Duration) *virtualConn {
	vc := &virtualConn{
		sessionID:   sessionID,
		peer:        peer,
		turns:       make(chan *turn, 1),
		closed:      make(chan struct{}),
		idleTimeout: idleTimeout,
	}
	if idleTimeout > 0 {
		vc.idleTimer = time.AfterFunc(idleTimeout, func() { _ = vc.Close() })
	}
	return vc
}

// touch resets the idle timer in response to any POST activity.
func (vc *virtualConn) touch() {
	if vc == nil || vc.idleTimer == nil {
		return
	}
	vc.idleMu.Lock()
	defer vc.idleMu.Unlock()
	vc.idleTimer.Reset(vc.idleTimeout)
}

// Send hands msg to the HTTP handler that is currently waiting for a
// reply on the pending turn. Returns an error if there is no pending
// turn (i.e. Send was called before Recv) or if the conn is closed.
func (vc *virtualConn) Send(ctx context.Context, msg []byte) error {
	if vc == nil {
		return errors.New("h2: nil virtual conn")
	}
	select {
	case <-vc.closed:
		return errors.New("h2: virtual conn closed")
	default:
	}
	vc.pendingMu.Lock()
	t := vc.pending
	vc.pending = nil
	vc.pendingMu.Unlock()
	if t == nil {
		return errors.New("h2: Send called without a pending POST")
	}
	// replyCh is buffered 1, so this never blocks against a well-behaved
	// handler. Guard against a Close race anyway.
	select {
	case t.replyCh <- turnReply{body: msg}:
		return nil
	case <-vc.closed:
		return errors.New("h2: virtual conn closed")
	case <-ctx.Done():
		// Still return the reply so the HTTP handler doesn't hang.
		select {
		case t.replyCh <- turnReply{err: ctx.Err()}:
		default:
		}
		return ctx.Err()
	}
}

// Recv blocks until a new POST arrives for this session, then returns
// its request body. If the previous turn's reply was never sent, it is
// abandoned with an error so its HTTP handler returns 500 rather than
// hanging.
func (vc *virtualConn) Recv(ctx context.Context) ([]byte, error) {
	if vc == nil {
		return nil, errors.New("h2: nil virtual conn")
	}
	// If a previous turn is still pending, the accept callback is
	// effectively skipping its reply. Surface an error to the stranded
	// HTTP handler so it doesn't block forever.
	vc.pendingMu.Lock()
	if prev := vc.pending; prev != nil {
		select {
		case prev.replyCh <- turnReply{err: errors.New("h2: accept callback abandoned previous turn")}:
		default:
		}
		vc.pending = nil
	}
	vc.pendingMu.Unlock()

	select {
	case t, ok := <-vc.turns:
		if !ok {
			return nil, io.EOF
		}
		vc.pendingMu.Lock()
		vc.pending = t
		vc.pendingMu.Unlock()
		return t.req, nil
	case <-vc.closed:
		return nil, io.EOF
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Close tears down the virtual conn. Any goroutine blocked in Recv sees
// io.EOF on its next return. Any HTTP handler currently waiting on a
// pending turn's reply gets a "closed" error via the reply channel.
// The onClose hook runs at most once after the close fires.
func (vc *virtualConn) Close() error {
	if vc == nil {
		return nil
	}
	vc.closeOnce.Do(func() {
		close(vc.closed)
		if vc.idleTimer != nil {
			vc.idleTimer.Stop()
		}
		// Drain any pending turn with an error so its HTTP handler
		// doesn't hang on replyCh.
		vc.pendingMu.Lock()
		if prev := vc.pending; prev != nil {
			select {
			case prev.replyCh <- turnReply{err: errors.New("h2: virtual conn closed")}:
			default:
			}
			vc.pending = nil
		}
		vc.pendingMu.Unlock()
		if vc.onClose != nil {
			vc.onClose()
		}
	})
	return nil
}

// Peer returns a human-readable identifier for the remote. For
// persistent handler conns this is the HTTP client's RemoteAddr.
func (vc *virtualConn) Peer() string {
	if vc == nil {
		return ""
	}
	return vc.peer
}

// SessionID exposes the Semp-Session-Id string assigned to this conn.
func (vc *virtualConn) SessionID() string {
	if vc == nil {
		return ""
	}
	return vc.sessionID
}

// sessionRegistry is a tiny concurrent map from session id to virtualConn.
// Used by NewPersistentHandler to route subsequent POSTs to the same
// virtual conn as the initial POST that created the session.
type sessionRegistry struct {
	mu       sync.Mutex
	sessions map[string]*virtualConn
}

func newSessionRegistry() *sessionRegistry {
	return &sessionRegistry{sessions: map[string]*virtualConn{}}
}

func (r *sessionRegistry) put(sid string, vc *virtualConn) {
	r.mu.Lock()
	r.sessions[sid] = vc
	r.mu.Unlock()
}

func (r *sessionRegistry) get(sid string) *virtualConn {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.sessions[sid]
}

func (r *sessionRegistry) remove(sid string) {
	r.mu.Lock()
	delete(r.sessions, sid)
	r.mu.Unlock()
}

func (r *sessionRegistry) len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.sessions)
}

// -----------------------------------------------------------------------------
// NewPersistentHandler
// -----------------------------------------------------------------------------

// PersistentConfig extends Config with the idle timeout for server-side
// virtual conns. It is accepted by NewPersistentHandler and by
// Transport.Listen (via NewWithConfig).
type PersistentConfig struct {
	Config

	// IdleTimeout is how long a session may go without any client POST
	// before the server-side virtualConn is closed. Zero means
	// DefaultIdleTimeout. Negative disables the reaper entirely (not
	// recommended in production).
	IdleTimeout time.Duration
}

// NewPersistentHandler returns an http.Handler that maintains per-session
// virtual transport.Conns keyed by the Semp-Session-Id header. It closes
// the gap between HTTP/2's per-request model and the symmetric
// transport.Conn model used by handshake and inboxd.
//
// Lifecycle per session:
//
//  1. A POST with no Semp-Session-Id creates a new session: a virtual
//     conn is allocated, registered under a freshly generated session
//     id, and handed to the accept callback in a new goroutine.
//  2. The same POST's body is pushed onto the virtual conn's turn queue
//     as the first Recv, and the HTTP handler blocks waiting for the
//     accept callback to Send its reply.
//  3. Subsequent POSTs with a matching Semp-Session-Id repeat step 2,
//     routing the body to the existing virtual conn.
//  4. When the accept callback returns, or when the idle timer fires,
//     or when Close is called, the virtual conn is closed and removed
//     from the session registry.
//
// NewPersistentHandler does not perform path routing. Mount it at
// PathHandshake, PathEnvelope, or a single shared path depending on
// whether the consumer wants one handler per endpoint or one shared
// endpoint that the accept callback demultiplexes.
//
// The accept callback runs in its own goroutine. It MUST follow strict
// Recv → Send alternation (which both handshake.RunServer and
// inboxd.Server.Serve already do).
func NewPersistentHandler(cfg PersistentConfig, accept func(transport.Conn)) http.Handler {
	maxBody := cfg.MaxBodyBytes
	if maxBody <= 0 {
		maxBody = DefaultMaxBodyBytes
	}
	idleTimeout := cfg.IdleTimeout
	if idleTimeout == 0 {
		idleTimeout = DefaultIdleTimeout
	}
	reg := newSessionRegistry()

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if r.ContentLength > maxBody {
			http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
		if err != nil {
			http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
			return
		}
		if int64(len(body)) > maxBody {
			http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
			return
		}

		sid := r.Header.Get(HeaderSessionID)
		var vc *virtualConn
		if sid == "" {
			// New session.
			newSID, err := newSessionID()
			if err != nil {
				http.Error(w, "session id: "+err.Error(), http.StatusInternalServerError)
				return
			}
			sid = newSID
			vc = newVirtualConn(sid, r.RemoteAddr, idleTimeout)
			// Wire registry cleanup into the conn's close path so
			// the session lifetime is owned by whoever closes the
			// conn — the accept callback itself, a downstream
			// consumer (when accept just hands off via a queue), or
			// the idle reaper.
			localSID := sid
			vc.onClose = func() { reg.remove(localSID) }
			reg.put(sid, vc)
			// Run the accept callback in its own goroutine. For
			// direct consumers the callback loops Recv/Send for the
			// lifetime of the session; for transport.Listener
			// adapters it just queues the conn and returns. In
			// either case we do NOT close vc on return — a queued
			// conn is still in active use.
			go accept(vc)
		} else {
			vc = reg.get(sid)
			if vc == nil {
				http.Error(w, "unknown session", http.StatusNotFound)
				return
			}
		}
		vc.touch()

		// Post a turn and wait for the reply.
		t := &turn{req: body, replyCh: make(chan turnReply, 1)}
		select {
		case vc.turns <- t:
		case <-vc.closed:
			http.Error(w, "session closed", http.StatusGone)
			return
		case <-r.Context().Done():
			return
		}

		select {
		case rep := <-t.replyCh:
			if rep.err != nil {
				http.Error(w, rep.err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", ContentType)
			w.Header().Set(HeaderSessionID, sid)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(rep.body)
		case <-vc.closed:
			http.Error(w, "session closed", http.StatusGone)
			return
		case <-r.Context().Done():
			return
		}
	})
}

// -----------------------------------------------------------------------------
// transport.Listener wiring
// -----------------------------------------------------------------------------

// listener is the transport.Listener implementation returned by
// Transport.Listen. Each new session (first POST without a
// Semp-Session-Id header) becomes a transport.Conn queued for Accept.
type listener struct {
	cfg         PersistentConfig
	srv         *http.Server
	netListener net.Listener

	mu     sync.Mutex
	queue  chan transport.Conn
	closed bool
}

// Accept blocks until a new session's virtual conn is available.
func (l *listener) Accept(ctx context.Context) (transport.Conn, error) {
	select {
	case c, ok := <-l.queue:
		if !ok {
			return nil, errors.New("h2: listener closed")
		}
		return c, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Close stops the underlying http.Server and drains the Accept queue.
// Already-accepted virtual conns continue to operate until their
// callers close them or their idle timers fire.
func (l *listener) Close() error {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil
	}
	l.closed = true
	l.mu.Unlock()
	close(l.queue)
	if l.srv != nil {
		_ = l.srv.Close()
	}
	if l.netListener != nil {
		_ = l.netListener.Close()
	}
	return nil
}

// Addr returns the local listen address. Useful in tests that bind to
// :0 for an ephemeral port.
func (l *listener) Addr() string {
	if l == nil || l.netListener == nil {
		return ""
	}
	return l.netListener.Addr().String()
}

// -----------------------------------------------------------------------------
// Session id generation
// -----------------------------------------------------------------------------

// crockfordAlphabet is the Crockford base32 alphabet used by ULIDs. We
// don't need bit-for-bit ULID compliance here, just a collision-free
// 26-character identifier.
const crockfordAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

var crockfordEncoding = base32.NewEncoding(crockfordAlphabet).WithPadding(base32.NoPadding)

// newSessionID returns a ULID-shaped 26-character session identifier
// with a 48-bit millisecond timestamp prefix and 80 bits of randomness.
// Inlined rather than importing handshake to preserve package layering
// (handshake imports transport bindings, not the other way round).
func newSessionID() (string, error) {
	var raw [16]byte
	now := uint64(time.Now().UnixMilli())
	binary.BigEndian.PutUint64(raw[:8], now<<16)
	if _, err := rand.Read(raw[6:]); err != nil {
		return "", fmt.Errorf("h2: session id randomness: %w", err)
	}
	enc := crockfordEncoding.EncodeToString(raw[:])
	if len(enc) > 26 {
		enc = enc[:26]
	}
	return enc, nil
}

