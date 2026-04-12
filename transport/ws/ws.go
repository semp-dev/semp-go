// Package ws is the WebSocket binding for the SEMP transport layer.
//
// It implements the seven minimum transport requirements from TRANSPORT.md
// §2 on top of github.com/coder/websocket:
//
//   - Confidentiality:        TLS via wss:// (the operator is responsible
//                             for terminating TLS, typically with a reverse
//                             proxy or http.Server with TLSConfig).
//   - Server authentication:  TLS certificate verification by the standard
//                             library when wss:// is used.
//   - Reliable, ordered:      WebSocket guarantees both within a connection.
//   - Bidirectional:          Native to WebSocket.
//   - Message framing:        Native WebSocket frames.
//   - Variable-length payloads: Limited only by the configured read limit.
//   - Lifecycle signaling:    WebSocket close frames distinguish a clean
//                             disconnect from a network failure.
//
// SEMP messages travel as text frames per TRANSPORT.md §4.1.2.
package ws

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/coder/websocket"

	"semp.dev/semp-go/transport"
)

// Subprotocol is the WebSocket subprotocol identifier sent in the HTTP
// Upgrade request and confirmed by the server in its Upgrade response
// (TRANSPORT.md §4.1.1).
const Subprotocol = "semp.v1"

// PingInterval is the recommended keepalive ping interval for long-lived
// SEMP WebSocket sessions (TRANSPORT.md §4.1.3).
const PingInterval = 30 // seconds

// DefaultMaxMessageSize is the maximum SEMP message size in bytes accepted
// by the binding by default. This matches the discovery default of 25 MiB
// from DISCOVERY.md §3.1 (max_message_size).
const DefaultMaxMessageSize = 25 * 1024 * 1024

// Config controls the behavior of a Transport.
type Config struct {
	// AllowInsecure permits dialing plain ws:// URLs and listening without
	// requiring TLS at the binding level. This is for tests and local
	// development only — production deployments MUST set this to false
	// (the default), in which case Dial refuses ws:// URLs.
	AllowInsecure bool

	// MaxMessageSize is the maximum SEMP message size in bytes that the
	// binding will accept on read. Zero means use DefaultMaxMessageSize.
	MaxMessageSize int64

	// OriginPatterns is forwarded to websocket.AcceptOptions.OriginPatterns.
	// Used by the listener to authorize cross-origin upgrade requests.
	OriginPatterns []string
}

// Transport is the WebSocket implementation of transport.Transport.
type Transport struct {
	cfg Config
}

// New returns a fresh WebSocket Transport with default configuration
// (TLS required, 25 MiB message size limit).
func New() *Transport { return &Transport{} }

// NewWithConfig returns a Transport configured per cfg.
func NewWithConfig(cfg Config) *Transport {
	return &Transport{cfg: cfg}
}

// ID returns transport.IDWebSocket.
func (*Transport) ID() transport.ID { return transport.IDWebSocket }

// Profiles reports that WebSocket satisfies both synchronous and
// asynchronous profiles.
func (*Transport) Profiles() transport.Profile { return transport.ProfileBoth }

// Dial opens a WebSocket connection to endpoint and negotiates the
// `semp.v1` subprotocol. The endpoint MUST be a wss:// URL unless
// AllowInsecure is set in Config.
//
// The returned Conn is safe for concurrent Send and Recv calls — the
// underlying *websocket.Conn permits this — but callers SHOULD serialize
// Sends from a single goroutine to keep handshake message ordering
// predictable.
func (t *Transport) Dial(ctx context.Context, endpoint string) (transport.Conn, error) {
	if endpoint == "" {
		return nil, errors.New("ws: empty endpoint")
	}
	if !t.cfg.AllowInsecure && !strings.HasPrefix(endpoint, "wss://") {
		return nil, fmt.Errorf("ws: refusing to dial non-wss URL %q (set Config.AllowInsecure for local dev)", endpoint)
	}
	wc, _, err := websocket.Dial(ctx, endpoint, &websocket.DialOptions{
		Subprotocols: []string{Subprotocol},
	})
	if err != nil {
		return nil, fmt.Errorf("ws: dial %s: %w", endpoint, err)
	}
	if wc.Subprotocol() != Subprotocol {
		// Per TRANSPORT.md §4.1.1, if the server does not confirm
		// `semp.v1` the client MUST close the connection.
		_ = wc.Close(websocket.StatusPolicyViolation, "subprotocol not confirmed")
		return nil, fmt.Errorf("ws: server did not confirm %q subprotocol (got %q)", Subprotocol, wc.Subprotocol())
	}
	limit := t.cfg.MaxMessageSize
	if limit <= 0 {
		limit = DefaultMaxMessageSize
	}
	wc.SetReadLimit(limit)
	return &Conn{ws: wc, peer: endpoint}, nil
}

// Listen starts a WebSocket listener bound to addr (host:port). The
// returned Listener serves a single path, "/v1/ws", which upgrades to
// the SEMP WebSocket subprotocol.
//
// The returned Listener is plain HTTP. Operators that want TLS termination
// at the binding level should construct an *http.Server with TLSConfig
// around the Handler returned by NewHandler instead.
func (t *Transport) Listen(ctx context.Context, addr string) (transport.Listener, error) {
	netListener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("ws: listen on %s: %w", addr, err)
	}
	l := newListener(t.cfg)
	srv := &http.Server{
		Handler:     l.handler(),
		BaseContext: func(net.Listener) context.Context { return ctx },
	}
	l.srv = srv
	go func() {
		_ = srv.Serve(netListener)
	}()
	l.localAddr = netListener.Addr().String()
	return l, nil
}

// NewHandler returns an http.Handler that upgrades inbound HTTP requests
// to SEMP WebSocket connections. Each accepted connection is delivered to
// the supplied accept function, which is invoked in its own goroutine.
//
// This is the entry point operators use to mount SEMP on an existing
// *http.Server or HTTP routing tree.
func NewHandler(cfg Config, accept func(transport.Conn)) http.Handler {
	limit := cfg.MaxMessageSize
	if limit <= 0 {
		limit = DefaultMaxMessageSize
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wc, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			Subprotocols:   []string{Subprotocol},
			OriginPatterns: cfg.OriginPatterns,
		})
		if err != nil {
			// Accept already wrote an HTTP error response.
			return
		}
		if wc.Subprotocol() != Subprotocol {
			_ = wc.Close(websocket.StatusPolicyViolation, "subprotocol not confirmed")
			return
		}
		wc.SetReadLimit(limit)
		c := &Conn{
			ws:   wc,
			peer: r.RemoteAddr,
		}
		accept(c)
	})
}

// Conn is a single SEMP message stream over a WebSocket.
type Conn struct {
	ws   *websocket.Conn
	peer string

	closeOnce sync.Once
}

// Send transmits one SEMP message as a single WebSocket text frame
// (TRANSPORT.md §4.1.2).
func (c *Conn) Send(ctx context.Context, msg []byte) error {
	if c == nil || c.ws == nil {
		return errors.New("ws: nil connection")
	}
	if err := c.ws.Write(ctx, websocket.MessageText, msg); err != nil {
		return fmt.Errorf("ws: send: %w", err)
	}
	return nil
}

// Recv blocks until the next complete SEMP message is available, then
// returns its bytes. Binary frames are rejected per TRANSPORT.md §4.1.2.
func (c *Conn) Recv(ctx context.Context) ([]byte, error) {
	if c == nil || c.ws == nil {
		return nil, errors.New("ws: nil connection")
	}
	mt, data, err := c.ws.Read(ctx)
	if err != nil {
		return nil, fmt.Errorf("ws: recv: %w", err)
	}
	if mt != websocket.MessageText {
		return nil, fmt.Errorf("ws: unexpected message type %v (SEMP requires text frames)", mt)
	}
	return data, nil
}

// Close sends a clean close frame and tears down the underlying connection.
func (c *Conn) Close() error {
	if c == nil || c.ws == nil {
		return nil
	}
	var err error
	c.closeOnce.Do(func() {
		err = c.ws.Close(websocket.StatusNormalClosure, "")
	})
	return err
}

// Peer returns a human-readable identifier for the remote endpoint.
func (c *Conn) Peer() string {
	if c == nil {
		return ""
	}
	return c.peer
}

// listener is the transport.Listener implementation returned by Transport.Listen.
type listener struct {
	cfg       Config
	srv       *http.Server
	localAddr string
	mu        sync.Mutex
	queue     chan transport.Conn
	closed    bool
}

func newListener(cfg Config) *listener {
	return &listener{
		cfg:   cfg,
		queue: make(chan transport.Conn, 32),
	}
}

func (l *listener) handler() http.Handler {
	return NewHandler(l.cfg, func(c transport.Conn) {
		l.mu.Lock()
		closed := l.closed
		l.mu.Unlock()
		if closed {
			_ = c.Close()
			return
		}
		select {
		case l.queue <- c:
		default:
			// Queue full — drop the connection rather than block the
			// HTTP handler indefinitely.
			_ = c.Close()
		}
	})
}

// Accept blocks until the next inbound connection arrives.
func (l *listener) Accept(ctx context.Context) (transport.Conn, error) {
	select {
	case c, ok := <-l.queue:
		if !ok {
			return nil, errors.New("ws: listener closed")
		}
		return c, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Close stops the listener. Already-accepted connections continue to
// function until their callers close them.
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
		return l.srv.Close()
	}
	return nil
}

// Addr returns the local listen address as a host:port string. Useful in
// tests where the operator passes addr=":0" to bind to an ephemeral port.
func (l *listener) Addr() string {
	if l == nil {
		return ""
	}
	return l.localAddr
}
