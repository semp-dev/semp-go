// Package ws is the client-side WebSocket binding for the SEMP
// transport layer (TRANSPORT.md §4.1).
//
// It implements the seven minimum transport requirements from
// TRANSPORT.md §2 on top of github.com/coder/websocket:
//
//   - Confidentiality:        TLS via wss:// (the operator is
//                             responsible for terminating TLS).
//   - Server authentication:  TLS certificate verification by the
//                             standard library when wss:// is used.
//   - Reliable, ordered:      WebSocket guarantees both within a
//                             connection.
//   - Bidirectional:          Native to WebSocket.
//   - Message framing:        Native WebSocket frames.
//   - Variable-length payloads: Limited only by the configured read
//                             limit.
//   - Lifecycle signaling:    WebSocket close frames distinguish a
//                             clean disconnect from a network failure.
//
// SEMP messages travel as text frames per TRANSPORT.md §4.1.2.
//
// Server-side accept loops (HTTP listener mount, upgrade-request
// authorization, per-connection goroutine spawn) are application-layer
// and live outside this package.
package ws

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/coder/websocket"

	"github.com/semp-dev/semp-go/transport"
)

// Subprotocol is the WebSocket subprotocol identifier sent in the HTTP
// Upgrade request and confirmed by the server in its Upgrade response
// (TRANSPORT.md §4.1.1).
const Subprotocol = "semp.v1"

// PingInterval is the recommended keepalive ping interval for long-lived
// SEMP WebSocket sessions (TRANSPORT.md §4.1.3).
const PingInterval = 30 // seconds

// DefaultMaxEnvelopeSize is the maximum SEMP message size in bytes accepted
// by the binding by default. This matches the discovery default of 25 MiB
// from DISCOVERY.md §3.1 (max_envelope_size).
const DefaultMaxEnvelopeSize = 25 * 1024 * 1024

// Config controls the behavior of a Transport.
type Config struct {
	// AllowInsecure permits dialing plain ws:// URLs. This is for
	// tests and local development only. Production deployments MUST
	// leave this false (the default), in which case Dial refuses
	// ws:// URLs.
	AllowInsecure bool

	// MaxEnvelopeSize is the maximum SEMP message size in bytes that
	// Recv will accept on read. Zero means use DefaultMaxEnvelopeSize.
	MaxEnvelopeSize int64
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
// The returned Conn is safe for concurrent Send and Recv calls - the
// underlying *websocket.Conn permits this - but callers SHOULD serialize
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
	limit := t.cfg.MaxEnvelopeSize
	if limit <= 0 {
		limit = DefaultMaxEnvelopeSize
	}
	wc.SetReadLimit(limit)
	return &Conn{ws: wc, peer: endpoint}, nil
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

