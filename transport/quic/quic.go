// Package quic is the QUIC / HTTP/3 binding for the SEMP transport
// layer (TRANSPORT.md §4.3).
//
// Per §4.3.1 the QUIC binding "follows the same endpoint structure and
// message encoding as the HTTP/2 binding (section 4.2), carried over
// HTTP/3. All path routing, status code semantics, and session stream
// mechanisms are identical." This package therefore wraps the existing
// h2 package's persistent-handler machinery and simply swaps the
// underlying transport from TCP+HTTP/2 to UDP+QUIC+HTTP/3 via
// github.com/quic-go/quic-go/http3.
//
// # Dial
//
// Transport.Dial constructs an *http.Client whose Transport field is
// an *http3.Transport (QUIC-backed HTTP/3 round-tripper) and passes it
// into h2.Dial + h2.PersistentClient via the same Config mechanism
// already used by the h2 binding. The returned transport.Conn is
// identical to the h2 Conn — strictly turn-based, Send → Recv → Send.
//
// # Listen
//
// Transport.Listen starts an http3.Server backed by
// h2.NewPersistentHandler. Accept yields one transport.Conn per new
// Semp-Session-Id, exactly as the h2 binding does over TCP.
//
// # TLS
//
// TLS 1.3 is integral to QUIC (TRANSPORT.md §4.3: "Built-in TLS 1.3.
// Encryption is not optional or negotiable."). Unlike the h2 binding,
// there is no AllowInsecure escape hatch for the dial side — QUIC
// requires a valid TLS configuration. For tests, use
// Config.TLSConfig with InsecureSkipVerify (which allows self-signed
// certs but still runs TLS 1.3, unlike h2's AllowInsecure which drops
// to plain HTTP).
package quic

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/quic-go/quic-go/http3"

	"github.com/semp-dev/semp-go/transport"
	"github.com/semp-dev/semp-go/transport/h2"
)

// Config controls the behavior of the QUIC transport.
type Config struct {
	// TLSConfig is the TLS configuration for both client and server.
	// Required for Listen (the server must present a certificate);
	// optional for Dial (a nil config picks the default, which
	// requires valid certs — for tests, set InsecureSkipVerify).
	TLSConfig *tls.Config

	// H2Config is the underlying h2 configuration inherited by both
	// client and server. MaxBodyBytes, IdleTimeout, etc. are passed
	// through to the h2 persistent handler.
	H2Config h2.PersistentConfig

	// MaxBodyBytes caps the size of request and response bodies. Zero
	// picks h2.DefaultMaxBodyBytes (25 MiB).
	MaxBodyBytes int64
}

// Transport is the QUIC / HTTP/3 implementation of transport.Transport.
// It delegates all session management, message framing, and turn-based
// Conn semantics to the h2 package and only handles the QUIC-specific
// server and client setup.
type Transport struct {
	cfg Config
}

// New returns a fresh QUIC Transport with default configuration.
func New() *Transport { return &Transport{} }

// NewWithConfig returns a QUIC Transport configured per cfg.
func NewWithConfig(cfg Config) *Transport {
	return &Transport{cfg: cfg}
}

// ID returns transport.IDQUIC.
func (*Transport) ID() transport.ID { return transport.IDQUIC }

// Profiles reports that QUIC satisfies both synchronous and
// asynchronous profiles (TRANSPORT.md §4.3).
func (*Transport) Profiles() transport.Profile { return transport.ProfileBoth }

// Dial opens a turn-based transport.Conn to endpoint over HTTP/3.
// The endpoint MUST be an https:// URL — QUIC does not permit
// unencrypted connections. Dial does no network I/O; the first POST
// happens on the first Send.
//
// The returned Conn is strictly turn-based: Send → Recv → Send →
// Recv. This matches the SEMP handshake and inboxd request-response
// pattern.
func (t *Transport) Dial(ctx context.Context, endpoint string) (transport.Conn, error) {
	_ = ctx // Dial is non-blocking
	tlsCfg := t.cfg.TLSConfig
	if tlsCfg == nil {
		tlsCfg = &tls.Config{}
	}
	// Clone the TLS config so per-dial mutations don't affect other
	// dials. Set NextProtos to h3 if not already set.
	tlsCfg = tlsCfg.Clone()
	if len(tlsCfg.NextProtos) == 0 {
		tlsCfg.NextProtos = []string{http3.NextProtoH3}
	}
	h3Transport := &http3.Transport{
		TLSClientConfig: tlsCfg,
	}
	// Build an h2.Transport with the HTTP/3 client plugged in, then
	// delegate to its Dial which returns a turn-based transport.Conn.
	h2Cfg := t.cfg.H2Config
	h2Cfg.Config.AllowInsecure = true // the URL is https:// but we're using http3; h2.Dial only checks the scheme prefix
	h2Cfg.Config.HTTPClient = newHTTPClient(h3Transport)
	h2T := h2.NewWithConfig(h2Cfg)
	h2Conn, err := h2T.Dial(ctx, endpoint)
	if err != nil {
		return nil, fmt.Errorf("quic: dial: %w", err)
	}
	return newConn(h2Conn, endpoint, h3Transport), nil
}

// Listen starts an HTTP/3 server bound to addr and returns a
// transport.Listener whose Accept yields one transport.Conn per new
// session. The server uses the h2 persistent handler machinery
// (NewPersistentHandler) so session management is identical to the
// h2 binding.
//
// cfg.TLSConfig MUST be set and MUST contain at least one certificate.
// QUIC requires TLS 1.3 — there is no insecure mode.
func (t *Transport) Listen(ctx context.Context, addr string) (transport.Listener, error) {
	if t.cfg.TLSConfig == nil {
		return nil, errors.New("quic: TLSConfig is required for Listen (QUIC requires TLS 1.3)")
	}
	tlsCfg := t.cfg.TLSConfig.Clone()
	if len(tlsCfg.NextProtos) == 0 {
		tlsCfg.NextProtos = []string{http3.NextProtoH3}
	}

	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("quic: resolve UDP addr %s: %w", addr, err)
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, fmt.Errorf("quic: listen UDP %s: %w", addr, err)
	}

	l := &listener{
		udpConn: udpConn,
		queue:   make(chan transport.Conn, 32),
	}
	handler := h2.NewPersistentHandler(t.cfg.H2Config, func(c transport.Conn) {
		l.mu.Lock()
		closed := l.closed
		l.mu.Unlock()
		if closed {
			_ = c.Close()
			return
		}
		select {
		case l.queue <- c:
		case <-time.After(time.Second):
			_ = c.Close()
		}
	})
	srv := &http3.Server{
		TLSConfig: tlsCfg,
		Handler:   handler,
	}
	l.srv = srv
	go func() {
		_ = srv.Serve(udpConn)
	}()
	return l, nil
}

// -----------------------------------------------------------------------------
// Conn wrapper
// -----------------------------------------------------------------------------

// conn wraps the h2 persistent client Conn and adds a Close hook that
// shuts down the underlying HTTP/3 transport.
type conn struct {
	transport.Conn
	h3 *http3.Transport
}

func newConn(h2Conn transport.Conn, peer string, h3t *http3.Transport) *conn {
	return &conn{Conn: h2Conn, h3: h3t}
}

// Close tears down the h2 persistent conn and the underlying HTTP/3
// transport. The transport.Close() releases any cached QUIC
// connections.
func (c *conn) Close() error {
	err := c.Conn.Close()
	if c.h3 != nil {
		_ = c.h3.Close()
	}
	return err
}

// newHTTPClient returns a standard *http.Client whose Transport is
// the given http3.Transport, so every request goes over QUIC. h2.Dial
// uses this client via Config.HTTPClient.
func newHTTPClient(rt *http3.Transport) *http.Client {
	return &http.Client{Transport: rt}
}

// -----------------------------------------------------------------------------
// Listener
// -----------------------------------------------------------------------------

type listener struct {
	srv     *http3.Server
	udpConn *net.UDPConn

	mu     sync.Mutex
	queue  chan transport.Conn
	closed bool
}

func (l *listener) Accept(ctx context.Context) (transport.Conn, error) {
	select {
	case c, ok := <-l.queue:
		if !ok {
			return nil, errors.New("quic: listener closed")
		}
		return c, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

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
	if l.udpConn != nil {
		_ = l.udpConn.Close()
	}
	return nil
}

// Addr returns the local listen address. Useful in tests that bind
// to :0 for an ephemeral port.
func (l *listener) Addr() string {
	if l == nil || l.udpConn == nil {
		return ""
	}
	return l.udpConn.LocalAddr().String()
}
