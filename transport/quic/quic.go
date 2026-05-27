// Package quic is the client-side QUIC / HTTP/3 binding for the
// SEMP transport layer (TRANSPORT.md §4.3).
//
// Per §4.3.1 the QUIC binding "follows the same endpoint structure
// and message encoding as the HTTP/2 binding (section 4.2), carried
// over HTTP/3." This package wraps the h2 client primitives and
// swaps the underlying round-tripper from TCP+HTTP/2 to
// UDP+QUIC+HTTP/3 via github.com/quic-go/quic-go/http3.
//
// # Dial
//
// Transport.Dial constructs an *http.Client whose Transport field is
// an *http3.Transport (QUIC-backed HTTP/3 round-tripper) and passes
// it into h2.Dial. The returned transport.Conn is identical to the
// h2 Conn - strictly turn-based, Send -> Recv -> Send.
//
// # TLS
//
// TLS 1.3 is integral to QUIC (TRANSPORT.md §4.3: "Built-in TLS 1.3.
// Encryption is not optional or negotiable."). For tests, use
// Config.TLSConfig with InsecureSkipVerify (which allows self-signed
// certs but still runs TLS 1.3).
//
// Server-side wiring is application-layer and lives outside this
// package.
package quic

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/quic-go/quic-go/http3"

	"github.com/semp-dev/semp-go/transport"
	"github.com/semp-dev/semp-go/transport/h2"
)

// Config controls the behavior of the QUIC transport.
type Config struct {
	// TLSConfig is the TLS configuration for the QUIC client. A nil
	// config picks the default, which requires valid certificates;
	// tests targeting a self-signed local server set
	// InsecureSkipVerify here.
	TLSConfig *tls.Config

	// H2Config is the underlying h2 configuration inherited by the
	// QUIC client. Carries TLS, dial timeout, and request-body bounds.
	H2Config h2.Config

	// MaxBodyBytes caps the size of response bodies. Zero picks
	// h2.DefaultMaxBodyBytes (25 MiB).
	MaxBodyBytes int64
}

// Transport is the QUIC / HTTP/3 client implementation of
// transport.Transport. It delegates all session management, message
// framing, and turn-based Conn semantics to the h2 package and only
// handles the QUIC-specific client setup.
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
// The endpoint MUST be an https:// URL; QUIC does not permit
// unencrypted connections. Dial does no network I/O; the first POST
// happens on the first Send.
//
// The returned Conn is strictly turn-based: Send -> Recv -> Send ->
// Recv. This matches the SEMP handshake and request-response
// pattern.
func (t *Transport) Dial(ctx context.Context, endpoint string) (transport.Conn, error) {
	_ = ctx // Dial is non-blocking
	if endpoint == "" {
		return nil, errors.New("quic: empty endpoint")
	}
	if !strings.HasPrefix(endpoint, "https://") {
		return nil, fmt.Errorf("quic: refusing to dial non-https URL %q (QUIC requires TLS)", endpoint)
	}
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
	// We force h2's AllowInsecure here because QUIC's own scheme check
	// above already enforced https://; h2.Dial would otherwise re-check
	// the same scheme without knowing it's about to be carried over
	// HTTP/3.
	h2Cfg := t.cfg.H2Config
	h2Cfg.AllowInsecure = true
	h2Cfg.HTTPClient = newHTTPClient(h3Transport)
	h2T := h2.NewWithConfig(h2Cfg)
	h2Conn, err := h2T.Dial(ctx, endpoint)
	if err != nil {
		return nil, fmt.Errorf("quic: dial: %w", err)
	}
	return newConn(h2Conn, endpoint, h3Transport), nil
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
	_ = peer
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
