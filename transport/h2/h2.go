// Package h2 is the client-side HTTP/2 binding for the SEMP
// transport layer (TRANSPORT.md §4.2).
//
// # Scope
//
// This package provides protocol-pure HTTP/2 client primitives:
//
//   - Client / Dial: a per-session helper that POSTs SEMP messages
//     to a server endpoint and threads the Semp-Session-Id header
//     across the request sequence.
//   - Transport.Dial: returns a transport.Conn that POSTs on Send
//     and returns the response body on Recv. Strictly turn-based
//     (Send -> Recv -> Send -> Recv), matching the SEMP handshake and
//     request-response flows.
//   - EncodeEvent / EventReader: SSE encoder + decoder for the
//     long-lived /v1/session/{id} channel (TRANSPORT.md §4.2.4),
//     server->client push direction.
//   - OpenSessionStream / SessionStreamConn: the client side of
//     the long-lived POST, decoding pushed events and exposing
//     Recv / Close.
//
// Server-side wiring (HTTP listener mount, session demux, fan-out
// registry) is application-layer and lives outside this package.
// Consumers compose Client + Transport.Dial + the SSE primitives
// into whatever HTTP server framework they use.
package h2

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/semp-dev/semp-go/transport"
)

// Path constants for the HTTP/2 binding per TRANSPORT.md §4.2.1.
//
// Discovery and keys are read-only lookups that SHOULD be issued
// as GET requests carrying the address in the path:
//
//   GET /v1/discovery/{address}
//   GET /v1/keys/{address}
//
// Servers MUST also accept POST on the same paths so callers that
// need to send a signed request body can use them. The bare
// PathDiscovery and PathKeys constants are the path prefixes used
// to build the per-address URL via DiscoveryPath and KeysPath.
//
// State-changing operations are POST-only:
//
//   POST /v1/handshake
//   POST /v1/envelope
//
// Long-lived server-initiated streams use GET:
//
//   GET /v1/session/{id}
const (
	PathDiscovery = "/v1/discovery"
	PathKeys      = "/v1/keys"
	PathHandshake = "/v1/handshake"
	PathEnvelope  = "/v1/envelope"
	PathSession   = "/v1/session/" // append session id
)

// DiscoveryPath returns the GET-lookup URL path for address per
// TRANSPORT.md §4.2.1: "/v1/discovery/{address}".
func DiscoveryPath(address string) string {
	return PathDiscovery + "/" + address
}

// KeysPath returns the GET-lookup URL path for address per
// TRANSPORT.md §4.2.1: "/v1/keys/{address}".
func KeysPath(address string) string {
	return PathKeys + "/" + address
}

// SessionPath returns the GET-stream URL path for a session id per
// TRANSPORT.md §4.2.4: "/v1/session/{id}".
func SessionPath(sessionID string) string {
	return PathSession + sessionID
}

// HeaderSessionID is the response header that the server uses to
// correlate subsequent handshake POSTs with the in-progress handshake
// (TRANSPORT.md §4.2.3).
const HeaderSessionID = "Semp-Session-Id"

// ContentType is the JSON content type used for all SEMP HTTP/2
// bodies (TRANSPORT.md §4.2.1 - "All request and response bodies are
// application/json; charset=utf-8").
const ContentType = "application/json; charset=utf-8"

// DefaultTimeout is the default request timeout the Client applies to
// each Do call when the context has no deadline.
const DefaultTimeout = 30 * time.Second

// DefaultMaxBodyBytes is the maximum response body size the Client
// will read from an HTTP/2 response. 25 MiB matches the
// DISCOVERY.md §3.1 default max_envelope_size and keeps a hostile
// peer from tricking the reader into unbounded allocation.
const DefaultMaxBodyBytes int64 = 25 * 1024 * 1024

// Config controls the behavior of Client.
type Config struct {
	// AllowInsecure permits dialing plain http:// URLs. Production
	// deployments MUST leave this false (the default). Per
	// TRANSPORT.md §4.2, HTTPS is the only permitted scheme; tests
	// and local dev use this flag to opt out of the check.
	AllowInsecure bool

	// HTTPClient is the underlying *http.Client. Zero means
	// "use a fresh client with DefaultTimeout".
	HTTPClient *http.Client

	// MaxBodyBytes caps the size of response bodies the Client
	// reads. Zero means DefaultMaxBodyBytes.
	MaxBodyBytes int64
}

// Client is the client-side HTTP/2 primitive. One Client corresponds
// to one logical SEMP session against one endpoint URL. Client.Do
// makes one POST per call and threads the Semp-Session-Id header
// across successive calls, so a multi-message handshake (init ->
// response -> confirm -> accepted per TRANSPORT.md §4.2.3) maps to a
// sequence of Do calls on the same Client.
//
// Client is NOT safe for concurrent Do calls. Callers that want to
// multiplex multiple logical sessions over one HTTP client should
// construct one Client per session.
type Client struct {
	endpoint  string
	httpC     *http.Client
	sessionID string
	maxBody   int64
}

// Dial constructs a new Client targeting endpoint. The endpoint MUST
// be an https:// URL unless cfg.AllowInsecure is true.
//
// Dial does not perform any network I/O - the first actual HTTP
// request happens on the first Do call.
func Dial(cfg Config, endpoint string) (*Client, error) {
	if endpoint == "" {
		return nil, errors.New("h2: empty endpoint")
	}
	if !cfg.AllowInsecure && !strings.HasPrefix(endpoint, "https://") {
		return nil, fmt.Errorf("h2: refusing to dial non-https URL %q (set Config.AllowInsecure for local dev)", endpoint)
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: DefaultTimeout}
	}
	maxBody := cfg.MaxBodyBytes
	if maxBody <= 0 {
		maxBody = DefaultMaxBodyBytes
	}
	return &Client{
		endpoint: endpoint,
		httpC:    client,
		maxBody:  maxBody,
	}, nil
}

// Do makes one POST to the client's endpoint with msg as the request
// body and returns the response body. On the first call Semp-Session-Id
// is not included; if the server responds with the header set, the
// value is remembered and included on subsequent calls.
//
// An HTTP status code outside [200, 300) is treated as a transport
// error. The response body of a 200 response is returned as-is,
// regardless of its SEMP-level content - SEMP rejections with a
// reason_code come back as normal 200 responses and the caller is
// expected to parse the body.
func (c *Client) Do(ctx context.Context, msg []byte) ([]byte, error) {
	if c == nil {
		return nil, errors.New("h2: nil client")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(msg))
	if err != nil {
		return nil, fmt.Errorf("h2: build request: %w", err)
	}
	req.Header.Set("Content-Type", ContentType)
	req.Header.Set("Accept", ContentType)
	if c.sessionID != "" {
		req.Header.Set(HeaderSessionID, c.sessionID)
	}
	resp, err := c.httpC.Do(req)
	if err != nil {
		return nil, fmt.Errorf("h2: POST %s: %w", c.endpoint, err)
	}
	defer resp.Body.Close()

	// Capture the session id BEFORE checking status so a 4xx
	// response that still carries a session id (e.g. a structured
	// rejection) doesn't strand the client.
	if sid := resp.Header.Get(HeaderSessionID); sid != "" {
		c.sessionID = sid
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, c.maxBody))
		return nil, fmt.Errorf("h2: POST %s returned %d: %s", c.endpoint, resp.StatusCode, string(body))
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, c.maxBody+1))
	if err != nil {
		return nil, fmt.Errorf("h2: read response body: %w", err)
	}
	if int64(len(body)) > c.maxBody {
		return nil, fmt.Errorf("h2: response body exceeds %d bytes", c.maxBody)
	}
	return body, nil
}

// SessionID returns the Semp-Session-Id value the client has
// captured from the most recent response, or the empty string if no
// session id has been seen yet. Exposed primarily for diagnostics.
func (c *Client) SessionID() string {
	if c == nil {
		return ""
	}
	return c.sessionID
}

// Transport is the client-side HTTP/2 implementation of
// transport.Transport. Dial returns a turn-based transport.Conn
// that wraps an h2.Client; the underlying HTTP listener / session
// demux is supplied by the application.
type Transport struct {
	cfg Config
}

// New returns a fresh HTTP/2 Transport with default configuration
// (HTTPS required, 25 MiB message size limit, 60 s idle timeout).
func New() *Transport { return &Transport{} }

// NewWithConfig returns an HTTP/2 Transport configured per cfg. Pass
// AllowInsecure: true for local dev and tests.
func NewWithConfig(cfg Config) *Transport {
	return &Transport{cfg: cfg}
}

// ID returns transport.IDHTTP2.
func (*Transport) ID() transport.ID { return transport.IDHTTP2 }

// Profiles reports that HTTP/2 satisfies both synchronous and
// asynchronous profiles.
func (*Transport) Profiles() transport.Profile { return transport.ProfileBoth }

// Dial opens a turn-based transport.Conn to endpoint. The endpoint
// MUST be an https:// URL unless cfg.AllowInsecure is true. Dial does
// no network I/O - the first POST happens on the first Send.
//
// The returned Conn is strictly turn-based: callers MUST follow
// Send -> Recv -> Send -> Recv. This matches the SEMP handshake
// (TRANSPORT.md §4.2.3) and the request-response pattern.
func (t *Transport) Dial(ctx context.Context, endpoint string) (transport.Conn, error) {
	_ = ctx // Dial is non-blocking; ctx is accepted for interface compatibility.
	cli, err := Dial(t.cfg, endpoint)
	if err != nil {
		return nil, err
	}
	return newPersistentClient(cli, endpoint), nil
}

