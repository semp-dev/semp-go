// Package h2 is the HTTP/2 binding for the SEMP transport layer
// (TRANSPORT.md §4.2).
//
// # Scope
//
// This package currently provides two primitives that a consumer can
// use to build HTTP/2-backed SEMP flows:
//
//   - Client: a client-side request-response helper that POSTs SEMP
//     messages to a server endpoint and threads the Semp-Session-Id
//     header across multiple requests for a single logical session.
//   - NewHandler: an http.Handler factory that wraps a per-POST
//     HandlerFunc. Each incoming POST invokes the function once and
//     writes the returned bytes as the response body, setting the
//     Semp-Session-Id header on the way out.
//
// These primitives are enough to drive single-POST exchanges
// (envelope submission, SEMP_KEYS lookup, SEMP_DISCOVERY) and
// multi-POST exchanges (handshake, where each message is a separate
// request-response round trip per TRANSPORT.md §4.2.3).
//
// # What this package does NOT do yet
//
// transport.Transport.Dial and .Listen are implemented as wrappers
// that return errors with a clear "not yet wired" message. The full
// symmetric transport.Conn model for HTTP/2 requires cross-request
// server-side goroutine coordination (a persistent "virtual connection"
// behind multiple HTTP handlers correlated by Semp-Session-Id) which
// is a follow-up milestone.
//
// The SSE-based session stream described in TRANSPORT.md §4.2.4
// (server-push of delivery events and rekey init messages) is also
// deferred.
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

// Path constants for the HTTP/2 binding (TRANSPORT.md §4.2.1).
const (
	PathDiscovery = "/v1/discovery"
	PathKeys      = "/v1/keys"
	PathHandshake = "/v1/handshake"
	PathEnvelope  = "/v1/envelope"
	PathSession   = "/v1/session/" // append session id
)

// HeaderSessionID is the response header that the server uses to
// correlate subsequent handshake POSTs with the in-progress handshake
// (TRANSPORT.md §4.2.3).
const HeaderSessionID = "Semp-Session-Id"

// ContentType is the JSON content type used for all SEMP HTTP/2
// bodies (TRANSPORT.md §4.2.1 — "All request and response bodies are
// application/json; charset=utf-8").
const ContentType = "application/json; charset=utf-8"

// DefaultTimeout is the default request timeout the Client applies to
// each Do call when the context has no deadline.
const DefaultTimeout = 30 * time.Second

// DefaultMaxBodyBytes is the maximum body size the server-side
// handler will read from an incoming POST and the Client will read
// from a response. 25 MiB matches the DISCOVERY.md §3.1 default
// max_message_size and keeps a hostile peer from tricking the
// reader into unbounded allocation.
const DefaultMaxBodyBytes int64 = 25 * 1024 * 1024

// Config controls the behavior of Client and NewHandler.
type Config struct {
	// AllowInsecure permits dialing plain http:// URLs and
	// accepting plain HTTP servers. Production deployments MUST
	// leave this false (the default). Per TRANSPORT.md §4.2,
	// HTTPS is the only permitted scheme; tests and local dev use
	// this flag to opt out of the check.
	AllowInsecure bool

	// HTTPClient is the underlying *http.Client. Zero means
	// "use a fresh client with DefaultTimeout".
	HTTPClient *http.Client

	// MaxBodyBytes caps the size of request AND response bodies
	// on both the client and server. Zero means
	// DefaultMaxBodyBytes.
	MaxBodyBytes int64
}

// Client is the client-side HTTP/2 primitive. One Client corresponds
// to one logical SEMP session against one endpoint URL. Client.Do
// makes one POST per call and threads the Semp-Session-Id header
// across successive calls, so a multi-message handshake (init →
// response → confirm → accepted per TRANSPORT.md §4.2.3) maps to a
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
// Dial does not perform any network I/O — the first actual HTTP
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
// regardless of its SEMP-level content — SEMP rejections with a
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

// HandlerFunc is the server-side per-POST callback that
// NewHandler wraps. It receives the request body bytes and the
// Semp-Session-Id header from the request (empty on the first POST
// of a session) and returns the response body plus an optional new
// session id to set in the response header.
//
// Returning a non-nil error causes NewHandler to respond with HTTP
// 500 and err.Error() as the body. For SEMP-level rejections (a
// rejection message with a reason_code) the function should return
// the rejection JSON as resp and a nil error — the HTTP layer only
// signals TRANSPORT problems, not SEMP outcomes (TRANSPORT.md
// §4.2.2).
type HandlerFunc func(ctx context.Context, req []byte, sessionID string) (resp []byte, newSessionID string, err error)

// NewHandler returns an http.Handler that wraps fn in the SEMP
// HTTP/2 request-response convention:
//
//  1. Reject non-POST methods with 405.
//  2. Reject bodies larger than cfg.MaxBodyBytes with 413.
//  3. Extract the Semp-Session-Id header (may be empty).
//  4. Read the request body.
//  5. Invoke fn with (body, session id).
//  6. On success: write the returned body with Content-Type
//     application/json and set the response Semp-Session-Id header
//     if fn returned one.
//  7. On error: write HTTP 500 with the error message.
//
// NewHandler does NOT route based on path — the caller mounts the
// returned handler under whichever path they want (e.g. PathEnvelope,
// PathHandshake, or a single shared path).
func NewHandler(cfg Config, fn HandlerFunc) http.Handler {
	maxBody := cfg.MaxBodyBytes
	if maxBody <= 0 {
		maxBody = DefaultMaxBodyBytes
	}
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
		sessionID := r.Header.Get(HeaderSessionID)
		resp, newSessionID, err := fn(r.Context(), body, sessionID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", ContentType)
		if newSessionID != "" {
			w.Header().Set(HeaderSessionID, newSessionID)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(resp)
	})
}

// Transport is a placeholder implementation of transport.Transport
// for HTTP/2. Dial and Listen return errors because the full
// symmetric transport.Conn model for HTTP/2 requires per-session
// cross-request goroutine coordination on the server side, which is
// deferred to a follow-up milestone.
//
// Use Client and NewHandler directly for the time being.
type Transport struct{}

// New returns a fresh HTTP/2 Transport.
func New() *Transport { return &Transport{} }

// ID returns transport.IDHTTP2.
func (*Transport) ID() transport.ID { return transport.IDHTTP2 }

// Profiles reports that HTTP/2 satisfies both synchronous and
// asynchronous profiles.
func (*Transport) Profiles() transport.Profile { return transport.ProfileBoth }

// Dial is not yet implemented as a symmetric transport.Conn. Use
// h2.Dial (returning *Client) instead.
func (*Transport) Dial(ctx context.Context, endpoint string) (transport.Conn, error) {
	_, _ = ctx, endpoint
	return nil, errors.New("h2: symmetric transport.Conn Dial not yet implemented; use h2.Dial(cfg, endpoint) for Client")
}

// Listen is not yet implemented as a symmetric transport.Listener.
// Use h2.NewHandler to mount the HTTP/2 SEMP binding on an existing
// http.Server.
func (*Transport) Listen(ctx context.Context, addr string) (transport.Listener, error) {
	_, _ = ctx, addr
	return nil, errors.New("h2: symmetric transport.Listener Listen not yet implemented; use h2.NewHandler to mount on an http.Server")
}
