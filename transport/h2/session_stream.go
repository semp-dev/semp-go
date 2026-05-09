package h2

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
)

// ContentTypeSSE is the media type served by the session stream handler
// (TRANSPORT.md §4.2.4). The long-lived POST to /v1/session/{id} returns
// Server-Sent Events with this content type.
const ContentTypeSSE = "text/event-stream"

// ErrNoStream is returned by the SSE writer when there is no open SSE
// stream registered for the requested session id.
var ErrNoStream = errors.New("h2: no open session stream for session id")

// ErrStreamBusy is returned by the SSE writer when a second SSE stream is
// opened for a session id that already has one. The HTTP handler
// surfaces this as 409 Conflict.
var ErrStreamBusy = errors.New("h2: session stream already open")

// -----------------------------------------------------------------------------
// SSE low-level primitives
// -----------------------------------------------------------------------------

// EncodeEvent serializes one SEMP JSON message as one SSE event per
// TRANSPORT.md §4.2.4: a sequence of `data: <line>` lines followed by a
// terminating blank line. Embedded newlines in msg are preserved by
// splitting across multiple `data:` lines per the SSE specification.
//
// Note: the SSE wire format uses CR, LF, and CRLF interchangeably as
// line terminators (WHATWG HTML §9.2). EncodeEvent normalizes any of
// those three forms to a single LF before emitting each data line,
// which means bare CR / CRLF bytes in msg do not survive the
// round trip — they are all collapsed to LF. This is fine for SEMP
// because every SEMP payload is a JSON document where control bytes
// are escaped (`\r`, `\n`), so the wire form never actually carries
// a literal CR or LF. Callers that want to transmit arbitrary binary
// bytes over an SSE channel need a separate encoding (base64) above
// this layer.
func EncodeEvent(msg []byte) []byte {
	var buf bytes.Buffer
	lines := splitSSELines(msg)
	for _, line := range lines {
		buf.WriteString("data: ")
		buf.Write(line)
		buf.WriteByte('\n')
	}
	buf.WriteByte('\n')
	return buf.Bytes()
}

// splitSSELines splits msg on any SSE-recognized line terminator (CR,
// LF, or CRLF), returning one element per line. A trailing terminator
// does NOT produce a trailing empty line — matching the behavior of
// strings.Split when the final byte is the separator is explicitly
// what we want, because an empty trailing element would emit a spurious
// `data: ` line and the decoder would then see an extra empty-data
// event.
func splitSSELines(msg []byte) [][]byte {
	if len(msg) == 0 {
		return [][]byte{nil}
	}
	var out [][]byte
	start := 0
	for i := 0; i < len(msg); i++ {
		b := msg[i]
		if b != '\r' && b != '\n' {
			continue
		}
		out = append(out, msg[start:i])
		if b == '\r' && i+1 < len(msg) && msg[i+1] == '\n' {
			i++ // skip the LF of a CRLF pair
		}
		start = i + 1
	}
	// Final segment (may be empty if msg ended in a line terminator).
	out = append(out, msg[start:])
	return out
}

// EventReader decodes SSE events from an io.Reader. Each call to
// ReadEvent returns the concatenated data payload of the next event,
// stitching multi-line `data:` continuations together with a single
// newline between them per the SSE spec. Comment lines (beginning with
// `:`) and non-`data:` fields (`event:`, `id:`, `retry:`) are silently
// ignored because SEMP only uses the `data` field.
type EventReader struct {
	br *bufio.Reader
}

// NewEventReader wraps r with the default bufio buffer size.
func NewEventReader(r io.Reader) *EventReader {
	return &EventReader{br: bufio.NewReader(r)}
}

// NewEventReaderSize wraps r with an explicit buffer size, useful when
// the caller expects payloads near the 25 MiB envelope ceiling.
func NewEventReaderSize(r io.Reader, size int) *EventReader {
	return &EventReader{br: bufio.NewReaderSize(r, size)}
}

// ReadEvent returns the data payload of the next event. Returns io.EOF
// when the underlying stream ends with no partial event buffered.
func (er *EventReader) ReadEvent() ([]byte, error) {
	if er == nil || er.br == nil {
		return nil, errors.New("h2: nil event reader")
	}
	var data []byte
	hasData := false
	for {
		line, err := er.br.ReadString('\n')
		if len(line) == 0 {
			if err == nil {
				// Should not happen with ReadString, but be defensive.
				continue
			}
			if err == io.EOF && hasData {
				return data, nil
			}
			return nil, err
		}
		// Strip the trailing LF plus any preceding CR (SSE permits
		// LF, CR, or CRLF line endings).
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			if hasData {
				return data, nil
			}
			// Empty leading blank lines (keepalives, initial handshake
			// comment flushes) are benign — keep reading.
			if err == io.EOF {
				return nil, io.EOF
			}
			continue
		}
		// Comment: colon-prefixed line with no field name. Ignore.
		if strings.HasPrefix(line, ":") {
			if err == io.EOF {
				if hasData {
					return data, nil
				}
				return nil, io.EOF
			}
			continue
		}
		// Field parse: "<field>: <value>" per SSE, where the single
		// space after the colon is optional.
		var field, value string
		if idx := strings.IndexByte(line, ':'); idx >= 0 {
			field = line[:idx]
			value = line[idx+1:]
			if strings.HasPrefix(value, " ") {
				value = value[1:]
			}
		} else {
			field = line
		}
		if field != "data" {
			// SEMP only cares about the data field.
			if err == io.EOF {
				if hasData {
					return data, nil
				}
				return nil, io.EOF
			}
			continue
		}
		if hasData {
			data = append(data, '\n')
		}
		data = append(data, value...)
		hasData = true
		if err == io.EOF {
			return data, nil
		}
	}
}

// -----------------------------------------------------------------------------
// Client-side SSE consumer
// -----------------------------------------------------------------------------

// SessionStreamConn is the client-side reader for an open SSE session
// stream. Recv returns one SEMP message at a time; callers are
// responsible for parsing the JSON they receive. Close tears down the
// underlying HTTP connection.
type SessionStreamConn struct {
	sid    string
	url    string
	resp   *http.Response
	reader *EventReader
	cancel context.CancelFunc

	closeOnce sync.Once
}

// OpenSessionStream opens the long-lived SSE session stream at
// endpoint + PathSession + sid. The returned SessionStreamConn must be
// Closed when the caller is done, to release the underlying HTTP
// connection. ctx drives the lifetime of the stream: canceling ctx
// aborts any pending Recv.
//
// endpoint is the same base URL used for request-response h2 POSTs.
// Per TRANSPORT.md §4.2, HTTPS is required unless cfg.AllowInsecure
// is true (tests and local development only).
//
// OpenSessionStream does NOT apply cfg.HTTPClient's Timeout to the
// stream — session streams are expected to live for the duration of
// the session and the caller's ctx is the only cancellation source.
// If cfg.HTTPClient is nil, a fresh timeout-free *http.Client is
// constructed. Consumers that want a shared transport should pass a
// client with Transport set but Timeout left zero.
func OpenSessionStream(ctx context.Context, cfg Config, endpoint, sid string) (*SessionStreamConn, error) {
	if sid == "" {
		return nil, errors.New("h2: empty session id")
	}
	if endpoint == "" {
		return nil, errors.New("h2: empty endpoint")
	}
	if !cfg.AllowInsecure && !strings.HasPrefix(endpoint, "https://") {
		return nil, fmt.Errorf("h2: refusing to open stream on non-https URL %q (set Config.AllowInsecure for local dev)", endpoint)
	}
	client := cfg.HTTPClient
	if client == nil {
		// A timeout here would kill the long-lived stream; ctx is
		// the only cancellation source.
		client = &http.Client{}
	}
	streamCtx, cancel := context.WithCancel(ctx)
	url := strings.TrimRight(endpoint, "/") + PathSession + sid
	req, err := http.NewRequestWithContext(streamCtx, http.MethodPost, url, nil)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("h2: build session stream request: %w", err)
	}
	req.Header.Set("Accept", ContentTypeSSE)
	req.Header.Set(HeaderSessionID, sid)
	resp, err := client.Do(req)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("h2: open session stream: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
		cancel()
		return nil, fmt.Errorf("h2: session stream %s returned %d: %s", url, resp.StatusCode, string(body))
	}
	return &SessionStreamConn{
		sid:    sid,
		url:    url,
		resp:   resp,
		reader: NewEventReader(resp.Body),
		cancel: cancel,
	}, nil
}

// Recv blocks until the next server-pushed SEMP message arrives or the
// stream closes. Returns io.EOF when the server terminates the stream
// cleanly; returns ctx.Err() (via the context passed to
// OpenSessionStream) on cancellation.
func (s *SessionStreamConn) Recv() ([]byte, error) {
	if s == nil || s.reader == nil {
		return nil, errors.New("h2: nil session stream")
	}
	return s.reader.ReadEvent()
}

// Close tears down the underlying HTTP connection. It is safe to call
// Close multiple times; the second and subsequent calls are no-ops.
func (s *SessionStreamConn) Close() error {
	if s == nil {
		return nil
	}
	s.closeOnce.Do(func() {
		if s.cancel != nil {
			s.cancel()
		}
		if s.resp != nil && s.resp.Body != nil {
			_ = s.resp.Body.Close()
		}
	})
	return nil
}

// SessionID returns the session id this stream is bound to.
func (s *SessionStreamConn) SessionID() string {
	if s == nil {
		return ""
	}
	return s.sid
}

// URL returns the full URL of the server-side SSE endpoint. Useful for
// diagnostics.
func (s *SessionStreamConn) URL() string {
	if s == nil {
		return ""
	}
	return s.url
}
