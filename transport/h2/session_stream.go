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

// ErrNoStream is returned by SessionHub.Push when there is no open SSE
// stream registered for the requested session id.
var ErrNoStream = errors.New("h2: no open session stream for session id")

// ErrStreamBusy is returned by SessionHub when a second SSE stream is
// opened for a session id that already has one. The HTTP handler
// surfaces this as 409 Conflict.
var ErrStreamBusy = errors.New("h2: session stream already open")

// -----------------------------------------------------------------------------
// SSE low-level primitives
// -----------------------------------------------------------------------------

// EncodeEvent serializes one SEMP JSON message as one SSE event per
// TRANSPORT.md §4.2.4: a sequence of `data: <line>` lines followed by a
// terminating blank line. Embedded newlines in msg are preserved by
// splitting across multiple `data:` lines per the SSE specification;
// receivers reassemble them by joining on `\n`. CR characters that
// precede an LF are stripped so a CRLF-terminated payload does not emit
// stray CRs on the wire.
func EncodeEvent(msg []byte) []byte {
	var buf bytes.Buffer
	lines := bytes.Split(msg, []byte{'\n'})
	for _, line := range lines {
		line = bytes.TrimRight(line, "\r")
		buf.WriteString("data: ")
		buf.Write(line)
		buf.WriteByte('\n')
	}
	buf.WriteByte('\n')
	return buf.Bytes()
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
// SessionHub
// -----------------------------------------------------------------------------

// SessionHub is a fan-out registry that lets higher-level SEMP server
// code push asynchronous messages to connected clients over the SSE
// session stream defined in TRANSPORT.md §4.2.4. One entry exists per
// currently-open SSE stream, keyed by the client's session id.
//
// The hub is the integration point between server-initiated message
// producers (delivery event publishers, server-side rekey initiators)
// and the HTTP handler that serves the long-lived POST. Producers call
// Push(sid, msg); the handler mounted via NewSessionStreamHandler
// drains the registered channel and writes each message as one SSE
// event. When no stream is currently open for a session id Push
// returns ErrNoStream — the caller is responsible for deciding whether
// to queue, drop, or report the undeliverable message.
type SessionHub struct {
	mu      sync.Mutex
	streams map[string]chan []byte
	bufSize int
}

// NewSessionHub returns an empty SessionHub. bufSize is the per-stream
// buffered channel capacity; Push blocks once the buffer is full until
// the handler drains earlier events or the stream closes. Zero picks a
// modest default (32 messages).
func NewSessionHub(bufSize int) *SessionHub {
	if bufSize <= 0 {
		bufSize = 32
	}
	return &SessionHub{
		streams: map[string]chan []byte{},
		bufSize: bufSize,
	}
}

// register adds a fresh push channel for sid. Returns ErrStreamBusy
// when a stream is already registered — the SEMP protocol permits at
// most one session stream per session id at a time.
func (h *SessionHub) register(sid string) (chan []byte, error) {
	if h == nil {
		return nil, errors.New("h2: nil session hub")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, exists := h.streams[sid]; exists {
		return nil, ErrStreamBusy
	}
	ch := make(chan []byte, h.bufSize)
	h.streams[sid] = ch
	return ch, nil
}

// unregister removes ch from the hub, but only if it is still the
// registered channel for sid. A stale unregister (after the session
// has been re-opened) is a no-op.
func (h *SessionHub) unregister(sid string, ch chan []byte) {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if cur, ok := h.streams[sid]; ok && cur == ch {
		delete(h.streams, sid)
		close(ch)
	}
}

// Push delivers msg as one SSE event to the stream registered for sid.
// Returns ErrNoStream if no stream is currently open. The caller's msg
// is copied before enqueue so the hub does not share ownership of the
// backing array.
func (h *SessionHub) Push(ctx context.Context, sid string, msg []byte) error {
	if h == nil {
		return errors.New("h2: nil session hub")
	}
	h.mu.Lock()
	ch, ok := h.streams[sid]
	h.mu.Unlock()
	if !ok {
		return ErrNoStream
	}
	buf := make([]byte, len(msg))
	copy(buf, msg)
	select {
	case ch <- buf:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Active reports whether an SSE stream is currently open for sid.
func (h *SessionHub) Active(sid string) bool {
	if h == nil {
		return false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	_, ok := h.streams[sid]
	return ok
}

// Len returns the number of currently-open streams. Intended for
// diagnostics and metrics.
func (h *SessionHub) Len() int {
	if h == nil {
		return 0
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.streams)
}

// -----------------------------------------------------------------------------
// Server-side SSE handler
// -----------------------------------------------------------------------------

// NewSessionStreamHandler returns an http.Handler that serves the
// long-lived session stream defined in TRANSPORT.md §4.2.4. The handler
// expects a URL path of the form PathSession + "<session-id>" and
// streams every message pushed to hub for that session id as one SSE
// event. The client half of this channel is OpenSessionStream.
//
// Per the spec the session stream is opened with a POST; the handler
// also accepts GET for test and debugging convenience but production
// clients should use POST. Any other method returns 405.
//
// Duplicate opens for a session id that is already streaming are
// rejected with 409 Conflict.
//
// The handler holds the HTTP response open until one of:
//   - hub.unregister closes the push channel (e.g. on shutdown)
//   - the underlying http.Request context is canceled (client closed)
//
// On return the handler unregisters its channel so Push starts
// returning ErrNoStream for the session id again.
func NewSessionStreamHandler(hub *SessionHub) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost && r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !strings.HasPrefix(r.URL.Path, PathSession) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		sid := strings.TrimPrefix(r.URL.Path, PathSession)
		if sid == "" || strings.ContainsRune(sid, '/') {
			http.Error(w, "malformed session path", http.StatusBadRequest)
			return
		}
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}
		ch, err := hub.register(sid)
		if err != nil {
			if errors.Is(err, ErrStreamBusy) {
				http.Error(w, err.Error(), http.StatusConflict)
				return
			}
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer hub.unregister(sid, ch)

		h := w.Header()
		h.Set("Content-Type", ContentTypeSSE)
		h.Set("Cache-Control", "no-cache")
		h.Set("Connection", "keep-alive")
		h.Set(HeaderSessionID, sid)
		w.WriteHeader(http.StatusOK)
		// Emit an initial comment line so intermediaries flush the
		// response headers and the client's ReadEvent loop observes a
		// live body before the first real event arrives.
		_, _ = io.WriteString(w, ": semp-stream-ready\n\n")
		flusher.Flush()

		for {
			select {
			case msg, open := <-ch:
				if !open {
					return
				}
				if _, err := w.Write(EncodeEvent(msg)); err != nil {
					return
				}
				flusher.Flush()
			case <-r.Context().Done():
				return
			}
		}
	})
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
