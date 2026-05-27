package h2_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/semp-dev/semp-go/transport/h2"
)

// -----------------------------------------------------------------------------
// EncodeEvent / EventReader unit tests
// -----------------------------------------------------------------------------

// TestEncodeEventSingleLine confirms a single-line JSON payload is
// wrapped in one `data:` line followed by the required blank line.
func TestEncodeEventSingleLine(t *testing.T) {
	msg := []byte(`{"type":"SEMP_SUBMISSION","step":"event"}`)
	got := h2.EncodeEvent(msg)
	want := "data: " + string(msg) + "\n\n"
	if string(got) != want {
		t.Errorf("EncodeEvent = %q, want %q", got, want)
	}
}

// TestEncodeEventMultiLine confirms that embedded newlines are split
// across multiple `data:` lines per the SSE spec and that CRLF / CR
// line endings normalize to LF.
func TestEncodeEventMultiLine(t *testing.T) {
	msg := []byte("line-one\r\nline-two\nline-three")
	got := string(h2.EncodeEvent(msg))
	want := "data: line-one\ndata: line-two\ndata: line-three\n\n"
	if got != want {
		t.Errorf("EncodeEvent multi-line = %q, want %q", got, want)
	}
}

// TestEventReaderSingleEvent decodes one event from a bytes.Reader.
func TestEventReaderSingleEvent(t *testing.T) {
	input := "data: {\"hello\":\"world\"}\n\n"
	er := h2.NewEventReader(strings.NewReader(input))
	got, err := er.ReadEvent()
	if err != nil {
		t.Fatalf("ReadEvent: %v", err)
	}
	if string(got) != `{"hello":"world"}` {
		t.Errorf("data = %q, want %q", got, `{"hello":"world"}`)
	}
	if _, err := er.ReadEvent(); err != io.EOF {
		t.Errorf("expected io.EOF after single event, got %v", err)
	}
}

// TestEventReaderMultipleEvents decodes several back-to-back events.
func TestEventReaderMultipleEvents(t *testing.T) {
	input := "data: one\n\ndata: two\n\ndata: three\n\n"
	er := h2.NewEventReader(strings.NewReader(input))
	for _, want := range []string{"one", "two", "three"} {
		got, err := er.ReadEvent()
		if err != nil {
			t.Fatalf("ReadEvent(%s): %v", want, err)
		}
		if string(got) != want {
			t.Errorf("got %q, want %q", got, want)
		}
	}
	if _, err := er.ReadEvent(); err != io.EOF {
		t.Errorf("expected io.EOF at end of stream, got %v", err)
	}
}

// TestEventReaderMultilineData confirms that consecutive `data:` lines
// within one event are joined with a single newline per the SSE spec.
func TestEventReaderMultilineData(t *testing.T) {
	input := "data: line-one\ndata: line-two\ndata: line-three\n\n"
	er := h2.NewEventReader(strings.NewReader(input))
	got, err := er.ReadEvent()
	if err != nil {
		t.Fatalf("ReadEvent: %v", err)
	}
	want := "line-one\nline-two\nline-three"
	if string(got) != want {
		t.Errorf("multi-line data = %q, want %q", got, want)
	}
}

// TestEventReaderIgnoresCommentsAndOtherFields drops `:` comments,
// `event:`, `id:`, and `retry:` lines since SEMP only uses `data:`.
func TestEventReaderIgnoresCommentsAndOtherFields(t *testing.T) {
	input := ": keepalive comment\nevent: noop\nid: 42\nretry: 5000\ndata: payload\n\n"
	er := h2.NewEventReader(strings.NewReader(input))
	got, err := er.ReadEvent()
	if err != nil {
		t.Fatalf("ReadEvent: %v", err)
	}
	if string(got) != "payload" {
		t.Errorf("data = %q, want %q", got, "payload")
	}
}

// TestEventReaderCRLFLineEndings confirms CRLF line endings are
// accepted, matching the SSE spec.
func TestEventReaderCRLFLineEndings(t *testing.T) {
	input := "data: payload\r\n\r\n"
	er := h2.NewEventReader(strings.NewReader(input))
	got, err := er.ReadEvent()
	if err != nil {
		t.Fatalf("ReadEvent: %v", err)
	}
	if string(got) != "payload" {
		t.Errorf("CRLF data = %q, want %q", got, "payload")
	}
}

// TestEventReaderRoundTrip encodes a slice of messages with
// EncodeEvent then decodes them with EventReader: the simplest proof
// that the two halves agree on the wire format.
func TestEventReaderRoundTrip(t *testing.T) {
	messages := [][]byte{
		[]byte(`{"type":"A"}`),
		[]byte(`{"type":"B","nested":{"x":1}}`),
		[]byte("plain text without json"),
	}
	var buf bytes.Buffer
	for _, m := range messages {
		buf.Write(h2.EncodeEvent(m))
	}
	er := h2.NewEventReader(&buf)
	for i, want := range messages {
		got, err := er.ReadEvent()
		if err != nil {
			t.Fatalf("ReadEvent[%d]: %v", i, err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("ReadEvent[%d] = %q, want %q", i, got, want)
		}
	}
}

// -----------------------------------------------------------------------------
// OpenSessionStream client tests against a vanilla httptest SSE server
// -----------------------------------------------------------------------------

// sseServer returns an httptest.Server whose handler:
//   - responds 200 OK with Content-Type: text/event-stream;
//   - reads payloads off the events channel and writes each one as
//     one EncodeEvent-formatted SSE event with an explicit Flush;
//   - exits cleanly when the request context is cancelled (the client
//     closed) or when events is closed.
//
// The handler ignores the request body and the Semp-Session-Id header
// because the SSE wire behavior is what these tests cover; per-session
// fan-out is application-layer.
func sseServer(t *testing.T, events <-chan []byte) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", h2.ContentTypeSSE)
		w.WriteHeader(http.StatusOK)
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Errorf("ResponseWriter does not implement http.Flusher")
			return
		}
		flusher.Flush()
		for {
			select {
			case payload, ok := <-events:
				if !ok {
					return
				}
				if _, err := w.Write(h2.EncodeEvent(payload)); err != nil {
					return
				}
				flusher.Flush()
			case <-r.Context().Done():
				return
			}
		}
	}))
}

// TestOpenSessionStreamRefusesNonHTTPS covers the same TLS-by-default
// posture as Dial: the session stream opener MUST refuse plain http://
// URLs unless AllowInsecure is set.
func TestOpenSessionStreamRefusesNonHTTPS(t *testing.T) {
	_, err := h2.OpenSessionStream(context.Background(), h2.Config{}, "http://example.com/", "abc")
	if err == nil {
		t.Fatal("expected error for plain http:// URL with default config")
	}
	if !strings.Contains(err.Error(), "non-https") {
		t.Errorf("error should mention non-https refusal: %v", err)
	}
}

// TestSessionStreamDeliversMultipleEvents pushes several messages
// into the SSE handler and confirms the client receives all of them
// in order. This is the round-trip proof that EncodeEvent on one side
// and OpenSessionStream/Recv on the other agree on the wire.
func TestSessionStreamDeliversMultipleEvents(t *testing.T) {
	events := make(chan []byte, 4)
	srv := sseServer(t, events)
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream, err := h2.OpenSessionStream(ctx, h2.Config{AllowInsecure: true}, srv.URL, "01JSESS01MULTI")
	if err != nil {
		t.Fatalf("OpenSessionStream: %v", err)
	}
	defer stream.Close()

	payloads := [][]byte{
		[]byte(`{"type":"SEMP_SUBMISSION","step":"event","n":1}`),
		[]byte(`{"type":"SEMP_SUBMISSION","step":"event","n":2}`),
		[]byte(`{"type":"SEMP_REKEY","step":"init"}`),
	}
	for _, p := range payloads {
		events <- p
	}
	for i, want := range payloads {
		got, err := stream.Recv()
		if err != nil {
			t.Fatalf("Recv[%d]: %v", i, err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("Recv[%d] = %q, want %q", i, got, want)
		}
	}
}

// TestSessionStreamRecvUnblocksOnClose confirms that closing the
// client-side stream unblocks a pending Recv with an error instead
// of hanging forever.
func TestSessionStreamRecvUnblocksOnClose(t *testing.T) {
	events := make(chan []byte) // never written; Recv will park
	srv := sseServer(t, events)
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream, err := h2.OpenSessionStream(ctx, h2.Config{AllowInsecure: true}, srv.URL, "01JSESS02CLOSE")
	if err != nil {
		t.Fatalf("OpenSessionStream: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := stream.Recv()
		done <- err
	}()

	time.Sleep(50 * time.Millisecond)
	if err := stream.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Error("expected Recv to return an error after Close")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Recv did not unblock after Close")
	}
}

// TestSessionStreamServerTCPResetEndsStream confirms that if the
// underlying TCP connection is forcibly closed by the server (as
// httptest.Server.CloseClientConnections simulates on graceful
// shutdown or a crash), the client-side Recv returns instead of
// hanging.
func TestSessionStreamServerTCPResetEndsStream(t *testing.T) {
	events := make(chan []byte) // never written; Recv parks until reset
	srv := sseServer(t, events)
	defer srv.CloseClientConnections()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream, err := h2.OpenSessionStream(ctx, h2.Config{AllowInsecure: true}, srv.URL, "01JSESS03RESET")
	if err != nil {
		t.Fatalf("OpenSessionStream: %v", err)
	}
	defer stream.Close()

	done := make(chan error, 1)
	go func() {
		_, err := stream.Recv()
		done <- err
	}()

	time.Sleep(50 * time.Millisecond)
	srv.CloseClientConnections()

	select {
	case err := <-done:
		// Either io.EOF or a transport error is acceptable; what
		// matters is that Recv did NOT hang.
		_ = err
	case <-time.After(2 * time.Second):
		t.Fatal("Recv did not return after TCP reset")
	}
}
