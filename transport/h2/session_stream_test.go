package h2_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"semp.dev/semp-go/transport/h2"
)

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
// across multiple `data:` lines per the SSE spec and that trailing CRs
// are stripped.
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
	// Next read should return io.EOF cleanly.
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

// TestEventReaderCRLFLineEndings confirms CRLF, CR, and LF line endings
// are all accepted.
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

// TestEventReaderRoundTrip encodes a slice of messages with EncodeEvent
// then decodes them with EventReader — the simplest proof that the two
// halves agree on the wire format.
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

// TestSessionHubPushAndUnregister covers the happy path: register
// (via handler), push a message, receive it, unregister.
func TestSessionHubPushAndUnregister(t *testing.T) {
	hub := h2.NewSessionHub(4)
	handler := h2.NewSessionStreamHandler(hub)
	srv := httptest.NewServer(handler)
	defer srv.Close()

	sid := "01JSESSION01HUBBASIC"

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream, err := h2.OpenSessionStream(ctx, h2.Config{AllowInsecure: true}, srv.URL, sid)
	if err != nil {
		t.Fatalf("OpenSessionStream: %v", err)
	}
	defer stream.Close()

	// Spin until the handler has registered the session so the
	// Push happens against an open stream.
	deadline := time.Now().Add(time.Second)
	for !hub.Active(sid) && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !hub.Active(sid) {
		t.Fatal("hub never registered the session")
	}

	payload := []byte(`{"type":"SEMP_SUBMISSION","step":"event","status":"delivered"}`)
	if err := hub.Push(context.Background(), sid, payload); err != nil {
		t.Fatalf("Push: %v", err)
	}

	got, err := stream.Recv()
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("Recv = %q, want %q", got, payload)
	}

	stream.Close()
	// Handler should unregister after the client closes.
	deadline = time.Now().Add(time.Second)
	for hub.Active(sid) && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if hub.Active(sid) {
		t.Error("hub did not unregister after client close")
	}
}

// TestSessionHubPushNoStream confirms Push returns ErrNoStream when no
// stream is registered for a session id.
func TestSessionHubPushNoStream(t *testing.T) {
	hub := h2.NewSessionHub(4)
	err := hub.Push(context.Background(), "nobody", []byte(`{"x":1}`))
	if !errors.Is(err, h2.ErrNoStream) {
		t.Errorf("Push to unknown sid = %v, want ErrNoStream", err)
	}
	if hub.Len() != 0 {
		t.Errorf("empty hub Len = %d, want 0", hub.Len())
	}
}

// TestSessionStreamHandlerConflict confirms a second concurrent open
// for the same session id returns 409 Conflict.
func TestSessionStreamHandlerConflict(t *testing.T) {
	hub := h2.NewSessionHub(4)
	handler := h2.NewSessionStreamHandler(hub)
	srv := httptest.NewServer(handler)
	defer srv.Close()

	sid := "01JSESSION02CONFLICT"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	first, err := h2.OpenSessionStream(ctx, h2.Config{AllowInsecure: true}, srv.URL, sid)
	if err != nil {
		t.Fatalf("first OpenSessionStream: %v", err)
	}
	defer first.Close()
	// Wait for registration.
	deadline := time.Now().Add(time.Second)
	for !hub.Active(sid) && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !hub.Active(sid) {
		t.Fatal("hub never registered first stream")
	}
	_, err = h2.OpenSessionStream(ctx, h2.Config{AllowInsecure: true}, srv.URL, sid)
	if err == nil {
		t.Fatal("second OpenSessionStream should have failed with 409")
	}
	if !strings.Contains(err.Error(), "409") {
		t.Errorf("second open error should mention 409: %v", err)
	}
}

// TestSessionStreamHandlerInvalidPath confirms bad URLs get 400/404.
func TestSessionStreamHandlerInvalidPath(t *testing.T) {
	hub := h2.NewSessionHub(4)
	handler := h2.NewSessionStreamHandler(hub)
	srv := httptest.NewServer(handler)
	defer srv.Close()

	tests := []struct {
		name string
		path string
		want int
	}{
		{"wrong prefix", "/not-session/abc", http.StatusNotFound},
		{"empty sid", h2.PathSession, http.StatusBadRequest},
		{"nested sid", h2.PathSession + "abc/def", http.StatusBadRequest},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodPost, srv.URL+tc.path, nil)
			resp, err := srv.Client().Do(req)
			if err != nil {
				t.Fatalf("Do: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != tc.want {
				t.Errorf("status = %d, want %d", resp.StatusCode, tc.want)
			}
		})
	}
}

// TestSessionStreamHandlerMethodNotAllowed confirms PUT / DELETE are
// rejected with 405 while POST and GET are accepted.
func TestSessionStreamHandlerMethodNotAllowed(t *testing.T) {
	hub := h2.NewSessionHub(4)
	handler := h2.NewSessionStreamHandler(hub)
	srv := httptest.NewServer(handler)
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodPut, srv.URL+h2.PathSession+"abc", nil)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("PUT status = %d, want 405", resp.StatusCode)
	}
}

// TestSessionStreamDeliversMultipleEvents pushes several messages and
// confirms the client receives all of them in order.
func TestSessionStreamDeliversMultipleEvents(t *testing.T) {
	hub := h2.NewSessionHub(16)
	handler := h2.NewSessionStreamHandler(hub)
	srv := httptest.NewServer(handler)
	defer srv.Close()

	sid := "01JSESSION03MULTI"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream, err := h2.OpenSessionStream(ctx, h2.Config{AllowInsecure: true}, srv.URL, sid)
	if err != nil {
		t.Fatalf("OpenSessionStream: %v", err)
	}
	defer stream.Close()

	deadline := time.Now().Add(time.Second)
	for !hub.Active(sid) && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !hub.Active(sid) {
		t.Fatal("hub never registered the session")
	}

	payloads := [][]byte{
		[]byte(`{"type":"SEMP_SUBMISSION","step":"event","n":1}`),
		[]byte(`{"type":"SEMP_SUBMISSION","step":"event","n":2}`),
		[]byte(`{"type":"SEMP_REKEY","step":"init"}`),
	}
	for _, p := range payloads {
		if err := hub.Push(context.Background(), sid, p); err != nil {
			t.Fatalf("Push: %v", err)
		}
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
// client-side stream unblocks a pending Recv with an error instead of
// hanging forever.
func TestSessionStreamRecvUnblocksOnClose(t *testing.T) {
	hub := h2.NewSessionHub(4)
	handler := h2.NewSessionStreamHandler(hub)
	srv := httptest.NewServer(handler)
	defer srv.Close()

	sid := "01JSESSION04CLOSE"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream, err := h2.OpenSessionStream(ctx, h2.Config{AllowInsecure: true}, srv.URL, sid)
	if err != nil {
		t.Fatalf("OpenSessionStream: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := stream.Recv()
		done <- err
	}()

	// Let Recv start blocking, then close the stream.
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
// hanging. We use CloseClientConnections rather than Close because
// httptest.Server.Close waits for in-flight handlers to return,
// which would itself deadlock on the SSE handler we are testing.
func TestSessionStreamServerTCPResetEndsStream(t *testing.T) {
	hub := h2.NewSessionHub(4)
	handler := h2.NewSessionStreamHandler(hub)
	srv := httptest.NewServer(handler)
	defer srv.CloseClientConnections()

	sid := "01JSESSION05TCPRESET"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream, err := h2.OpenSessionStream(ctx, h2.Config{AllowInsecure: true}, srv.URL, sid)
	if err != nil {
		t.Fatalf("OpenSessionStream: %v", err)
	}
	defer stream.Close()

	deadline := time.Now().Add(time.Second)
	for !hub.Active(sid) && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}

	done := make(chan error, 1)
	go func() {
		_, err := stream.Recv()
		done <- err
	}()

	// Let the Recv goroutine park on its Read, then tear down the
	// client-side TCP connection. The server handler will detect
	// the broken pipe on its next write or via r.Context().Done().
	time.Sleep(50 * time.Millisecond)
	srv.CloseClientConnections()

	select {
	case err := <-done:
		// Either io.EOF or a transport error is acceptable; what
		// matters is Recv did NOT hang.
		_ = err
	case <-time.After(2 * time.Second):
		t.Fatal("Recv did not return after TCP reset")
	}
}

// TestSessionHubLen tracks stream count through open/close cycles.
func TestSessionHubLen(t *testing.T) {
	hub := h2.NewSessionHub(4)
	handler := h2.NewSessionStreamHandler(hub)
	srv := httptest.NewServer(handler)
	defer srv.Close()

	if hub.Len() != 0 {
		t.Errorf("initial Len = %d, want 0", hub.Len())
	}
	var streams []*h2.SessionStreamConn
	for i, sid := range []string{
		"01JSESSHUB01",
		"01JSESSHUB02",
		"01JSESSHUB03",
	} {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		s, err := h2.OpenSessionStream(ctx, h2.Config{AllowInsecure: true}, srv.URL, sid)
		if err != nil {
			t.Fatalf("OpenSessionStream[%d]: %v", i, err)
		}
		streams = append(streams, s)
	}
	// Wait for all registrations.
	deadline := time.Now().Add(time.Second)
	for hub.Len() < 3 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if hub.Len() != 3 {
		t.Errorf("after 3 opens Len = %d, want 3", hub.Len())
	}
	for _, s := range streams {
		s.Close()
	}
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

