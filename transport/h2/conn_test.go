package h2_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/semp-dev/semp-go/transport"
	"github.com/semp-dev/semp-go/transport/h2"
)

// makePost is a tiny helper for the handful of tests that need to
// drive a POST with a manually chosen Semp-Session-Id header.
func makePost(url, sessionID string) (*http.Request, error) {
	r, err := http.NewRequest("POST", url, bytes.NewReader([]byte(`{}`)))
	if err != nil {
		return nil, err
	}
	r.Header.Set("Content-Type", h2.ContentType)
	if sessionID != "" {
		r.Header.Set(h2.HeaderSessionID, sessionID)
	}
	return r, nil
}

// TestPersistentHandlerTurnBased drives a single Semp-Session-Id
// through two POSTs against NewPersistentHandler. The accept callback
// sees a real transport.Conn and runs Recv → Send → Recv → Send
// without knowing anything about HTTP.
func TestPersistentHandlerTurnBased(t *testing.T) {
	var acceptErr error
	done := make(chan struct{})
	handler := h2.NewPersistentHandler(h2.PersistentConfig{
		Config: h2.Config{AllowInsecure: true},
	}, func(c transport.Conn) {
		defer close(done)
		defer c.Close()
		for i := 0; i < 2; i++ {
			msg, err := c.Recv(context.Background())
			if err != nil {
				acceptErr = err
				return
			}
			reply := append([]byte("echo:"), msg...)
			if err := c.Send(context.Background(), reply); err != nil {
				acceptErr = err
				return
			}
		}
	})
	srv := httptest.NewServer(handler)
	defer srv.Close()

	cli, err := h2.Dial(h2.Config{AllowInsecure: true}, srv.URL)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}

	for i, in := range []string{"hello", "world"} {
		resp, err := cli.Do(context.Background(), []byte(in))
		if err != nil {
			t.Fatalf("Do[%d]: %v", i, err)
		}
		if got, want := string(resp), "echo:"+in; got != want {
			t.Errorf("Do[%d] = %q, want %q", i, got, want)
		}
	}
	if cli.SessionID() == "" {
		t.Error("client did not capture a Semp-Session-Id")
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("accept callback did not finish")
	}
	if acceptErr != nil {
		t.Errorf("accept callback error: %v", acceptErr)
	}
}

// TestPersistentHandlerUnknownSession confirms that a POST with an
// unrecognized Semp-Session-Id gets a 404 rather than being silently
// promoted to a new session.
func TestPersistentHandlerUnknownSession(t *testing.T) {
	handler := h2.NewPersistentHandler(h2.PersistentConfig{
		Config: h2.Config{AllowInsecure: true},
	}, func(c transport.Conn) {
		t.Error("accept callback should not fire for unknown session")
	})
	srv := httptest.NewServer(handler)
	defer srv.Close()

	r, err := makePost(srv.URL, "NOSUCHSESSION00000000000000")
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	resp, err := srv.Client().Do(r)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

// TestPersistentHandlerRejectsSendBeforeRecv confirms that an accept
// callback calling Send before Recv gets a clean error, not a panic
// or a hang.
func TestPersistentHandlerRejectsSendBeforeRecv(t *testing.T) {
	var acceptErr error
	done := make(chan struct{})
	handler := h2.NewPersistentHandler(h2.PersistentConfig{
		Config: h2.Config{AllowInsecure: true},
	}, func(c transport.Conn) {
		defer close(done)
		defer c.Close()
		// Intentionally violate the protocol: Send without Recv.
		acceptErr = c.Send(context.Background(), []byte("early"))
	})
	srv := httptest.NewServer(handler)
	defer srv.Close()

	cli, err := h2.Dial(h2.Config{AllowInsecure: true}, srv.URL)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	// Don't drive any POSTs — the accept callback runs on session
	// creation and needs a POST to trigger. So POST once and let the
	// handler block (we expect a 500 back because Send fails).
	_, err = cli.Do(context.Background(), []byte("hi"))
	if err == nil {
		// The accept callback's first action was Send (which fails
		// because there's no pending turn). That leaves the POST
		// waiting on the reply channel until the conn is closed by
		// the deferred c.Close(), at which point the handler surfaces
		// a "session closed" 410.
		t.Fatal("expected POST to fail because accept misbehaved")
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("accept callback did not finish")
	}
	if acceptErr == nil || !strings.Contains(acceptErr.Error(), "without a pending POST") {
		t.Errorf("expected 'without a pending POST' error, got %v", acceptErr)
	}
}

// TestPersistentHandlerIdleReaper confirms that a session with no
// POST activity for the configured idle timeout is closed, and the
// accept callback's next Recv returns io.EOF.
func TestPersistentHandlerIdleReaper(t *testing.T) {
	var recvErr error
	done := make(chan struct{})
	handler := h2.NewPersistentHandler(h2.PersistentConfig{
		Config:      h2.Config{AllowInsecure: true},
		IdleTimeout: 150 * time.Millisecond,
	}, func(c transport.Conn) {
		defer close(done)
		defer c.Close()
		// Process the first POST.
		msg, err := c.Recv(context.Background())
		if err != nil {
			recvErr = err
			return
		}
		_ = c.Send(context.Background(), msg)
		// Wait for another POST that never comes — Recv should
		// unblock with io.EOF once the idle reaper fires.
		_, err = c.Recv(context.Background())
		recvErr = err
	})
	srv := httptest.NewServer(handler)
	defer srv.Close()

	cli, err := h2.Dial(h2.Config{AllowInsecure: true}, srv.URL)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	if _, err := cli.Do(context.Background(), []byte("hello")); err != nil {
		t.Fatalf("Do: %v", err)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("idle reaper did not close conn in time")
	}
	if !errors.Is(recvErr, io.EOF) {
		t.Errorf("expected io.EOF after idle reap, got %v", recvErr)
	}
}

// TestTransportDialListenRoundTrip drives a full handshake-shaped
// exchange through Transport.Listen and Transport.Dial. This is the
// "inboxd.Server.Serve can now run over h2 transparently" proof:
// handshake.MessageStream only needs Send/Recv and the listener-side
// transport.Conn behaves exactly like the ws equivalent.
func TestTransportDialListenRoundTrip(t *testing.T) {
	tr := h2.NewWithConfig(h2.PersistentConfig{Config: h2.Config{AllowInsecure: true}})
	lis, err := tr.Listen(context.Background(), "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer lis.Close()

	addr := lis.(interface{ Addr() string }).Addr()
	serverURL := "http://" + addr

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		c, err := lis.Accept(context.Background())
		if err != nil {
			t.Errorf("Accept: %v", err)
			return
		}
		defer c.Close()
		for i := 0; i < 3; i++ {
			msg, err := c.Recv(context.Background())
			if err != nil {
				t.Errorf("server Recv[%d]: %v", i, err)
				return
			}
			if err := c.Send(context.Background(), append([]byte("ack:"), msg...)); err != nil {
				t.Errorf("server Send[%d]: %v", i, err)
				return
			}
		}
	}()

	conn, err := tr.Dial(context.Background(), serverURL)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	for i, msg := range []string{"init", "confirm", "payload"} {
		if err := conn.Send(context.Background(), []byte(msg)); err != nil {
			t.Fatalf("Send[%d]: %v", i, err)
		}
		got, err := conn.Recv(context.Background())
		if err != nil {
			t.Fatalf("Recv[%d]: %v", i, err)
		}
		if string(got) != "ack:"+msg {
			t.Errorf("Recv[%d] = %q, want %q", i, got, "ack:"+msg)
		}
	}

	// Confirm Peer() returns a non-empty string on both sides.
	if conn.Peer() == "" {
		t.Error("client Peer() returned empty string")
	}

	wg.Wait()
}

// TestPersistentClientSendBeforeRecvRejected confirms that the client
// side enforces turn-based discipline. Two Sends in a row without an
// intervening Recv should fail fast.
func TestPersistentClientSendBeforeRecvRejected(t *testing.T) {
	tr := h2.NewWithConfig(h2.PersistentConfig{Config: h2.Config{AllowInsecure: true}})
	lis, err := tr.Listen(context.Background(), "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer lis.Close()
	go func() {
		c, err := lis.Accept(context.Background())
		if err != nil {
			return
		}
		defer c.Close()
		msg, err := c.Recv(context.Background())
		if err != nil {
			return
		}
		_ = c.Send(context.Background(), msg)
	}()

	addr := lis.(interface{ Addr() string }).Addr()
	conn, err := tr.Dial(context.Background(), "http://"+addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
	if err := conn.Send(context.Background(), []byte("one")); err != nil {
		t.Fatalf("Send(one): %v", err)
	}
	// Second Send without Recv should reject.
	err = conn.Send(context.Background(), []byte("two"))
	if err == nil {
		t.Fatal("expected error on second Send without Recv")
	}
	if !strings.Contains(err.Error(), "turn-based") {
		t.Errorf("error should mention turn-based discipline: %v", err)
	}
}

// TestPersistentClientRecvBeforeSendRejected is the mirror image: calling
// Recv without a prior Send should also fail fast.
func TestPersistentClientRecvBeforeSendRejected(t *testing.T) {
	tr := h2.NewWithConfig(h2.PersistentConfig{Config: h2.Config{AllowInsecure: true}})
	// We don't need a server — the error is local to the client.
	conn, err := tr.Dial(context.Background(), "http://127.0.0.1:1/")
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Recv(context.Background()); err == nil {
		t.Error("expected error for Recv without prior Send")
	}
}

// TestListenerClose confirms that Close unblocks Accept and that
// subsequent Accepts return errors.
func TestListenerClose(t *testing.T) {
	tr := h2.NewWithConfig(h2.PersistentConfig{Config: h2.Config{AllowInsecure: true}})
	lis, err := tr.Listen(context.Background(), "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	acceptDone := make(chan error, 1)
	go func() {
		_, e := lis.Accept(context.Background())
		acceptDone <- e
	}()
	// Give the goroutine a moment to block.
	time.Sleep(50 * time.Millisecond)
	if err := lis.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	select {
	case e := <-acceptDone:
		if e == nil {
			t.Error("Accept should return an error after Close")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Accept did not unblock after Close")
	}
}
