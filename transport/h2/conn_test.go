package h2_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"semp.dev/semp-go/transport/h2"
)

// TestPersistentConnTurnBased confirms the client-side Conn returned
// by Transport.Dial enforces the strict Send -> Recv -> Send -> Recv
// alternation pattern documented in TRANSPORT.md §4.2.3.
//
// The server is a vanilla httptest server that echoes the request
// body back; the test exercises two full round trips.
func TestPersistentConnTurnBased(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", h2.ContentType)
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	tr := h2.NewWithConfig(h2.Config{AllowInsecure: true})
	conn, err := tr.Dial(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	for i, in := range []string{"hello", "world"} {
		if err := conn.Send(context.Background(), []byte(in)); err != nil {
			t.Fatalf("Send[%d]: %v", i, err)
		}
		got, err := conn.Recv(context.Background())
		if err != nil {
			t.Fatalf("Recv[%d]: %v", i, err)
		}
		if string(got) != in {
			t.Errorf("Recv[%d] = %q, want %q", i, got, in)
		}
	}

	if conn.Peer() == "" {
		t.Error("Peer() returned empty string")
	}
}

// TestPersistentConnSendBeforeRecvRejected confirms that two Sends in
// a row without an intervening Recv fail fast.
func TestPersistentConnSendBeforeRecvRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	tr := h2.NewWithConfig(h2.Config{AllowInsecure: true})
	conn, err := tr.Dial(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	if err := conn.Send(context.Background(), []byte("one")); err != nil {
		t.Fatalf("Send(one): %v", err)
	}
	err = conn.Send(context.Background(), []byte("two"))
	if err == nil {
		t.Fatal("expected error on second Send without intervening Recv")
	}
	if !strings.Contains(err.Error(), "turn-based") {
		t.Errorf("error should mention turn-based discipline: %v", err)
	}
}

// TestPersistentConnRecvBeforeSendRejected is the mirror image:
// calling Recv without a prior Send must also fail fast. No server is
// needed since the error is local to the client.
func TestPersistentConnRecvBeforeSendRejected(t *testing.T) {
	tr := h2.NewWithConfig(h2.Config{AllowInsecure: true})
	conn, err := tr.Dial(context.Background(), "http://127.0.0.1:1/")
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Recv(context.Background()); err == nil {
		t.Error("expected error for Recv without prior Send")
	}
}

// TestPersistentConnCloseUnblocksOps confirms Close puts the Conn
// into a state where subsequent Send / Recv calls return errors
// rather than silently doing nothing.
func TestPersistentConnCloseUnblocksOps(t *testing.T) {
	tr := h2.NewWithConfig(h2.Config{AllowInsecure: true})
	conn, err := tr.Dial(context.Background(), "http://127.0.0.1:1/")
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	if err := conn.Send(context.Background(), []byte("after-close")); err == nil {
		t.Error("Send after Close should error")
	}
	if _, err := conn.Recv(context.Background()); err == nil {
		t.Error("Recv after Close should error")
	}
}
