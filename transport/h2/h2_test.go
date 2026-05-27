package h2_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/semp-dev/semp-go/transport/h2"
)

// TestDialRefusesPlainHTTP confirms that the default (secure)
// configuration refuses plain http:// URLs per TRANSPORT.md §4.2
// ("Required (HTTPS only)"). AllowInsecure is the only way to opt
// out, and it's reserved for tests and local dev.
func TestDialRefusesPlainHTTP(t *testing.T) {
	_, err := h2.Dial(h2.Config{}, "http://example.com/v1/envelope")
	if err == nil {
		t.Fatal("expected error for plain http:// URL with default config")
	}
	if !strings.Contains(err.Error(), "non-https") {
		t.Errorf("error should mention non-https refusal: %v", err)
	}
}

// TestTransportDialRefusesNonHTTPSByDefault confirms that the default
// (secure) h2.Transport configuration refuses plain http:// URLs from
// Transport.Dial, matching the behavior of the low-level h2.Dial
// helper.
func TestTransportDialRefusesNonHTTPSByDefault(t *testing.T) {
	tr := h2.New()
	_, err := tr.Dial(context.Background(), "http://example.com/v1/envelope")
	if err == nil {
		t.Fatal("Transport.Dial should refuse non-https URL with default config")
	}
	if !strings.Contains(err.Error(), "non-https") {
		t.Errorf("error should mention non-https refusal: %v", err)
	}
}

// TestClientSessionIDThreading drives a three-POST conversation
// through one h2.Client. The server (a vanilla httptest server) sets
// Semp-Session-Id on the first response and verifies that subsequent
// POSTs carry it. This is the TRANSPORT.md §4.2.3 multi-POST
// handshake flow pattern.
func TestClientSessionIDThreading(t *testing.T) {
	type step struct {
		req         string
		expectedSID string
	}
	steps := []step{
		{req: `{"step":"init"}`, expectedSID: ""},
		{req: `{"step":"confirm"}`, expectedSID: "sess-1"},
		{req: `{"step":"ping"}`, expectedSID: "sess-1"},
	}
	var (
		mu        sync.Mutex
		callIndex int
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if callIndex >= len(steps) {
			t.Errorf("too many POSTs: %d", callIndex)
			http.Error(w, "too many", http.StatusBadRequest)
			return
		}
		want := steps[callIndex]
		body, _ := io.ReadAll(r.Body)
		if string(body) != want.req {
			t.Errorf("call %d: req = %q, want %q", callIndex, body, want.req)
		}
		if got := r.Header.Get(h2.HeaderSessionID); got != want.expectedSID {
			t.Errorf("call %d: %s = %q, want %q", callIndex, h2.HeaderSessionID, got, want.expectedSID)
		}
		callIndex++
		w.Header().Set("Content-Type", h2.ContentType)
		w.Header().Set(h2.HeaderSessionID, "sess-1")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	client, err := h2.Dial(h2.Config{AllowInsecure: true}, srv.URL)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	for i, s := range steps {
		if _, err := client.Do(context.Background(), []byte(s.req)); err != nil {
			t.Fatalf("Do[%d]: %v", i, err)
		}
	}
	if client.SessionID() != "sess-1" {
		t.Errorf("client SessionID = %q, want sess-1", client.SessionID())
	}
	mu.Lock()
	defer mu.Unlock()
	if callIndex != len(steps) {
		t.Errorf("server saw %d calls, want %d", callIndex, len(steps))
	}
}

// TestClientSurfacesNon2xxAsError confirms that the client treats any
// HTTP status outside [200,300) as a transport-level error, surfacing
// the response body in the error string so the caller can debug.
func TestClientSurfacesNon2xxAsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "database unavailable", http.StatusInternalServerError)
	}))
	defer srv.Close()

	client, err := h2.Dial(h2.Config{AllowInsecure: true}, srv.URL)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	_, err = client.Do(context.Background(), []byte(`{"x":1}`))
	if err == nil {
		t.Fatal("expected error from 500 response")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error should mention 500: %v", err)
	}
	if !strings.Contains(err.Error(), "database unavailable") {
		t.Errorf("error should include response body: %v", err)
	}
}

// TestClientRespectsContextDeadline confirms that a context with a
// short deadline cancels the Do call promptly rather than blocking
// on the HTTP client's default timeout.
func TestClientRespectsContextDeadline(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(5 * time.Second):
			_, _ = w.Write([]byte("too late"))
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()

	client, _ := h2.Dial(h2.Config{AllowInsecure: true}, srv.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := client.Do(ctx, []byte(`{"slow":true}`))
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected context deadline error")
	}
	if elapsed > 2*time.Second {
		t.Errorf("Do took %s, expected to return promptly on context cancel", elapsed)
	}
}

// TestClientCapturesSessionIDOnNon2xx confirms the session id capture
// happens BEFORE the status check. A structured rejection that
// includes a Semp-Session-Id should not strand the client without an
// id even though the call returns an error.
func TestClientCapturesSessionIDOnNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(h2.HeaderSessionID, "sess-rejected")
		http.Error(w, `{"reason_code":"policy_forbidden"}`, http.StatusBadRequest)
	}))
	defer srv.Close()

	client, _ := h2.Dial(h2.Config{AllowInsecure: true}, srv.URL)
	_, err := client.Do(context.Background(), []byte(`{"x":1}`))
	if err == nil {
		t.Fatal("expected error from 400 response")
	}
	if client.SessionID() != "sess-rejected" {
		t.Errorf("SessionID = %q, want sess-rejected", client.SessionID())
	}
}
