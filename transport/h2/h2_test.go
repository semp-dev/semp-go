package h2_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/semp-dev/semp-go/transport/h2"
)

// TestClientHandlerRoundTrip exercises a single POST through the
// NewHandler server-side helper and the Client client-side helper.
// The server echoes the request body back and assigns a session id.
func TestClientHandlerRoundTrip(t *testing.T) {
	handler := h2.NewHandler(h2.Config{AllowInsecure: true},
		func(ctx context.Context, req []byte, sid string) ([]byte, string, error) {
			if sid != "" {
				t.Errorf("first POST should carry no Semp-Session-Id, got %q", sid)
			}
			return req, "session-abc", nil
		})

	srv := httptest.NewServer(handler)
	defer srv.Close()

	client, err := h2.Dial(h2.Config{AllowInsecure: true}, srv.URL)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	body := []byte(`{"hello":"world"}`)
	resp, err := client.Do(context.Background(), body)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if string(resp) != string(body) {
		t.Errorf("echo mismatch: got %q want %q", resp, body)
	}
	if client.SessionID() != "session-abc" {
		t.Errorf("client did not capture session id: got %q want session-abc", client.SessionID())
	}
}

// TestClientSessionIDThreading drives a three-POST conversation
// through one Client and one NewHandler-backed server. The server
// verifies that the second and third POSTs carry the session id set
// on the first response. This is the TRANSPORT.md §4.2.3 multi-POST
// handshake flow pattern: each message is a separate round trip
// correlated by Semp-Session-Id.
func TestClientSessionIDThreading(t *testing.T) {
	type step struct {
		req          string
		expectedSID  string
		responseBody string
		responseSID  string
	}
	// Three sequential POSTs simulating init → response + sid,
	// confirm (carries sid), accepted, ack (carries sid).
	steps := []step{
		{req: `{"step":"init"}`, expectedSID: "", responseBody: `{"step":"response"}`, responseSID: "sess-1"},
		{req: `{"step":"confirm"}`, expectedSID: "sess-1", responseBody: `{"step":"accepted"}`, responseSID: "sess-1"},
		{req: `{"step":"ping"}`, expectedSID: "sess-1", responseBody: `{"step":"pong"}`, responseSID: "sess-1"},
	}
	var callIndex int
	var mu sync.Mutex
	handler := h2.NewHandler(h2.Config{AllowInsecure: true},
		func(ctx context.Context, req []byte, sid string) ([]byte, string, error) {
			mu.Lock()
			defer mu.Unlock()
			if callIndex >= len(steps) {
				t.Errorf("too many POSTs: %d", callIndex)
				return nil, "", nil
			}
			want := steps[callIndex]
			if string(req) != want.req {
				t.Errorf("call %d: req = %q, want %q", callIndex, req, want.req)
			}
			if sid != want.expectedSID {
				t.Errorf("call %d: sid = %q, want %q", callIndex, sid, want.expectedSID)
			}
			callIndex++
			return []byte(want.responseBody), want.responseSID, nil
		})
	srv := httptest.NewServer(handler)
	defer srv.Close()

	client, err := h2.Dial(h2.Config{AllowInsecure: true}, srv.URL)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	for i, step := range steps {
		resp, err := client.Do(context.Background(), []byte(step.req))
		if err != nil {
			t.Fatalf("Do[%d]: %v", i, err)
		}
		if string(resp) != step.responseBody {
			t.Errorf("Do[%d] response = %q, want %q", i, resp, step.responseBody)
		}
	}
	if callIndex != len(steps) {
		t.Errorf("handler call count = %d, want %d", callIndex, len(steps))
	}
}

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

// TestHandlerRejectsNonPOST confirms that GET requests get a 405.
func TestHandlerRejectsNonPOST(t *testing.T) {
	handler := h2.NewHandler(h2.Config{}, func(ctx context.Context, req []byte, sid string) ([]byte, string, error) {
		t.Error("handler should not be called for GET")
		return nil, "", nil
	})
	srv := httptest.NewServer(handler)
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", resp.StatusCode)
	}
}

// TestHandlerRejectsOversizedBody confirms that a body exceeding
// cfg.MaxBodyBytes is rejected with 413.
func TestHandlerRejectsOversizedBody(t *testing.T) {
	handler := h2.NewHandler(h2.Config{MaxBodyBytes: 16},
		func(ctx context.Context, req []byte, sid string) ([]byte, string, error) {
			t.Error("handler should not be called for oversized body")
			return nil, "", nil
		})
	srv := httptest.NewServer(handler)
	defer srv.Close()

	// Use a Dial+Do with a body bigger than the handler's limit.
	client, err := h2.Dial(h2.Config{AllowInsecure: true}, srv.URL)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	_, err = client.Do(context.Background(), []byte(`{"this":"payload","is":"too","long":"for","the":"handler","to":"accept"}`))
	if err == nil {
		t.Fatal("Do should have returned an error for oversized body")
	}
	if !strings.Contains(err.Error(), "413") {
		t.Errorf("error should mention 413: %v", err)
	}
}

// TestHandlerSurfacesErrorAs500 confirms that a HandlerFunc returning
// a non-nil error produces an HTTP 500 response with the error text.
func TestHandlerSurfacesErrorAs500(t *testing.T) {
	handler := h2.NewHandler(h2.Config{},
		func(ctx context.Context, req []byte, sid string) ([]byte, string, error) {
			return nil, "", &simpleError{msg: "database unavailable"}
		})
	srv := httptest.NewServer(handler)
	defer srv.Close()

	client, _ := h2.Dial(h2.Config{AllowInsecure: true}, srv.URL)
	_, err := client.Do(context.Background(), []byte(`{"x":1}`))
	if err == nil {
		t.Fatal("expected error from 500 response")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error should mention 500: %v", err)
	}
	if !strings.Contains(err.Error(), "database unavailable") {
		t.Errorf("error should include handler error text: %v", err)
	}
}

// TestClientRespectsContextDeadline confirms that a context with a
// short deadline cancels the Do call promptly rather than blocking
// on the HTTP client's default timeout.
func TestClientRespectsContextDeadline(t *testing.T) {
	// Handler that sleeps longer than the context deadline.
	handler := h2.NewHandler(h2.Config{},
		func(ctx context.Context, req []byte, sid string) ([]byte, string, error) {
			select {
			case <-time.After(5 * time.Second):
				return []byte("too late"), "", nil
			case <-ctx.Done():
				return nil, "", ctx.Err()
			}
		})
	srv := httptest.NewServer(handler)
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

// TestUnwiredTransportMethodsErrorCleanly confirms that
// h2.Transport.Dial and .Listen return a non-panicking error with a
// clear "not yet implemented" message. This pins the deferred-work
// documentation: future refactors that actually wire them up will
// update this test.
func TestUnwiredTransportMethodsErrorCleanly(t *testing.T) {
	tr := h2.New()
	if _, err := tr.Dial(context.Background(), "https://example.com/v1/envelope"); err == nil {
		t.Error("Transport.Dial should return an error")
	}
	if _, err := tr.Listen(context.Background(), ":0"); err == nil {
		t.Error("Transport.Listen should return an error")
	}
}

// TestRealSEMPLikeExchange drives a realistic-looking exchange
// through h2: the server parses the incoming JSON, constructs a
// response JSON with a new session id on the first POST, and
// validates the session id on subsequent POSTs. This exercises the
// "use Client+NewHandler to build a real SEMP flow" primary use case.
func TestRealSEMPLikeExchange(t *testing.T) {
	type envelope struct {
		Type string `json:"type"`
		Step string `json:"step"`
	}
	var (
		mu        sync.Mutex
		sessionID = "01JTESTH2SESSION00000000001"
		history   []string
	)
	handler := h2.NewHandler(h2.Config{AllowInsecure: true},
		func(ctx context.Context, req []byte, sid string) ([]byte, string, error) {
			var in envelope
			if err := json.Unmarshal(req, &in); err != nil {
				return nil, "", err
			}
			mu.Lock()
			history = append(history, in.Step)
			mu.Unlock()

			switch in.Step {
			case "init":
				resp, _ := json.Marshal(envelope{Type: "SEMP_HANDSHAKE", Step: "response"})
				return resp, sessionID, nil
			case "confirm":
				if sid != sessionID {
					return nil, "", &simpleError{msg: "missing session id"}
				}
				resp, _ := json.Marshal(envelope{Type: "SEMP_HANDSHAKE", Step: "accepted"})
				return resp, sessionID, nil
			}
			return nil, "", &simpleError{msg: "unknown step: " + in.Step}
		})
	srv := httptest.NewServer(handler)
	defer srv.Close()

	client, err := h2.Dial(h2.Config{AllowInsecure: true}, srv.URL)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}

	// Send init.
	initBody, _ := json.Marshal(envelope{Type: "SEMP_HANDSHAKE", Step: "init"})
	respRaw, err := client.Do(context.Background(), initBody)
	if err != nil {
		t.Fatalf("Do(init): %v", err)
	}
	var initResp envelope
	_ = json.Unmarshal(respRaw, &initResp)
	if initResp.Step != "response" {
		t.Errorf("init response step = %q, want response", initResp.Step)
	}
	if client.SessionID() != sessionID {
		t.Errorf("client did not capture session id after init")
	}

	// Send confirm. Client should automatically include the session id.
	confirmBody, _ := json.Marshal(envelope{Type: "SEMP_HANDSHAKE", Step: "confirm"})
	respRaw, err = client.Do(context.Background(), confirmBody)
	if err != nil {
		t.Fatalf("Do(confirm): %v", err)
	}
	var confirmResp envelope
	_ = json.Unmarshal(respRaw, &confirmResp)
	if confirmResp.Step != "accepted" {
		t.Errorf("confirm response step = %q, want accepted", confirmResp.Step)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(history) != 2 || history[0] != "init" || history[1] != "confirm" {
		t.Errorf("server history = %v, want [init confirm]", history)
	}
}

// simpleError is a tiny error type so the test doesn't need to
// import "errors" just for one use.
type simpleError struct{ msg string }

func (e *simpleError) Error() string { return e.msg }
