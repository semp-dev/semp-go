package ws_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/semp-dev/semp-go/transport/ws"
)

// TestDialRefusesNonWSSEndpoint confirms that the default Transport
// (AllowInsecure=false) refuses to dial a plain ws:// URL: production
// deployments MUST use wss:// per TRANSPORT.md §4.1.
func TestDialRefusesNonWSSEndpoint(t *testing.T) {
	tr := ws.New() // default config: AllowInsecure = false
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := tr.Dial(ctx, "ws://127.0.0.1:1/v1/ws")
	if err == nil {
		t.Fatal("Dial accepted a plain ws:// URL with AllowInsecure=false")
	}
	if !strings.Contains(err.Error(), "non-wss") {
		t.Errorf("expected 'non-wss' refusal, got: %v", err)
	}
}

// TestDialEmptyEndpointRejected confirms the Dial-time guard on empty
// endpoints. Trivial but cheap to assert.
func TestDialEmptyEndpointRejected(t *testing.T) {
	tr := ws.NewWithConfig(ws.Config{AllowInsecure: true})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := tr.Dial(ctx, "")
	if err == nil {
		t.Fatal("Dial accepted empty endpoint")
	}
}

// TestDialRequiresSempV1Subprotocol confirms that a server which
// completes the WebSocket upgrade WITHOUT confirming the `semp.v1`
// subprotocol is rejected by the client per TRANSPORT.md §4.1.1.
//
// We mount a vanilla coder/websocket handler with no Subprotocols
// configured, so the server accepts the upgrade but does not echo
// `semp.v1` in Sec-WebSocket-Protocol. Dial MUST surface this as a
// "subprotocol not confirmed" error rather than returning a Conn
// that would later misbehave.
func TestDialRequiresSempV1Subprotocol(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			// Subprotocols deliberately empty so the server does not
			// confirm semp.v1 in its upgrade response.
		})
		if err != nil {
			return
		}
		// Hold the connection open just long enough for the client to
		// inspect Sec-WebSocket-Protocol before tearing down.
		_ = c.Close(websocket.StatusNormalClosure, "test done")
	}))
	defer srv.Close()

	wsURL := "ws://" + strings.TrimPrefix(srv.URL, "http://")
	tr := ws.NewWithConfig(ws.Config{AllowInsecure: true})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := tr.Dial(ctx, wsURL)
	if err == nil {
		t.Fatal("Dial accepted a server that did not confirm semp.v1")
	}
	if !strings.Contains(err.Error(), "subprotocol") {
		t.Errorf("error should mention subprotocol mismatch: %v", err)
	}
}
