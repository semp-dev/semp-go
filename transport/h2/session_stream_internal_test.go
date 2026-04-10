package h2

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestSessionHubPushRespectsContext uses the unexported register hook
// to install a push channel without a handler draining it, so we can
// exercise Push's context-cancellation behavior when the channel is
// saturated. This path cannot be tested through NewSessionStreamHandler
// because the handler drains the channel as fast as Push fills it.
func TestSessionHubPushRespectsContext(t *testing.T) {
	hub := NewSessionHub(1)
	sid := "01JSESSHUBCTX"
	ch, err := hub.register(sid)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	defer hub.unregister(sid, ch)

	// First push fits in the cap-1 buffer.
	if err := hub.Push(context.Background(), sid, []byte("first")); err != nil {
		t.Fatalf("first Push: %v", err)
	}

	// Second push must block on the full channel. Cancel its
	// context and confirm Push returns context.Canceled.
	pushCtx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- hub.Push(pushCtx, sid, []byte("second"))
	}()
	// Give the goroutine a moment to park on the channel send.
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Push error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Push did not unblock after context cancel")
	}
}

// TestSessionHubDuplicateRegister exercises the ErrStreamBusy path
// directly without needing two HTTP clients.
func TestSessionHubDuplicateRegister(t *testing.T) {
	hub := NewSessionHub(4)
	sid := "01JSESSHUBDUP"
	ch, err := hub.register(sid)
	if err != nil {
		t.Fatalf("first register: %v", err)
	}
	defer hub.unregister(sid, ch)
	if _, err := hub.register(sid); !errors.Is(err, ErrStreamBusy) {
		t.Errorf("duplicate register = %v, want ErrStreamBusy", err)
	}
	// After unregister, a new register should succeed.
	hub.unregister(sid, ch)
	ch2, err := hub.register(sid)
	if err != nil {
		t.Fatalf("re-register after unregister: %v", err)
	}
	hub.unregister(sid, ch2)
}

// TestSessionHubUnregisterStale confirms that an unregister call with
// a stale channel reference (after the session has been re-opened) is
// a no-op and does not disturb the currently-registered stream.
func TestSessionHubUnregisterStale(t *testing.T) {
	hub := NewSessionHub(4)
	sid := "01JSESSHUBSTALE"
	ch1, err := hub.register(sid)
	if err != nil {
		t.Fatalf("register 1: %v", err)
	}
	hub.unregister(sid, ch1) // removes ch1
	ch2, err := hub.register(sid)
	if err != nil {
		t.Fatalf("register 2: %v", err)
	}
	// Stale unregister with ch1 must not remove ch2.
	hub.unregister(sid, ch1)
	if !hub.Active(sid) {
		t.Error("stale unregister removed the live stream")
	}
	hub.unregister(sid, ch2)
}
