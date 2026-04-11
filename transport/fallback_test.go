package transport_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/semp-dev/semp-go/transport"
)

// -----------------------------------------------------------------------------
// Test fixtures: fakeTransport and fakeConn
// -----------------------------------------------------------------------------

// fakeTransport is an in-memory transport.Transport used by the
// fallback tests. Its Dial behavior is controlled by a dialFunc
// closure so individual tests can plug in success, failure, delay,
// or context-aware behavior without standing up real network sockets.
type fakeTransport struct {
	id       transport.ID
	dialFunc func(ctx context.Context, endpoint string) (transport.Conn, error)
	// dialCount counts how many times Dial has been invoked. Tests
	// use this to assert sequential-not-concurrent attempt ordering.
	dialCount atomic.Int32
}

func (f *fakeTransport) ID() transport.ID              { return f.id }
func (f *fakeTransport) Profiles() transport.Profile   { return transport.ProfileBoth }
func (f *fakeTransport) Dial(ctx context.Context, endpoint string) (transport.Conn, error) {
	f.dialCount.Add(1)
	if f.dialFunc != nil {
		return f.dialFunc(ctx, endpoint)
	}
	return nil, errors.New("fakeTransport: no dialFunc configured")
}
func (f *fakeTransport) Listen(context.Context, string) (transport.Listener, error) {
	return nil, errors.New("fakeTransport: Listen not supported")
}

// fakeConn is a minimal transport.Conn that remembers its origin
// transport ID so tests can confirm which candidate actually won.
type fakeConn struct {
	id   transport.ID
	peer string
}

func (c *fakeConn) Send(context.Context, []byte) error          { return nil }
func (c *fakeConn) Recv(context.Context) ([]byte, error)        { return nil, nil }
func (c *fakeConn) Close() error                                { return nil }
func (c *fakeConn) Peer() string                                { return c.peer }

// succeedWith returns a dialFunc that always produces a fakeConn
// tagged with the given id and endpoint.
func succeedWith(id transport.ID) func(context.Context, string) (transport.Conn, error) {
	return func(_ context.Context, endpoint string) (transport.Conn, error) {
		return &fakeConn{id: id, peer: endpoint}, nil
	}
}

// failWith returns a dialFunc that always returns the given error.
func failWith(msg string) func(context.Context, string) (transport.Conn, error) {
	err := errors.New(msg)
	return func(context.Context, string) (transport.Conn, error) {
		return nil, err
	}
}

// stallUntilCtx returns a dialFunc that blocks until its dial context
// is canceled, then returns the context error. Useful for timeout and
// cancellation tests.
func stallUntilCtx() func(context.Context, string) (transport.Conn, error) {
	return func(ctx context.Context, _ string) (transport.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
}

// -----------------------------------------------------------------------------
// Order
// -----------------------------------------------------------------------------

// TestOrderRecommendedPriority confirms Order sorts candidates into
// QUIC > WebSocket > HTTP/2 > gRPC, preserving the relative order of
// duplicates (multiple endpoints for the same transport).
func TestOrderRecommendedPriority(t *testing.T) {
	ws := &fakeTransport{id: transport.IDWebSocket}
	h2 := &fakeTransport{id: transport.IDHTTP2}
	quic := &fakeTransport{id: transport.IDQUIC}
	// Mixed input order.
	in := []transport.Candidate{
		{Transport: h2, Endpoint: "h2-1"},
		{Transport: ws, Endpoint: "ws-1"},
		{Transport: quic, Endpoint: "quic-1"},
		{Transport: ws, Endpoint: "ws-2"},
	}
	out := transport.Order(in)
	wantIDs := []transport.ID{
		transport.IDQUIC,
		transport.IDWebSocket, // ws-1
		transport.IDWebSocket, // ws-2 (duplicate preserved)
		transport.IDHTTP2,
	}
	if len(out) != len(wantIDs) {
		t.Fatalf("len(out) = %d, want %d", len(out), len(wantIDs))
	}
	for i, c := range out {
		if c.ID() != wantIDs[i] {
			t.Errorf("out[%d].ID = %s, want %s", i, c.ID(), wantIDs[i])
		}
	}
	// The two ws entries must retain their original order.
	if out[1].Endpoint != "ws-1" || out[2].Endpoint != "ws-2" {
		t.Errorf("ws duplicate order not preserved: %q %q",
			out[1].Endpoint, out[2].Endpoint)
	}
}

// TestOrderUnknownTransportsGoLast confirms transports not in the
// recommended list are appended after recommended ones in input order.
func TestOrderUnknownTransportsGoLast(t *testing.T) {
	ws := &fakeTransport{id: transport.IDWebSocket}
	custom := &fakeTransport{id: transport.ID("my.custom/v1")}
	in := []transport.Candidate{
		{Transport: custom, Endpoint: "custom-1"},
		{Transport: ws, Endpoint: "ws-1"},
	}
	out := transport.Order(in)
	if len(out) != 2 {
		t.Fatalf("len(out) = %d, want 2", len(out))
	}
	if out[0].ID() != transport.IDWebSocket || out[1].ID() != "my.custom/v1" {
		t.Errorf("unknown transport should be last; got %s, %s",
			out[0].ID(), out[1].ID())
	}
}

// TestOrderEmpty confirms Order(nil) and Order([]) return nil/empty.
func TestOrderEmpty(t *testing.T) {
	if got := transport.Order(nil); got != nil {
		t.Errorf("Order(nil) = %v, want nil", got)
	}
	if got := transport.Order([]transport.Candidate{}); got != nil {
		t.Errorf("Order([]) = %v, want nil", got)
	}
}

// -----------------------------------------------------------------------------
// Fallback
// -----------------------------------------------------------------------------

// TestFallbackFirstSucceeds confirms the happy path: the first
// candidate succeeds, the second is never tried.
func TestFallbackFirstSucceeds(t *testing.T) {
	first := &fakeTransport{id: transport.IDWebSocket, dialFunc: succeedWith(transport.IDWebSocket)}
	second := &fakeTransport{id: transport.IDHTTP2, dialFunc: failWith("should not be tried")}
	conn, err := transport.Fallback(context.Background(), []transport.Candidate{
		{Transport: first, Endpoint: "wss://first"},
		{Transport: second, Endpoint: "https://second"},
	})
	if err != nil {
		t.Fatalf("Fallback: %v", err)
	}
	if conn == nil {
		t.Fatal("Fallback returned nil Conn without error")
	}
	if fc, ok := conn.(*fakeConn); !ok || fc.id != transport.IDWebSocket {
		t.Errorf("returned conn id = %v, want ws", conn)
	}
	if got := second.dialCount.Load(); got != 0 {
		t.Errorf("second transport was dialed %d times, want 0", got)
	}
}

// TestFallbackSecondSucceeds confirms the first candidate's failure
// causes a sequential move to the second, which succeeds.
func TestFallbackSecondSucceeds(t *testing.T) {
	first := &fakeTransport{id: transport.IDWebSocket, dialFunc: failWith("refused")}
	second := &fakeTransport{id: transport.IDHTTP2, dialFunc: succeedWith(transport.IDHTTP2)}
	conn, err := transport.Fallback(context.Background(), []transport.Candidate{
		{Transport: first, Endpoint: "wss://first"},
		{Transport: second, Endpoint: "https://second"},
	})
	if err != nil {
		t.Fatalf("Fallback: %v", err)
	}
	if fc, ok := conn.(*fakeConn); !ok || fc.id != transport.IDHTTP2 {
		t.Errorf("returned conn id = %v, want h2", conn)
	}
	if got := first.dialCount.Load(); got != 1 {
		t.Errorf("first transport dialed %d times, want 1", got)
	}
	if got := second.dialCount.Load(); got != 1 {
		t.Errorf("second transport dialed %d times, want 1", got)
	}
}

// TestFallbackAllFailReturnsFallbackError confirms exhausted candidates
// produce a *FallbackError with one Attempt per candidate.
func TestFallbackAllFailReturnsFallbackError(t *testing.T) {
	ws := &fakeTransport{id: transport.IDWebSocket, dialFunc: failWith("connection refused")}
	h2 := &fakeTransport{id: transport.IDHTTP2, dialFunc: failWith("timeout")}
	_, err := transport.Fallback(context.Background(), []transport.Candidate{
		{Transport: ws, Endpoint: "wss://a"},
		{Transport: h2, Endpoint: "https://a"},
	})
	if err == nil {
		t.Fatal("expected error from exhausted candidates")
	}
	var fe *transport.FallbackError
	if !errors.As(err, &fe) {
		t.Fatalf("expected *FallbackError, got %T: %v", err, err)
	}
	if len(fe.Attempts) != 2 {
		t.Errorf("Attempts length = %d, want 2", len(fe.Attempts))
	}
	if fe.Attempts[0].Candidate.ID() != transport.IDWebSocket {
		t.Errorf("Attempt[0] ID = %s, want ws", fe.Attempts[0].Candidate.ID())
	}
	if fe.Attempts[1].Candidate.ID() != transport.IDHTTP2 {
		t.Errorf("Attempt[1] ID = %s, want h2", fe.Attempts[1].Candidate.ID())
	}
	// Error message should summarize every attempt on one line.
	if got := err.Error(); !strings.Contains(got, "connection refused") || !strings.Contains(got, "timeout") {
		t.Errorf("error message should summarize each attempt: %v", err)
	}
}

// TestFallbackEmptyCandidates confirms nil/empty candidate lists return
// an error without trying to dial anything.
func TestFallbackEmptyCandidates(t *testing.T) {
	_, err := transport.Fallback(context.Background(), nil)
	if err == nil {
		t.Error("Fallback(nil) should return an error")
	}
	_, err = transport.Fallback(context.Background(), []transport.Candidate{})
	if err == nil {
		t.Error("Fallback([]) should return an error")
	}
}

// TestFallbackNilTransportInCandidate confirms a candidate with a nil
// Transport is skipped (recorded as a failure) rather than panicking.
func TestFallbackNilTransportInCandidate(t *testing.T) {
	good := &fakeTransport{id: transport.IDWebSocket, dialFunc: succeedWith(transport.IDWebSocket)}
	conn, err := transport.Fallback(context.Background(), []transport.Candidate{
		{Transport: nil, Endpoint: "wss://nope"},
		{Transport: good, Endpoint: "wss://yes"},
	})
	if err != nil {
		t.Fatalf("Fallback: %v", err)
	}
	if conn == nil {
		t.Fatal("expected non-nil Conn after skipping nil candidate")
	}
}

// TestFallbackSequentialNotConcurrent confirms the TRANSPORT.md §5.4
// MUST-sequential rule: the second candidate's Dial is never invoked
// while the first candidate's Dial is still running.
func TestFallbackSequentialNotConcurrent(t *testing.T) {
	var (
		firstActive  atomic.Bool
		overlapSeen  atomic.Bool
	)
	first := &fakeTransport{id: transport.IDWebSocket}
	second := &fakeTransport{id: transport.IDHTTP2}
	first.dialFunc = func(_ context.Context, _ string) (transport.Conn, error) {
		firstActive.Store(true)
		time.Sleep(50 * time.Millisecond)
		firstActive.Store(false)
		return nil, errors.New("first fails")
	}
	second.dialFunc = func(_ context.Context, _ string) (transport.Conn, error) {
		if firstActive.Load() {
			overlapSeen.Store(true)
		}
		return &fakeConn{id: transport.IDHTTP2}, nil
	}
	_, err := transport.Fallback(context.Background(), []transport.Candidate{
		{Transport: first, Endpoint: "wss://x"},
		{Transport: second, Endpoint: "https://x"},
	})
	if err != nil {
		t.Fatalf("Fallback: %v", err)
	}
	if overlapSeen.Load() {
		t.Error("second candidate was dialed while first was still running — concurrent attempt detected")
	}
}

// TestFallbackPerCandidateTimeout confirms that a stalled candidate
// doesn't block forever — the fallback timeout moves us on.
func TestFallbackPerCandidateTimeout(t *testing.T) {
	// Override the fallback timeout via a stalled candidate that
	// respects its per-call ctx. We use a tiny overall parent context
	// so the stalled candidate's 10s per-candidate timeout never
	// dominates the test runtime.
	stalled := &fakeTransport{id: transport.IDWebSocket, dialFunc: stallUntilCtx()}
	quick := &fakeTransport{id: transport.IDHTTP2, dialFunc: succeedWith(transport.IDHTTP2)}

	// Give the caller context 30s so it's not the bottleneck.
	// The stalled candidate will only give up when its per-dial
	// context-with-timeout hits FallbackTimeout — which is 10s.
	// We shortcut by using a short parent deadline instead: the
	// parent ctx deadline gets inherited into the per-dial timeout,
	// so the stalled candidate returns as soon as the parent fires.
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err := transport.Fallback(ctx, []transport.Candidate{
		{Transport: stalled, Endpoint: "wss://slow"},
		{Transport: quick, Endpoint: "https://fast"},
	})
	// We expect the stalled candidate's per-dial ctx to fire, the
	// loop to record the failure, then the ctx-canceled check before
	// the second dial to abort the whole Fallback. The returned
	// error wraps ctx.DeadlineExceeded via *FallbackError.
	if err == nil {
		t.Fatal("expected timeout error")
	}
	var fe *transport.FallbackError
	if !errors.As(err, &fe) {
		t.Fatalf("expected *FallbackError, got %T: %v", err, err)
	}
	// The stalled candidate MUST be the first recorded attempt.
	if len(fe.Attempts) == 0 || fe.Attempts[0].Candidate.ID() != transport.IDWebSocket {
		t.Errorf("first recorded attempt should be the stalled ws candidate: %+v", fe.Attempts)
	}
}

// TestFallbackContextCanceledBeforeDial confirms a pre-canceled
// context returns the ctx error immediately without any dial attempt.
func TestFallbackContextCanceledBeforeDial(t *testing.T) {
	never := &fakeTransport{id: transport.IDWebSocket, dialFunc: failWith("should not be called")}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel up-front
	_, err := transport.Fallback(ctx, []transport.Candidate{
		{Transport: never, Endpoint: "wss://x"},
	})
	if err == nil {
		t.Fatal("expected error for pre-canceled context")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("error should be context.Canceled, got %v", err)
	}
	if got := never.dialCount.Load(); got != 0 {
		t.Errorf("never transport was dialed %d times, want 0", got)
	}
}

// TestFallbackErrorIsUnwrap confirms errors.Is can find a specific
// underlying error across the FallbackError's attempts.
func TestFallbackErrorIsUnwrap(t *testing.T) {
	sentinel := errors.New("my-sentinel")
	t1 := &fakeTransport{id: transport.IDWebSocket, dialFunc: failWith("refused")}
	t2 := &fakeTransport{
		id: transport.IDHTTP2,
		dialFunc: func(context.Context, string) (transport.Conn, error) {
			return nil, sentinel
		},
	}
	_, err := transport.Fallback(context.Background(), []transport.Candidate{
		{Transport: t1, Endpoint: "a"},
		{Transport: t2, Endpoint: "b"},
	})
	if !errors.Is(err, sentinel) {
		t.Errorf("errors.Is(err, sentinel) = false; want true")
	}
}

// -----------------------------------------------------------------------------
// FallbackCache
// -----------------------------------------------------------------------------

// TestFallbackCacheRememberLookup confirms Remember persists an entry
// that Lookup can retrieve while the TTL is live.
func TestFallbackCacheRememberLookup(t *testing.T) {
	cache := transport.NewFallbackCache(time.Minute, nil)
	cache.Remember("example.com", transport.IDWebSocket, "wss://example.com/v1/ws")
	id, endpoint, ok := cache.Lookup("example.com")
	if !ok {
		t.Fatal("Lookup returned ok=false for live entry")
	}
	if id != transport.IDWebSocket {
		t.Errorf("id = %s, want ws", id)
	}
	if endpoint != "wss://example.com/v1/ws" {
		t.Errorf("endpoint = %q, want wss://example.com/v1/ws", endpoint)
	}
}

// TestFallbackCacheCaseInsensitive confirms domain keys are normalized.
func TestFallbackCacheCaseInsensitive(t *testing.T) {
	cache := transport.NewFallbackCache(time.Minute, nil)
	cache.Remember("Example.COM", transport.IDWebSocket, "wss://e/ws")
	if _, _, ok := cache.Lookup("EXAMPLE.com"); !ok {
		t.Error("Lookup(EXAMPLE.com) failed after Remember(Example.COM)")
	}
}

// TestFallbackCacheExpiry confirms entries past their TTL are treated
// as absent and evicted on read.
func TestFallbackCacheExpiry(t *testing.T) {
	now := time.Now()
	clock := now
	cache := transport.NewFallbackCache(time.Minute, func() time.Time { return clock })
	cache.Remember("example.com", transport.IDWebSocket, "wss://x")
	clock = now.Add(2 * time.Minute)
	if _, _, ok := cache.Lookup("example.com"); ok {
		t.Error("Lookup returned ok=true for expired entry")
	}
	// And the expired entry should have been evicted.
	if n := cache.Len(); n != 0 {
		t.Errorf("Len after expiry = %d, want 0", n)
	}
}

// TestFallbackCacheInvalidate drops an entry explicitly.
func TestFallbackCacheInvalidate(t *testing.T) {
	cache := transport.NewFallbackCache(time.Minute, nil)
	cache.Remember("example.com", transport.IDWebSocket, "wss://x")
	cache.Invalidate("example.com")
	if _, _, ok := cache.Lookup("example.com"); ok {
		t.Error("Lookup returned ok=true after Invalidate")
	}
}

// TestFallbackCacheNilSafe confirms methods on a nil *FallbackCache
// are no-ops that don't panic.
func TestFallbackCacheNilSafe(t *testing.T) {
	var cache *transport.FallbackCache
	cache.Remember("example.com", transport.IDWebSocket, "x")
	if _, _, ok := cache.Lookup("example.com"); ok {
		t.Error("nil cache Lookup returned ok=true")
	}
	cache.Invalidate("example.com")
	if n := cache.Len(); n != 0 {
		t.Errorf("nil cache Len = %d, want 0", n)
	}
}

// -----------------------------------------------------------------------------
// CachedFallback
// -----------------------------------------------------------------------------

// TestCachedFallbackUsesCacheFirst confirms the cached transport is
// moved to the head of the dial list.
func TestCachedFallbackUsesCacheFirst(t *testing.T) {
	cache := transport.NewFallbackCache(time.Minute, nil)
	cache.Remember("example.com", transport.IDHTTP2, "https://x")

	// Candidate list is ws first, h2 second. Without cache, ws would
	// be tried first. With the h2 cache hint, h2 should be tried
	// first.
	var order sync.Mutex
	var dialOrder []transport.ID
	record := func(id transport.ID) func(context.Context, string) (transport.Conn, error) {
		return func(_ context.Context, endpoint string) (transport.Conn, error) {
			order.Lock()
			dialOrder = append(dialOrder, id)
			order.Unlock()
			return &fakeConn{id: id, peer: endpoint}, nil
		}
	}
	ws := &fakeTransport{id: transport.IDWebSocket, dialFunc: record(transport.IDWebSocket)}
	h2 := &fakeTransport{id: transport.IDHTTP2, dialFunc: record(transport.IDHTTP2)}

	conn, err := transport.CachedFallback(context.Background(), cache, "example.com", []transport.Candidate{
		{Transport: ws, Endpoint: "wss://x"},
		{Transport: h2, Endpoint: "https://x"},
	})
	if err != nil {
		t.Fatalf("CachedFallback: %v", err)
	}
	if fc, ok := conn.(*fakeConn); !ok || fc.id != transport.IDHTTP2 {
		t.Errorf("returned conn id = %v, want h2 (cached)", conn)
	}
	if len(dialOrder) != 1 || dialOrder[0] != transport.IDHTTP2 {
		t.Errorf("dial order = %v, want [h2] first", dialOrder)
	}
}

// TestCachedFallbackInvalidatesOnTotalFailure confirms that when the
// cached transport fails AND every other candidate also fails, the
// cache entry is dropped.
func TestCachedFallbackInvalidatesOnTotalFailure(t *testing.T) {
	cache := transport.NewFallbackCache(time.Minute, nil)
	cache.Remember("example.com", transport.IDHTTP2, "https://x")

	ws := &fakeTransport{id: transport.IDWebSocket, dialFunc: failWith("ws down")}
	h2 := &fakeTransport{id: transport.IDHTTP2, dialFunc: failWith("h2 down")}

	_, err := transport.CachedFallback(context.Background(), cache, "example.com", []transport.Candidate{
		{Transport: ws, Endpoint: "wss://x"},
		{Transport: h2, Endpoint: "https://x"},
	})
	if err == nil {
		t.Fatal("expected error from all-fail CachedFallback")
	}
	if _, _, ok := cache.Lookup("example.com"); ok {
		t.Error("cache entry should have been invalidated after total failure")
	}
}

// TestCachedFallbackRemembersActualSuccess confirms the cache records
// whichever candidate actually worked — even if the cache hint was
// stale and the successful candidate was further down the list.
func TestCachedFallbackRemembersActualSuccess(t *testing.T) {
	cache := transport.NewFallbackCache(time.Minute, nil)
	// Stale hint: cache says QUIC works, but QUIC is currently down.
	cache.Remember("example.com", transport.IDQUIC, "quic://x")

	quic := &fakeTransport{id: transport.IDQUIC, dialFunc: failWith("quic blocked")}
	ws := &fakeTransport{id: transport.IDWebSocket, dialFunc: succeedWith(transport.IDWebSocket)}

	conn, err := transport.CachedFallback(context.Background(), cache, "example.com", []transport.Candidate{
		{Transport: quic, Endpoint: "quic://x"},
		{Transport: ws, Endpoint: "wss://x"},
	})
	if err != nil {
		t.Fatalf("CachedFallback: %v", err)
	}
	if fc, ok := conn.(*fakeConn); !ok || fc.id != transport.IDWebSocket {
		t.Errorf("returned conn id = %v, want ws", conn)
	}
	// Cache should now reflect the ACTUALLY successful transport.
	id, _, ok := cache.Lookup("example.com")
	if !ok {
		t.Fatal("cache should have been refreshed after partial success")
	}
	if id != transport.IDWebSocket {
		t.Errorf("cached id = %s, want ws (actual success)", id)
	}
}

// TestCachedFallbackNilCacheFallsThrough confirms a nil cache is
// equivalent to calling Fallback directly.
func TestCachedFallbackNilCacheFallsThrough(t *testing.T) {
	ws := &fakeTransport{id: transport.IDWebSocket, dialFunc: succeedWith(transport.IDWebSocket)}
	conn, err := transport.CachedFallback(context.Background(), nil, "example.com", []transport.Candidate{
		{Transport: ws, Endpoint: "wss://x"},
	})
	if err != nil {
		t.Fatalf("CachedFallback: %v", err)
	}
	if conn == nil {
		t.Fatal("nil cache should not break Fallback")
	}
}
