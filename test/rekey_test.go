package test

import (
	"context"
	"testing"
	"time"

	"github.com/semp-dev/semp-go/crypto"
	"github.com/semp-dev/semp-go/handshake"
	"github.com/semp-dev/semp-go/keys"
	"github.com/semp-dev/semp-go/session"
	"github.com/semp-dev/semp-go/transport/ws"
)

// TestRekeyClientRoundTrip drives a SEMP_REKEY exchange over a live
// client session and asserts:
//
//   1. The client's Rekey call succeeds.
//   2. After rekey, the client session ID is different and the
//      K_env_mac is different.
//   3. The rekey counter is 1 and LastRekeyAt is set.
//   4. Subsequent envelope submission over the same connection works
//      (i.e. the server's envMAC() picks up the new K_env_mac, not
//      the snapshot from handshake time).
//
// This is the milestone-3m acceptance test.
func TestRekeyClientRoundTrip(t *testing.T) {
	const (
		seed   = "test-rekey-client"
		domain = "example.com"
		alice  = "alice@example.com"
		bob    = "bob@example.com"
	)
	suite := crypto.SuiteBaseline

	srv := bringUpServer(t, seed, domain, []string{alice, bob})
	defer srv.close()

	wsTransport := ws.NewWithConfig(ws.Config{AllowInsecure: true})
	dialCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := wsTransport.Dial(dialCtx, srv.wsURL)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	store := newClientStore(t, seed, domain, alice, srv.store)
	identityFP := keys.Compute(mustIdentityPub(seed, alice))
	cli := handshake.NewClient(handshake.ClientConfig{
		Suite:         suite,
		Store:         store,
		Identity:      alice,
		IdentityKeyID: identityFP,
		ServerDomain:  domain,
	})
	defer cli.Erase()
	hsCtx, hsCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer hsCancel()
	clientSess, err := handshake.RunClient(hsCtx, conn, cli)
	if err != nil {
		t.Fatalf("RunClient: %v", err)
	}

	// Snapshot the state we expect to change.
	oldID := clientSess.ID
	oldEnvMAC := append([]byte(nil), clientSess.EnvMAC()...)

	// Run a rekey. The server side of the dispatch loop handles it
	// via session.RekeyHandler and swaps in the new keys on its
	// copy of the session.
	rekeyer := &session.Rekeyer{Suite: suite, Session: clientSess}
	if err := rekeyer.Rekey(hsCtx, conn); err != nil {
		t.Fatalf("Rekeyer.Rekey: %v", err)
	}

	// After rekey:
	if clientSess.ID == oldID {
		t.Error("client session ID did not change after rekey")
	}
	if bytesEqual(clientSess.EnvMAC(), oldEnvMAC) {
		t.Error("client K_env_mac did not change after rekey")
	}
	if clientSess.RekeyCount != 1 {
		t.Errorf("client RekeyCount = %d, want 1", clientSess.RekeyCount)
	}
	if clientSess.LastRekeyAt.IsZero() {
		t.Error("client LastRekeyAt is zero after rekey")
	}
	if clientSess.PreviousID != oldID {
		t.Errorf("client PreviousID = %s, want %s", clientSess.PreviousID, oldID)
	}
	if !clientSess.AcceptsID(oldID, time.Now()) {
		t.Error("client session should still accept the old ID inside the transition window")
	}

	// Submission after rekey must still work — this exercises the
	// server's envMAC() accessor picking up the fresh session MAC
	// key. We issue a minimal SEMP_KEYS request instead of a full
	// envelope submission because the CLI's compose path is already
	// exercised elsewhere and this test is specifically about rekey.
	fetcher := keys.NewFetcher(conn)
	req := keys.NewRequest("rekey-postfetch", []string{bob})
	resp, err := fetcher.FetchKeys(hsCtx, req)
	if err != nil {
		t.Fatalf("FetchKeys after rekey: %v", err)
	}
	if len(resp.Results) != 1 || resp.Results[0].Status != keys.StatusFound {
		t.Errorf("post-rekey FetchKeys returned %+v, want one found result", resp.Results)
	}
}

// TestRekeyRateLimit confirms that an immediate second rekey on the
// same session is rejected with reason_code rate_limited per
// SESSION.md §3.5 (MUST NOT rekey more than once per minute).
func TestRekeyRateLimit(t *testing.T) {
	const (
		seed   = "test-rekey-rate"
		domain = "example.com"
		alice  = "alice@example.com"
	)
	suite := crypto.SuiteBaseline

	srv := bringUpServer(t, seed, domain, []string{alice})
	defer srv.close()

	wsTransport := ws.NewWithConfig(ws.Config{AllowInsecure: true})
	dialCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := wsTransport.Dial(dialCtx, srv.wsURL)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	store := newClientStore(t, seed, domain, alice, srv.store)
	identityFP := keys.Compute(mustIdentityPub(seed, alice))
	cli := handshake.NewClient(handshake.ClientConfig{
		Suite:         suite,
		Store:         store,
		Identity:      alice,
		IdentityKeyID: identityFP,
		ServerDomain:  domain,
	})
	defer cli.Erase()
	hsCtx, hsCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer hsCancel()
	clientSess, err := handshake.RunClient(hsCtx, conn, cli)
	if err != nil {
		t.Fatalf("RunClient: %v", err)
	}

	rekeyer := &session.Rekeyer{Suite: suite, Session: clientSess}
	if err := rekeyer.Rekey(hsCtx, conn); err != nil {
		t.Fatalf("first rekey: %v", err)
	}

	// Second rekey immediately. The client side's CanRekey should
	// refuse it before even sending a message, but to exercise the
	// server-side rate limit we reset the client's LastRekeyAt to
	// zero so it sends the init; the server's RekeyHandler.Handle
	// will then reject with rate_limited.
	clientSess.LastRekeyAt = time.Time{}
	err = rekeyer.Rekey(hsCtx, conn)
	if err == nil {
		t.Fatal("second immediate rekey should have been rejected")
	}
	if !containsStr(err.Error(), "rate_limited") {
		t.Errorf("expected rate_limited, got: %v", err)
	}
}

// TestRekeyTransitionWindow exercises the session.AcceptsID helper
// directly: after rekey, the previous ID remains valid for
// TransitionWindow per SESSION.md §3.4.
func TestRekeyTransitionWindow(t *testing.T) {
	sess := session.New(session.RoleClient)
	sess.ID = "old-id"
	sess.State = session.StateActive
	sess.TTL = time.Hour
	sess.ExpiresAt = time.Now().Add(time.Hour)

	// Apply a rekey.
	now := time.Now()
	sess.ApplyRekey("new-id", nil, now)

	if sess.ID != "new-id" {
		t.Errorf("ID = %s, want new-id", sess.ID)
	}
	if sess.PreviousID != "old-id" {
		t.Errorf("PreviousID = %s, want old-id", sess.PreviousID)
	}
	// Inside the transition window both IDs are accepted.
	if !sess.AcceptsID("new-id", now.Add(1*time.Second)) {
		t.Error("new-id should be accepted inside the transition window")
	}
	if !sess.AcceptsID("old-id", now.Add(1*time.Second)) {
		t.Error("old-id should still be accepted inside the transition window")
	}
	// Outside the transition window, only the new ID is accepted.
	if sess.AcceptsID("old-id", now.Add(session.TransitionWindow+time.Second)) {
		t.Error("old-id should NOT be accepted after the transition window")
	}
	if !sess.AcceptsID("new-id", now.Add(session.TransitionWindow+time.Second)) {
		t.Error("new-id should still be accepted after the transition window")
	}
}

// TestRekeyCanRekeyLimits checks the CanRekey gating helper against
// each failure mode: inactive session, expired session, rate limited,
// and max count reached.
func TestRekeyCanRekeyLimits(t *testing.T) {
	now := time.Now()

	// Inactive.
	s := session.New(session.RoleClient)
	s.ID = "id"
	// No State set → StateInitial.
	if ok, _, _ := s.CanRekey(now); ok {
		t.Error("expected CanRekey to refuse an inactive session")
	}

	// Expired.
	s.State = session.StateActive
	s.ExpiresAt = now.Add(-time.Second)
	if ok, code, _ := s.CanRekey(now); ok || code != "session_expired" {
		t.Errorf("expired session: ok=%v code=%s", ok, code)
	}

	// Rate limit by recent rekey.
	s.ExpiresAt = now.Add(time.Hour)
	s.LastRekeyAt = now.Add(-10 * time.Second)
	if ok, code, _ := s.CanRekey(now); ok || code != "rate_limited" {
		t.Errorf("rate-limited session: ok=%v code=%s", ok, code)
	}

	// Max count reached.
	s.LastRekeyAt = time.Time{}
	s.RekeyCount = session.MaxRekeysPerSession
	if ok, code, _ := s.CanRekey(now); ok || code != "rate_limited" {
		t.Errorf("max rekeys reached: ok=%v code=%s", ok, code)
	}

	// Happy path.
	s.RekeyCount = 0
	if ok, _, _ := s.CanRekey(now); !ok {
		t.Error("expected CanRekey to allow a fresh, active session")
	}
}

// containsStr is a case-sensitive substring helper used by
// TestRekeyRateLimit.
func containsStr(haystack, needle string) bool {
	if needle == "" {
		return true
	}
	if len(haystack) < len(needle) {
		return false
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

