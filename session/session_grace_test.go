package session_test

import (
	"testing"
	"time"

	"semp.dev/semp-go/clockskew"
	"semp.dev/semp-go/session"
)

func freshActiveSession(expiresAt time.Time) *session.Session {
	return &session.Session{
		ID:        "01JTEST00000000000000000001",
		State:     session.StateActive,
		ExpiresAt: expiresAt,
		TTL:       time.Hour,
	}
}

// TestActiveStrictRejectsPastExpiry confirms the strict (sender-
// side) Active treats a session as inactive the moment now > ExpiresAt.
func TestActiveStrictRejectsPastExpiry(t *testing.T) {
	now := time.Now().UTC()
	s := freshActiveSession(now.Add(-time.Second))
	if s.Active(now) {
		t.Error("strict Active accepted now > ExpiresAt; senders MUST NOT rely on grace")
	}
}

// TestActiveWithGraceAcceptsWithinWindow confirms the receiver-
// side variant accepts up to ExpiresAt + grace.
func TestActiveWithGraceAcceptsWithinWindow(t *testing.T) {
	now := time.Now().UTC()
	// Session expired 5 minutes ago; well inside the 15-min grace.
	s := freshActiveSession(now.Add(-5 * time.Minute))
	if !s.ActiveWithGrace(now, clockskew.Default().Grace) {
		t.Error("receiver-side ActiveWithGrace rejected session within §4.4 grace window")
	}
}

// TestActiveWithGraceRejectsBeyondWindow confirms past the grace
// window the session is treated as expired.
func TestActiveWithGraceRejectsBeyondWindow(t *testing.T) {
	now := time.Now().UTC()
	// Session expired 30 minutes ago; well past the 15-min grace.
	s := freshActiveSession(now.Add(-30 * time.Minute))
	if s.ActiveWithGrace(now, clockskew.Default().Grace) {
		t.Error("ActiveWithGrace accepted session past the grace window")
	}
}

// TestActiveWithGraceNegativeIsStrict confirms a negative grace
// degrades to the strict semantics.
func TestActiveWithGraceNegativeIsStrict(t *testing.T) {
	now := time.Now().UTC()
	s := freshActiveSession(now.Add(-time.Second))
	if s.ActiveWithGrace(now, -time.Hour) {
		t.Error("negative grace was not treated as zero (strict)")
	}
}

// TestCanRekeyStrictMatchesActive confirms CanRekey's expiry check
// is the strict variant; receivers use CanRekeyWithGrace.
func TestCanRekeyStrictMatchesActive(t *testing.T) {
	now := time.Now().UTC()
	s := freshActiveSession(now.Add(-time.Second))
	ok, code, _ := s.CanRekey(now)
	if ok {
		t.Error("strict CanRekey accepted past-expiry session")
	}
	if code != "session_expired" {
		t.Errorf("reason code = %q, want session_expired", code)
	}
}

// TestCanRekeyWithGraceWithinWindow confirms a session expired
// within the grace window can still rekey on the receiver side.
func TestCanRekeyWithGraceWithinWindow(t *testing.T) {
	now := time.Now().UTC()
	s := freshActiveSession(now.Add(-5 * time.Minute))
	ok, code, _ := s.CanRekeyWithGrace(now, clockskew.Default().Grace)
	if !ok {
		t.Errorf("CanRekeyWithGrace within-window: ok=false code=%q", code)
	}
}

// TestAcceptsIDStrictRejectsPostExpiryPrevID confirms the strict
// AcceptsID rejects PriorID after the transition window elapses.
func TestAcceptsIDStrictRejectsPostExpiryPrevID(t *testing.T) {
	now := time.Now().UTC()
	s := &session.Session{
		ID:                  "current-id",
		State:               session.StateActive,
		ExpiresAt:           now.Add(time.Hour),
		PreviousID:          "prior-id",
		PreviousIDExpiresAt: now.Add(-time.Second),
	}
	if s.AcceptsID("prior-id", now) {
		t.Error("strict AcceptsID accepted prior-id past transition window")
	}
}

// TestAcceptsIDWithGraceWithinWindow confirms AcceptsIDWithGrace
// extends the prior-id acceptance window.
func TestAcceptsIDWithGraceWithinWindow(t *testing.T) {
	now := time.Now().UTC()
	s := &session.Session{
		ID:                  "current-id",
		State:               session.StateActive,
		ExpiresAt:           now.Add(time.Hour),
		PreviousID:          "prior-id",
		PreviousIDExpiresAt: now.Add(-3 * time.Second),
	}
	if !s.AcceptsIDWithGrace("prior-id", now, 30*time.Second) {
		t.Error("AcceptsIDWithGrace rejected prior-id within tail-grace")
	}
}
