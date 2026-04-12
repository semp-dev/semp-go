package reputation_test

import (
	"encoding/base64"
	"testing"
	"time"

	"semp.dev/semp-go/reputation"
)

// mockDelegate is a minimal DelegatePolicy used by the adapter tests.
type mockDelegate struct {
	blocked map[string]bool
	ttl     int
	perms   []string
}

func (m *mockDelegate) BlockedDomain(domain string) bool { return m.blocked[domain] }
func (m *mockDelegate) SessionTTL(string) int            { return m.ttl }
func (m *mockDelegate) Permissions(string) []string      { return m.perms }

// TestHandshakeAdapterIssuesChallengeForUnknownOrigin confirms the
// adapter issues a baseline challenge when OriginFrom returns a fresh
// domain.
func TestHandshakeAdapterIssuesChallengeForUnknownOrigin(t *testing.T) {
	store := reputation.NewObservationStore(nil)
	ledger := reputation.NewChallengeLedger(time.Minute)
	adapter := &reputation.HandshakeAdapter{
		PoW: &reputation.PoWPolicy{
			Store:      store,
			Ledger:     ledger,
			AgeDaysFor: func(string) int { return 0 },
		},
		Delegate: &mockDelegate{ttl: 600},
		OriginFrom: func(initNonce, transport string) string {
			return "unknown.example"
		},
	}
	req := adapter.RequirePoW("some-nonce", "ws")
	if req == nil {
		t.Fatal("RequirePoW should have issued a challenge")
	}
	if req.Algorithm != reputation.DefaultPoWAlgorithm {
		t.Errorf("Algorithm = %q, want %q", req.Algorithm, reputation.DefaultPoWAlgorithm)
	}
	if req.Difficulty != reputation.DifficultyBaseline {
		t.Errorf("Difficulty = %d, want %d", req.Difficulty, reputation.DifficultyBaseline)
	}
	if req.ChallengeID == "" {
		t.Error("ChallengeID is empty")
	}
	if _, err := base64.StdEncoding.DecodeString(req.PrefixB64); err != nil {
		t.Errorf("PrefixB64 does not decode: %v", err)
	}
	if !req.Expires.After(time.Now()) {
		t.Errorf("Expires %s is not in the future", req.Expires)
	}
	// Adapter should remember the outstanding challenge.
	if adapter.Outstanding() != 1 {
		t.Errorf("Outstanding = %d, want 1 after issue", adapter.Outstanding())
	}
}

// TestHandshakeAdapterSkipsForTrustedDomain confirms no challenge
// is issued for a trusted-assessment domain.
func TestHandshakeAdapterSkipsForTrustedDomain(t *testing.T) {
	store := reputation.NewObservationStore(nil)
	for i := 0; i < 150; i++ {
		store.RecordEnvelope("trusted.example", true)
	}
	ledger := reputation.NewChallengeLedger(time.Minute)
	adapter := &reputation.HandshakeAdapter{
		PoW: &reputation.PoWPolicy{
			Store:      store,
			Ledger:     ledger,
			AgeDaysFor: func(string) int { return 365 },
		},
		Delegate:   &mockDelegate{ttl: 600},
		OriginFrom: func(initNonce, transport string) string { return "trusted.example" },
	}
	if req := adapter.RequirePoW("nonce", "ws"); req != nil {
		t.Errorf("trusted domain should get no challenge, got %+v", req)
	}
}

// TestHandshakeAdapterForgetDrainsScratch ensures Forget removes the
// stashed challenge entry.
func TestHandshakeAdapterForgetDrainsScratch(t *testing.T) {
	store := reputation.NewObservationStore(nil)
	ledger := reputation.NewChallengeLedger(time.Minute)
	adapter := &reputation.HandshakeAdapter{
		PoW: &reputation.PoWPolicy{
			Store:      store,
			Ledger:     ledger,
			AgeDaysFor: func(string) int { return 0 },
		},
		Delegate:   &mockDelegate{},
		OriginFrom: func(string, string) string { return "fresh.example" },
	}
	req := adapter.RequirePoW("n1", "ws")
	if req == nil {
		t.Fatal("RequirePoW issued nothing")
	}
	ch := adapter.Forget("n1")
	if ch == nil || ch.ID != req.ChallengeID {
		t.Errorf("Forget returned %+v, want challenge %s", ch, req.ChallengeID)
	}
	if adapter.Outstanding() != 0 {
		t.Errorf("Outstanding after Forget = %d, want 0", adapter.Outstanding())
	}
}

// TestHandshakeAdapterDelegates confirms BlockedDomain / SessionTTL /
// Permissions are passed through.
func TestHandshakeAdapterDelegates(t *testing.T) {
	adapter := &reputation.HandshakeAdapter{
		PoW: &reputation.PoWPolicy{
			Store:  reputation.NewObservationStore(nil),
			Ledger: reputation.NewChallengeLedger(time.Minute),
		},
		Delegate: &mockDelegate{
			blocked: map[string]bool{"mean.example": true},
			ttl:     1234,
			perms:   []string{"send", "receive"},
		},
	}
	if !adapter.BlockedDomain("mean.example") {
		t.Error("BlockedDomain did not delegate")
	}
	if adapter.BlockedDomain("fine.example") {
		t.Error("BlockedDomain wrongly returned true")
	}
	if got := adapter.SessionTTL("alice@example.com"); got != 1234 {
		t.Errorf("SessionTTL = %d, want 1234", got)
	}
	if perms := adapter.Permissions("alice@example.com"); len(perms) != 2 || perms[0] != "send" {
		t.Errorf("Permissions = %v, want [send receive]", perms)
	}
}

// TestHandshakeAdapterNilOriginFallsBackToBaseline confirms a nil
// OriginFrom still produces a baseline challenge (treating the caller
// as an unknown domain).
func TestHandshakeAdapterNilOriginFallsBackToBaseline(t *testing.T) {
	store := reputation.NewObservationStore(nil)
	adapter := &reputation.HandshakeAdapter{
		PoW: &reputation.PoWPolicy{
			Store:      store,
			Ledger:     reputation.NewChallengeLedger(time.Minute),
			AgeDaysFor: func(string) int { return 0 },
		},
		Delegate: &mockDelegate{},
		// OriginFrom: nil
	}
	req := adapter.RequirePoW("nonce", "ws")
	if req == nil {
		t.Fatal("expected baseline challenge with nil OriginFrom")
	}
	if req.Difficulty != reputation.DifficultyBaseline {
		t.Errorf("Difficulty = %d, want %d", req.Difficulty, reputation.DifficultyBaseline)
	}
}
