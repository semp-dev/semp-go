package reputation_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"
	"time"

	"semp.dev/semp-go/reputation"
)

// TestDifficultyForAgeCurve confirms the default age curve: new
// domains (< 30 days) get DifficultyBaseline, older domains get
// DifficultyRelaxed.
func TestDifficultyForAgeCurve(t *testing.T) {
	tests := []struct {
		ageDays int
		want    int
	}{
		{0, reputation.DifficultyBaseline},
		{1, reputation.DifficultyBaseline},
		{29, reputation.DifficultyBaseline},
		{30, reputation.DifficultyRelaxed},
		{365, reputation.DifficultyRelaxed},
	}
	for _, tc := range tests {
		if got := reputation.DifficultyForAge(tc.ageDays); got != tc.want {
			t.Errorf("DifficultyForAge(%d) = %d, want %d", tc.ageDays, got, tc.want)
		}
	}
}

// TestDifficultyForAssessment maps each Assessment to its expected
// difficulty, including zero (no PoW) for trusted/neutral.
func TestDifficultyForAssessment(t *testing.T) {
	tests := []struct {
		assessment reputation.Assessment
		want       int
	}{
		{reputation.AssessmentTrusted, 0},
		{reputation.AssessmentNeutral, 0},
		{reputation.AssessmentSuspicious, reputation.DifficultySuspicious},
		{reputation.AssessmentHostile, reputation.DifficultyHostile},
		{"", 0},
		{"unknown-future-value", 0},
	}
	for _, tc := range tests {
		if got := reputation.DifficultyForAssessment(tc.assessment); got != tc.want {
			t.Errorf("DifficultyForAssessment(%q) = %d, want %d", tc.assessment, got, tc.want)
		}
	}
}

// TestIssueChallengeHappyPath confirms a freshly-issued challenge has
// the right shape: non-empty ID, correct algorithm, sufficient
// prefix entropy, matching difficulty, and a future expiry.
func TestIssueChallengeHappyPath(t *testing.T) {
	ch, err := reputation.IssueChallenge(reputation.DifficultyBaseline, 2*time.Minute)
	if err != nil {
		t.Fatalf("IssueChallenge: %v", err)
	}
	if ch.ID == "" {
		t.Error("Challenge.ID is empty")
	}
	if ch.Algorithm != reputation.DefaultPoWAlgorithm {
		t.Errorf("Algorithm = %q, want %q", ch.Algorithm, reputation.DefaultPoWAlgorithm)
	}
	if len(ch.Prefix) < reputation.MinPrefixBytes {
		t.Errorf("len(Prefix) = %d, want ≥ %d", len(ch.Prefix), reputation.MinPrefixBytes)
	}
	if ch.Difficulty != reputation.DifficultyBaseline {
		t.Errorf("Difficulty = %d, want %d", ch.Difficulty, reputation.DifficultyBaseline)
	}
	if !ch.Expires.After(time.Now()) {
		t.Errorf("Expires %s is not in the future", ch.Expires)
	}
	// PrefixBase64 should round-trip.
	raw, err := base64.StdEncoding.DecodeString(ch.PrefixBase64())
	if err != nil {
		t.Fatalf("PrefixBase64 does not decode: %v", err)
	}
	if string(raw) != string(ch.Prefix) {
		t.Error("PrefixBase64 round-trip mismatch")
	}
}

// TestIssueChallengeZeroTTL confirms a zero TTL is replaced with the
// default and the challenge expires in the future.
func TestIssueChallengeZeroTTL(t *testing.T) {
	ch, err := reputation.IssueChallenge(16, 0)
	if err != nil {
		t.Fatalf("IssueChallenge: %v", err)
	}
	elapsed := time.Until(ch.Expires)
	if elapsed < time.Minute || elapsed > reputation.DefaultChallengeTTL+time.Second {
		t.Errorf("default TTL window = %s, want ~%s", elapsed, reputation.DefaultChallengeTTL)
	}
}

// TestIssueChallengeRejectsInvalid confirms input validation.
func TestIssueChallengeRejectsInvalid(t *testing.T) {
	if _, err := reputation.IssueChallenge(-1, time.Minute); err == nil {
		t.Error("negative difficulty should error")
	}
	if _, err := reputation.IssueChallenge(300, time.Minute); err == nil {
		t.Error("difficulty exceeding hash size should error")
	}
	if _, err := reputation.IssueChallenge(16, -time.Second); err == nil {
		t.Error("negative TTL should error")
	}
}

// TestIssueChallengeIDsUnique confirms two challenges issued in quick
// succession don't collide.
func TestIssueChallengeIDsUnique(t *testing.T) {
	seen := make(map[string]bool, 64)
	for i := 0; i < 64; i++ {
		ch, err := reputation.IssueChallenge(16, time.Minute)
		if err != nil {
			t.Fatalf("IssueChallenge[%d]: %v", i, err)
		}
		if seen[ch.ID] {
			t.Fatalf("duplicate challenge ID %q", ch.ID)
		}
		seen[ch.ID] = true
	}
}

// TestChallengeLedgerRecordAndRedeem exercises the happy path: record
// a challenge, redeem it once, confirm replay is rejected.
func TestChallengeLedgerRecordAndRedeem(t *testing.T) {
	ledger := reputation.NewChallengeLedger(time.Minute)
	ch, err := reputation.IssueChallenge(16, time.Minute)
	if err != nil {
		t.Fatalf("IssueChallenge: %v", err)
	}
	if err := ledger.Record(ch); err != nil {
		t.Fatalf("Record: %v", err)
	}
	// First redemption succeeds.
	got, err := ledger.Redeem(ch.ID)
	if err != nil {
		t.Fatalf("Redeem: %v", err)
	}
	if got.ID != ch.ID {
		t.Errorf("redeemed ID = %q, want %q", got.ID, ch.ID)
	}
	// Second redemption must be rejected as replay.
	if _, err := ledger.Redeem(ch.ID); !errors.Is(err, reputation.ErrChallengeReplayed) {
		t.Errorf("replay redemption = %v, want ErrChallengeReplayed", err)
	}
}

// TestChallengeLedgerRedeemUnknown returns ErrChallengeUnknown for a
// challenge that was never recorded.
func TestChallengeLedgerRedeemUnknown(t *testing.T) {
	ledger := reputation.NewChallengeLedger(time.Minute)
	_, err := ledger.Redeem("nonexistent")
	if !errors.Is(err, reputation.ErrChallengeUnknown) {
		t.Errorf("Redeem unknown = %v, want ErrChallengeUnknown", err)
	}
}

// TestChallengeLedgerRedeemExpired confirms that a challenge whose
// expiry has passed is rejected with ErrChallengeExpired.
func TestChallengeLedgerRedeemExpired(t *testing.T) {
	ledger := reputation.NewChallengeLedger(time.Minute)
	ch, err := reputation.IssueChallenge(16, time.Minute)
	if err != nil {
		t.Fatalf("IssueChallenge: %v", err)
	}
	// Rewind expiry to the past.
	ch.Expires = time.Now().Add(-time.Second)
	if err := ledger.Record(ch); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if _, err := ledger.Redeem(ch.ID); !errors.Is(err, reputation.ErrChallengeExpired) {
		t.Errorf("Redeem expired = %v, want ErrChallengeExpired", err)
	}
}

// TestChallengeLedgerDuplicateRecord rejects re-recording the same ID.
func TestChallengeLedgerDuplicateRecord(t *testing.T) {
	ledger := reputation.NewChallengeLedger(time.Minute)
	ch, _ := reputation.IssueChallenge(16, time.Minute)
	if err := ledger.Record(ch); err != nil {
		t.Fatalf("Record 1: %v", err)
	}
	if err := ledger.Record(ch); err == nil {
		t.Error("duplicate Record should fail")
	}
}

// TestChallengeLedgerActiveCount walks the Active() diagnostic.
func TestChallengeLedgerActiveCount(t *testing.T) {
	ledger := reputation.NewChallengeLedger(time.Minute)
	if ledger.Active() != 0 {
		t.Errorf("fresh Active = %d, want 0", ledger.Active())
	}
	ch1, _ := reputation.IssueChallenge(16, time.Minute)
	ch2, _ := reputation.IssueChallenge(16, time.Minute)
	_ = ledger.Record(ch1)
	_ = ledger.Record(ch2)
	if ledger.Active() != 2 {
		t.Errorf("Active after 2 Records = %d, want 2", ledger.Active())
	}
	_, _ = ledger.Redeem(ch1.ID)
	if ledger.Active() != 1 {
		t.Errorf("Active after 1 Redeem = %d, want 1", ledger.Active())
	}
}

// TestChallengeLedgerSweepPrunesExpired confirms Sweep drops entries
// whose expiry (+ grace) has passed.
func TestChallengeLedgerSweepPrunesExpired(t *testing.T) {
	ledger := reputation.NewChallengeLedger(time.Nanosecond)
	ch, _ := reputation.IssueChallenge(16, time.Minute)
	// Force the challenge to look like it's well past its grace window.
	ch.Expires = time.Now().Add(-10 * time.Minute)
	_ = ledger.Record(ch)
	// A sweep should drop the expired challenge.
	ledger.Sweep()
	if _, err := ledger.Redeem(ch.ID); !errors.Is(err, reputation.ErrChallengeUnknown) {
		t.Errorf("post-sweep Redeem = %v, want ErrChallengeUnknown", err)
	}
}

// TestPoWSolutionRoundTrip confirms an end-to-end PoW exchange:
// issue → solve manually → verify. We solve at difficulty 8 (cheap)
// and reuse the handshake package's hash math indirectly via raw
// SHA-256 to prove the wire format in REPUTATION.md §8.3.3 is stable.
func TestPoWSolutionRoundTrip(t *testing.T) {
	ch, err := reputation.IssueChallenge(8, time.Minute)
	if err != nil {
		t.Fatalf("IssueChallenge: %v", err)
	}
	// Solve: find a nonce such that SHA-256(prefixB64 ":" id ":" nonceB64)
	// has ≥ 8 leading zero bits.
	prefixB64 := ch.PrefixBase64()
	var nonceBuf [8]byte
	var nonceB64 string
	var sum [32]byte
	for counter := uint64(0); counter < 1<<24; counter++ {
		binary.BigEndian.PutUint64(nonceBuf[:], counter)
		nonceB64 = base64.StdEncoding.EncodeToString(nonceBuf[:])
		pre := prefixB64 + ":" + ch.ID + ":" + nonceB64
		sum = sha256.Sum256([]byte(pre))
		if leadingZeroBits(sum[:]) >= ch.Difficulty {
			break
		}
	}
	if leadingZeroBits(sum[:]) < ch.Difficulty {
		t.Fatal("could not find a solution within the search space")
	}
	// Verify by recomputing exactly as a server would.
	pre := prefixB64 + ":" + ch.ID + ":" + nonceB64
	got := sha256.Sum256([]byte(pre))
	if hex.EncodeToString(got[:]) != hex.EncodeToString(sum[:]) {
		t.Fatal("recomputed hash does not match solve-time hash")
	}
}

// leadingZeroBits is the same helper the handshake package exposes,
// inlined here so the reputation tests can stay dependency-free.
func leadingZeroBits(hash []byte) int {
	bits := 0
	for _, b := range hash {
		if b == 0 {
			bits += 8
			continue
		}
		for mask := byte(0x80); mask != 0; mask >>= 1 {
			if b&mask != 0 {
				return bits
			}
			bits++
		}
		return bits
	}
	return bits
}

// TestPoWPolicyDecideZeroScoreIssues confirms that a PoWPolicy with
// a store that has never seen a domain issues a baseline challenge.
func TestPoWPolicyDecideZeroScoreIssues(t *testing.T) {
	store := reputation.NewObservationStore(nil)
	ledger := reputation.NewChallengeLedger(time.Minute)
	policy := &reputation.PoWPolicy{
		Store:      store,
		Ledger:     ledger,
		AgeDaysFor: func(string) int { return 0 }, // fresh domain
	}
	ch, err := policy.Decide("unknown.example")
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if ch == nil {
		t.Fatal("Decide should have issued a challenge for a fresh domain")
	}
	if ch.Difficulty != reputation.DifficultyBaseline {
		t.Errorf("Difficulty = %d, want %d", ch.Difficulty, reputation.DifficultyBaseline)
	}
	// The challenge must have been recorded.
	if ledger.Active() != 1 {
		t.Errorf("ledger Active = %d, want 1 after Decide", ledger.Active())
	}
}

// TestPoWPolicyDecideTrustedSkips confirms a domain classified as
// trusted gets no challenge.
func TestPoWPolicyDecideTrustedSkips(t *testing.T) {
	store := reputation.NewObservationStore(nil)
	// Feed the store enough accepted envelopes to trip the trusted
	// classifier (≥ 100 accepted, 0 abuse, < 5% reject).
	for i := 0; i < 150; i++ {
		store.RecordEnvelope("good.example", true)
	}
	ledger := reputation.NewChallengeLedger(time.Minute)
	policy := &reputation.PoWPolicy{
		Store:      store,
		Ledger:     ledger,
		AgeDaysFor: func(string) int { return 365 }, // old domain
	}
	ch, err := policy.Decide("good.example")
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if ch != nil {
		t.Errorf("trusted domain should get no challenge, got %+v", ch)
	}
}

// TestPoWPolicyDecideHostileRaisesDifficulty confirms a hostile
// assessment produces the hostile difficulty even when the domain is
// old.
func TestPoWPolicyDecideHostileRaisesDifficulty(t *testing.T) {
	store := reputation.NewObservationStore(nil)
	// 10 envelopes with 5 abuse reports ⇒ 50% abuse rate → hostile.
	for i := 0; i < 10; i++ {
		store.RecordEnvelope("bad.example", true)
	}
	for i := 0; i < 5; i++ {
		store.RecordAbuseReport("bad.example", reputation.AbuseSpam)
	}
	ledger := reputation.NewChallengeLedger(time.Minute)
	policy := &reputation.PoWPolicy{
		Store:      store,
		Ledger:     ledger,
		AgeDaysFor: func(string) int { return 365 },
	}
	ch, err := policy.Decide("bad.example")
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if ch == nil {
		t.Fatal("hostile domain should get a challenge")
	}
	if ch.Difficulty != reputation.DifficultyHostile {
		t.Errorf("Difficulty = %d, want %d (hostile)", ch.Difficulty, reputation.DifficultyHostile)
	}
}

// TestPoWPolicyMinDifficultyFloor confirms the MinDifficulty knob
// floors every challenge regardless of assessment.
func TestPoWPolicyMinDifficultyFloor(t *testing.T) {
	store := reputation.NewObservationStore(nil)
	ledger := reputation.NewChallengeLedger(time.Minute)
	policy := &reputation.PoWPolicy{
		Store:         store,
		Ledger:        ledger,
		MinDifficulty: 24,
		AgeDaysFor:    func(string) int { return 365 }, // old → normally relaxed (16)
	}
	ch, err := policy.Decide("neutral.example")
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if ch == nil || ch.Difficulty != 24 {
		t.Errorf("MinDifficulty floor not applied, got %+v", ch)
	}
}

// TestPoWPolicyRedeemAndVerify stitches the ledger single-use check
// and a caller-provided verify func together.
func TestPoWPolicyRedeemAndVerify(t *testing.T) {
	store := reputation.NewObservationStore(nil)
	ledger := reputation.NewChallengeLedger(time.Minute)
	policy := &reputation.PoWPolicy{
		Store:      store,
		Ledger:     ledger,
		AgeDaysFor: func(string) int { return 0 },
	}
	ch, err := policy.Decide("fresh.example")
	if err != nil || ch == nil {
		t.Fatalf("Decide: ch=%v err=%v", ch, err)
	}
	verified := false
	err = policy.RedeemAndVerify(ch.ID, func(prefix []byte, difficulty int) error {
		verified = true
		if difficulty != ch.Difficulty {
			return fmt.Errorf("difficulty mismatch: got %d, want %d", difficulty, ch.Difficulty)
		}
		if string(prefix) != string(ch.Prefix) {
			return fmt.Errorf("prefix mismatch")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("RedeemAndVerify: %v", err)
	}
	if !verified {
		t.Error("verify closure was not invoked")
	}
	// Replay should now be rejected.
	err = policy.RedeemAndVerify(ch.ID, func([]byte, int) error { return nil })
	if !errors.Is(err, reputation.ErrChallengeReplayed) {
		t.Errorf("replay RedeemAndVerify = %v, want ErrChallengeReplayed", err)
	}
}
