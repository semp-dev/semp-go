package reputation_test

import (
	"testing"
	"time"

	"github.com/semp-dev/semp-go/reputation"
)

// TestObservationStoreRecordHandshake counts handshake outcomes.
func TestObservationStoreRecordHandshake(t *testing.T) {
	store := reputation.NewObservationStore(nil)
	store.RecordHandshake("example.com", true)
	store.RecordHandshake("example.com", true)
	store.RecordHandshake("example.com", false)
	m := store.Metrics("example.com")
	if m.HandshakesCompleted != 2 {
		t.Errorf("HandshakesCompleted = %d, want 2", m.HandshakesCompleted)
	}
	if m.HandshakesRejected != 1 {
		t.Errorf("HandshakesRejected = %d, want 1", m.HandshakesRejected)
	}
}

// TestObservationStoreRecordEnvelope counts envelope outcomes.
func TestObservationStoreRecordEnvelope(t *testing.T) {
	store := reputation.NewObservationStore(nil)
	store.RecordEnvelope("example.com", true)
	store.RecordEnvelope("example.com", true)
	store.RecordEnvelope("example.com", true)
	store.RecordEnvelope("example.com", false)
	m := store.Metrics("example.com")
	if got := m.EnvelopesReceived; got != 4 {
		t.Errorf("EnvelopesReceived = %d, want 4", got)
	}
	if got := m.EnvelopesRejected; got != 1 {
		t.Errorf("EnvelopesRejected = %d, want 1", got)
	}
}

// TestObservationStoreAbuseReport records abuse reports and reflects
// them in the score's AbuseRate.
func TestObservationStoreAbuseReport(t *testing.T) {
	store := reputation.NewObservationStore(nil)
	for i := 0; i < 20; i++ {
		store.RecordEnvelope("spam.example", true)
	}
	store.RecordAbuseReport("spam.example")
	store.RecordAbuseReport("spam.example")
	score := store.Score("spam.example")
	if score.TotalEnvelopes != 20 {
		t.Errorf("TotalEnvelopes = %d, want 20", score.TotalEnvelopes)
	}
	if score.AbuseRate != 0.1 {
		t.Errorf("AbuseRate = %v, want 0.1", score.AbuseRate)
	}
}

// TestObservationStoreCaseInsensitive confirms domain names are
// normalized.
func TestObservationStoreCaseInsensitive(t *testing.T) {
	store := reputation.NewObservationStore(nil)
	store.RecordHandshake("Example.Com", true)
	store.RecordHandshake("EXAMPLE.COM", true)
	m := store.Metrics("example.com")
	if m.HandshakesCompleted != 2 {
		t.Errorf("HandshakesCompleted = %d, want 2 (case-insensitive)", m.HandshakesCompleted)
	}
}

// TestObservationStoreUnknownDomain returns an empty Score / Metrics.
func TestObservationStoreUnknownDomain(t *testing.T) {
	store := reputation.NewObservationStore(nil)
	if m := store.Metrics("unknown.example"); m.EnvelopesReceived != 0 {
		t.Errorf("Metrics = %+v, want zero", m)
	}
	s := store.Score("unknown.example")
	if s.Assessment != reputation.AssessmentNeutral {
		t.Errorf("Assessment = %s, want neutral", s.Assessment)
	}
	if s.AgeDays != -1 {
		t.Errorf("AgeDays = %d, want -1 for unknown", s.AgeDays)
	}
}

// TestObservationStoreScoreHostile confirms the hostile classifier
// trips at ≥ 5% abuse rate.
func TestObservationStoreScoreHostile(t *testing.T) {
	store := reputation.NewObservationStore(nil)
	for i := 0; i < 100; i++ {
		store.RecordEnvelope("bad.example", true)
	}
	for i := 0; i < 5; i++ {
		store.RecordAbuseReport("bad.example")
	}
	score := store.Score("bad.example")
	if score.Assessment != reputation.AssessmentHostile {
		t.Errorf("Assessment = %s, want hostile (abuse_rate=%v)", score.Assessment, score.AbuseRate)
	}
}

// TestObservationStoreScoreSuspicious confirms the suspicious classifier
// trips between 1% and 5% abuse.
func TestObservationStoreScoreSuspicious(t *testing.T) {
	store := reputation.NewObservationStore(nil)
	for i := 0; i < 100; i++ {
		store.RecordEnvelope("meh.example", true)
	}
	store.RecordAbuseReport("meh.example") // 1/100 = 1% abuse
	score := store.Score("meh.example")
	if score.Assessment != reputation.AssessmentSuspicious {
		t.Errorf("Assessment = %s, want suspicious (abuse_rate=%v)", score.Assessment, score.AbuseRate)
	}
}

// TestObservationStoreScoreTrusted requires ≥ 100 envelopes, 0 abuse
// reports, and < 5% reject rate.
func TestObservationStoreScoreTrusted(t *testing.T) {
	store := reputation.NewObservationStore(nil)
	for i := 0; i < 100; i++ {
		store.RecordEnvelope("good.example", true)
	}
	// 2 rejects out of 102 → ~2% reject rate, still trusted.
	store.RecordEnvelope("good.example", false)
	store.RecordEnvelope("good.example", false)
	score := store.Score("good.example")
	if score.Assessment != reputation.AssessmentTrusted {
		t.Errorf("Assessment = %s, want trusted", score.Assessment)
	}
}

// TestObservationStoreScoreNeutralSmallVolume confirms a small-volume
// domain with no bad signals stays neutral (insufficient data).
func TestObservationStoreScoreNeutralSmallVolume(t *testing.T) {
	store := reputation.NewObservationStore(nil)
	for i := 0; i < 10; i++ {
		store.RecordEnvelope("quiet.example", true)
	}
	score := store.Score("quiet.example")
	if score.Assessment != reputation.AssessmentNeutral {
		t.Errorf("Assessment = %s, want neutral (too few envelopes for trusted)", score.Assessment)
	}
}

// TestObservationStoreScoreAgeDays uses a clock hook to confirm the
// derived age field.
func TestObservationStoreScoreAgeDays(t *testing.T) {
	fakeNow := time.Date(2026, 4, 11, 12, 0, 0, 0, time.UTC)
	clock := fakeNow
	store := reputation.NewObservationStore(func() time.Time { return clock })
	store.RecordHandshake("example.com", true)
	clock = fakeNow.Add(5 * 24 * time.Hour)
	score := store.Score("example.com")
	if score.AgeDays != 5 {
		t.Errorf("AgeDays = %d, want 5", score.AgeDays)
	}
}

// TestObservationStoreReset clears a domain.
func TestObservationStoreReset(t *testing.T) {
	store := reputation.NewObservationStore(nil)
	store.RecordHandshake("example.com", true)
	store.Reset("example.com")
	if store.Len() != 0 {
		t.Errorf("Len after Reset = %d, want 0", store.Len())
	}
	if m := store.Metrics("example.com"); m.HandshakesCompleted != 0 {
		t.Errorf("metrics after Reset non-zero: %+v", m)
	}
}

// TestObservationStoreLen counts distinct domains.
func TestObservationStoreLen(t *testing.T) {
	store := reputation.NewObservationStore(nil)
	store.RecordHandshake("a.example", true)
	store.RecordHandshake("b.example", true)
	store.RecordHandshake("a.example", true)
	if got := store.Len(); got != 2 {
		t.Errorf("Len = %d, want 2", got)
	}
}
