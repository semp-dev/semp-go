package reputation_test

import (
	"testing"
	"time"

	"semp.dev/semp-go/crypto"
	"semp.dev/semp-go/extensions"
	"semp.dev/semp-go/keys"
	"semp.dev/semp-go/reputation"
)

func TestBucketize(t *testing.T) {
	cases := []struct {
		in, want int64
	}{
		{0, 0},
		{-1, 0},
		{1, 1},
		{2, 2},
		{3, 4},
		{4, 4},
		{5, 8},
		{7, 8},
		{8, 8},
		{9, 16},
		{100, 128},
		{1023, 1024},
		{1024, 1024},
		{1025, 2048},
		{1 << 19, 1 << 19},
		{(1 << 19) + 1, 1 << 20},
		{1 << 20, 1 << 20},
		{(1 << 20) + 1, 1 << 20}, // clamps to MaxMetricBucket
		{1 << 30, reputation.MaxMetricBucket},
	}
	for _, tc := range cases {
		got := reputation.Bucketize(tc.in)
		if got != tc.want {
			t.Errorf("Bucketize(%d) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

// TestSignObservationDeduplicatesAbuseCategories confirms that the
// publish-time pass deduplicates the abuse_categories slice per
// REPUTATION.md section 4.5.2. Without deduplication, the array's
// length would leak the raw abuse_reports count and defeat the
// section 4.5.1 bucketing.
func TestSignObservationDeduplicatesAbuseCategories(t *testing.T) {
	signer := crypto.SuiteBaseline.Signer()
	pub, priv, err := signer.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	now := time.Date(2026, 4, 11, 12, 0, 0, 0, time.UTC)
	obs := &reputation.Observation{
		Type:     reputation.ObservationType,
		Version:  reputation.ObservationVersion,
		ID:       "01JTESTDEDUP000000000000001",
		Observer: "observer.example",
		Subject:  "subject.example",
		Window: reputation.Window{
			Start: now.Add(-30 * 24 * time.Hour),
			End:   now,
		},
		Metrics: reputation.Metrics{
			AbuseReports: 5,
			AbuseCategories: []reputation.AbuseCategory{
				reputation.AbuseSpam,
				reputation.AbuseSpam,
				reputation.AbusePhishing,
				reputation.AbuseSpam,
				reputation.AbuseSpam,
			},
		},
		Assessment: reputation.AssessmentNeutral,
		Timestamp:  now,
		Expires:    now.Add(30 * 24 * time.Hour),
		Extensions: extensions.Map{},
	}
	if err := reputation.SignObservation(signer, priv, keys.Fingerprint("fp"), obs); err != nil {
		t.Fatalf("SignObservation: %v", err)
	}
	if got := len(obs.Metrics.AbuseCategories); got != 2 {
		t.Errorf("after dedup, AbuseCategories length = %d, want 2", got)
	}
	// First-occurrence order: spam (4 occurrences), then phishing.
	want := []reputation.AbuseCategory{reputation.AbuseSpam, reputation.AbusePhishing}
	for i, cat := range want {
		if i >= len(obs.Metrics.AbuseCategories) {
			break
		}
		if obs.Metrics.AbuseCategories[i] != cat {
			t.Errorf("AbuseCategories[%d] = %q, want %q", i, obs.Metrics.AbuseCategories[i], cat)
		}
	}
	// Bucketing: 5 reports -> bucket 8.
	if obs.Metrics.AbuseReports != 8 {
		t.Errorf("AbuseReports after bucketing = %d, want 8", obs.Metrics.AbuseReports)
	}
	if err := reputation.VerifyObservation(signer, obs, pub); err != nil {
		t.Errorf("VerifyObservation after sign: %v", err)
	}
}
