package reputation_test

import (
	"strings"
	"testing"
	"time"

	"semp.dev/semp-go/crypto"
	"semp.dev/semp-go/extensions"
	"semp.dev/semp-go/keys"
	"semp.dev/semp-go/reputation"
)

// newObserverKeypair generates an Ed25519 signing keypair and
// computes its fingerprint. Used by every signing test in this file.
func newObserverKeypair(t *testing.T) (pub, priv []byte, fp keys.Fingerprint) {
	t.Helper()
	pub, priv, err := crypto.SuiteBaseline.Signer().GenerateKeyPair()
	if err != nil {
		t.Fatalf("signer keypair: %v", err)
	}
	return pub, priv, keys.Compute(pub)
}

// sampleObservation builds a minimal-but-complete Observation ready
// for signing. Tests mutate fields on the returned value before the
// sign call to exercise specific code paths.
func sampleObservation() *reputation.Observation {
	now := time.Date(2026, 4, 11, 12, 0, 0, 0, time.UTC)
	return &reputation.Observation{
		Type:     reputation.ObservationType,
		Version:  reputation.ObservationVersion,
		ID:       "01JTESTOBS000000000000001",
		Observer: "observer.example",
		Subject:  "subject.example",
		Window: reputation.Window{
			Start: now.Add(-30 * 24 * time.Hour),
			End:   now,
		},
		Metrics: reputation.Metrics{
			EnvelopesReceived:   1000,
			EnvelopesRejected:   20,
			AbuseReports:        3,
			AbuseCategories:     []reputation.AbuseCategory{reputation.AbuseSpam, reputation.AbuseSpam, reputation.AbusePhishing},
			HandshakesCompleted: 50,
			HandshakesRejected:  1,
		},
		Assessment:        reputation.AssessmentNeutral,
		EvidenceAvailable: false,
		Timestamp:         now,
		Expires:           now.Add(30 * 24 * time.Hour),
		Extensions:        extensions.Map{},
	}
}

// TestSignObservationRoundTrip confirms SignObservation then
// VerifyObservation succeeds with the same keypair.
func TestSignObservationRoundTrip(t *testing.T) {
	pub, priv, fp := newObserverKeypair(t)
	obs := sampleObservation()

	if err := reputation.SignObservation(crypto.SuiteBaseline.Signer(), priv, fp, obs); err != nil {
		t.Fatalf("SignObservation: %v", err)
	}
	if obs.Signature.Value == "" {
		t.Error("signature value is empty after SignObservation")
	}
	if obs.Signature.KeyID != fp {
		t.Errorf("signature key_id = %s, want %s", obs.Signature.KeyID, fp)
	}
	if obs.Signature.Algorithm != keys.SignatureAlgorithmEd25519 {
		t.Errorf("signature algorithm = %s, want ed25519", obs.Signature.Algorithm)
	}
	if err := reputation.VerifyObservation(crypto.SuiteBaseline.Signer(), obs, pub); err != nil {
		t.Errorf("VerifyObservation: %v", err)
	}
}

// TestSignObservationRejectsTamper confirms mutating any covered
// field after signing breaks verification.
func TestSignObservationRejectsTamper(t *testing.T) {
	pub, priv, fp := newObserverKeypair(t)

	tests := []struct {
		name   string
		mutate func(*reputation.Observation)
	}{
		{"subject", func(o *reputation.Observation) { o.Subject = "other.example" }},
		{"observer", func(o *reputation.Observation) { o.Observer = "other.example" }},
		{"assessment", func(o *reputation.Observation) { o.Assessment = reputation.AssessmentHostile }},
		{"envelopes_received", func(o *reputation.Observation) { o.Metrics.EnvelopesReceived = 9999 }},
		{"abuse_reports", func(o *reputation.Observation) { o.Metrics.AbuseReports = 0 }},
		{"window.start", func(o *reputation.Observation) { o.Window.Start = o.Window.Start.Add(-time.Hour) }},
		{"expires", func(o *reputation.Observation) { o.Expires = o.Expires.Add(time.Hour) }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			obs := sampleObservation()
			if err := reputation.SignObservation(crypto.SuiteBaseline.Signer(), priv, fp, obs); err != nil {
				t.Fatalf("SignObservation: %v", err)
			}
			tc.mutate(obs)
			err := reputation.VerifyObservation(crypto.SuiteBaseline.Signer(), obs, pub)
			if err == nil {
				t.Errorf("tamper on %s should have broken verification", tc.name)
			}
		})
	}
}

// TestVerifyObservationUnsigned returns an error for an observation
// whose signature.value is empty.
func TestVerifyObservationUnsigned(t *testing.T) {
	pub, _, _ := newObserverKeypair(t)
	obs := sampleObservation()
	err := reputation.VerifyObservation(crypto.SuiteBaseline.Signer(), obs, pub)
	if err == nil || !strings.Contains(err.Error(), "unsigned") {
		t.Errorf("VerifyObservation(unsigned) = %v, want 'unsigned' error", err)
	}
}

// TestVerifyObservationWrongKey confirms verification fails under a
// different public key than the one used to sign.
func TestVerifyObservationWrongKey(t *testing.T) {
	_, priv, fp := newObserverKeypair(t)
	other, _, _ := newObserverKeypair(t)
	obs := sampleObservation()
	if err := reputation.SignObservation(crypto.SuiteBaseline.Signer(), priv, fp, obs); err != nil {
		t.Fatalf("SignObservation: %v", err)
	}
	if err := reputation.VerifyObservation(crypto.SuiteBaseline.Signer(), obs, other); err == nil {
		t.Error("verification should fail under a different public key")
	}
}

// TestNewObservationBuildsFromStore exercises the ObservationStore
// helper that assembles an Observation ready for signing.
func TestNewObservationBuildsFromStore(t *testing.T) {
	store := reputation.NewObservationStore(nil)
	for i := 0; i < 10; i++ {
		store.RecordEnvelope("subject.example", true)
	}
	store.RecordEnvelope("subject.example", false)
	store.RecordAbuseReport("subject.example", reputation.AbuseSpam)

	window := reputation.Window{
		Start: time.Now().UTC().Add(-30 * 24 * time.Hour),
		End:   time.Now().UTC(),
	}
	obs := store.NewObservation("observer.example", "subject.example", "obs-1", window, reputation.AssessmentSuspicious)
	if obs == nil {
		t.Fatal("NewObservation returned nil")
	}
	if obs.Type != reputation.ObservationType {
		t.Errorf("Type = %q, want %q", obs.Type, reputation.ObservationType)
	}
	if obs.Subject != "subject.example" {
		t.Errorf("Subject = %q, want subject.example", obs.Subject)
	}
	if obs.Metrics.EnvelopesReceived != 11 {
		t.Errorf("EnvelopesReceived = %d, want 11", obs.Metrics.EnvelopesReceived)
	}
	if obs.Metrics.EnvelopesRejected != 1 {
		t.Errorf("EnvelopesRejected = %d, want 1", obs.Metrics.EnvelopesRejected)
	}
	if obs.Metrics.AbuseReports != 1 {
		t.Errorf("AbuseReports = %d, want 1", obs.Metrics.AbuseReports)
	}
	if len(obs.Metrics.AbuseCategories) != 1 || obs.Metrics.AbuseCategories[0] != reputation.AbuseSpam {
		t.Errorf("AbuseCategories = %v, want [spam]", obs.Metrics.AbuseCategories)
	}
	if obs.Assessment != reputation.AssessmentSuspicious {
		t.Errorf("Assessment = %s, want suspicious", obs.Assessment)
	}
}

// TestComputeGossipHashDeterministic confirms that two observation
// lists with the same IDs + timestamps produce byte-identical hashes
// regardless of input order.
func TestComputeGossipHashDeterministic(t *testing.T) {
	now := time.Date(2026, 4, 11, 12, 0, 0, 0, time.UTC)
	a := []reputation.Observation{
		{ID: "obs-1", Timestamp: now},
		{ID: "obs-2", Timestamp: now.Add(time.Hour)},
		{ID: "obs-3", Timestamp: now.Add(2 * time.Hour)},
	}
	b := []reputation.Observation{
		{ID: "obs-3", Timestamp: now.Add(2 * time.Hour)},
		{ID: "obs-1", Timestamp: now},
		{ID: "obs-2", Timestamp: now.Add(time.Hour)},
	}
	hashA, err := reputation.ComputeGossipHash("subject.example", a)
	if err != nil {
		t.Fatalf("ComputeGossipHash(a): %v", err)
	}
	hashB, err := reputation.ComputeGossipHash("subject.example", b)
	if err != nil {
		t.Fatalf("ComputeGossipHash(b): %v", err)
	}
	if hashA.Hash != hashB.Hash {
		t.Errorf("gossip hash not deterministic: a=%s b=%s", hashA.Hash, hashB.Hash)
	}
	if hashA.Algorithm != "sha256" {
		t.Errorf("algorithm = %q, want sha256", hashA.Algorithm)
	}
}

// TestComputeGossipHashDifferentSubjects confirms two hashes over
// identical observation sets but different subjects don't collide.
func TestComputeGossipHashDifferentSubjects(t *testing.T) {
	obs := []reputation.Observation{
		{ID: "obs-1", Timestamp: time.Now().UTC()},
	}
	hashA, _ := reputation.ComputeGossipHash("a.example", obs)
	hashB, _ := reputation.ComputeGossipHash("b.example", obs)
	if hashA.Hash == hashB.Hash {
		t.Error("different subjects should produce different hashes")
	}
}

// TestComputeGossipHashEmpty confirms an empty observation list is
// legitimate and produces a stable hash.
func TestComputeGossipHashEmpty(t *testing.T) {
	h, err := reputation.ComputeGossipHash("subject.example", nil)
	if err != nil {
		t.Fatalf("ComputeGossipHash(nil): %v", err)
	}
	if h.Hash == "" {
		t.Error("empty observation list should still produce a hash")
	}
	if h.Domain != "subject.example" {
		t.Errorf("Domain = %q, want subject.example", h.Domain)
	}
}

// TestComputeGossipHashRejectsEmptyDomain confirms the input
// validation path.
func TestComputeGossipHashRejectsEmptyDomain(t *testing.T) {
	_, err := reputation.ComputeGossipHash("", nil)
	if err == nil {
		t.Error("ComputeGossipHash(\"\") should have errored")
	}
}
