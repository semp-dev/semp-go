package transparency_test

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	"semp.dev/semp-go/crypto"
	"semp.dev/semp-go/transparency"
)

func newTestLog(t *testing.T) (*transparency.Log, []byte) {
	t.Helper()
	signer := crypto.SuiteBaseline.Signer()
	pub, priv, err := signer.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	log, err := transparency.NewLog(transparency.LogConfig{
		Suite:       crypto.SuiteBaseline,
		DomainKeyID: "log-domain-fp",
		DomainPriv:  priv,
		NowFn:       func() time.Time { return time.Date(2026, 5, 7, 12, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatalf("NewLog: %v", err)
	}
	return log, pub
}

func sampleEntry(seq int) transparency.LogEntry {
	return transparency.LogEntry{
		Event:        transparency.EventPublish,
		UserID:       "alice@example.com",
		KeyID:        "fp-" + string(rune('a'+seq)),
		KeyType:      transparency.KeyTypeIdentity,
		Algorithm:    "ed25519",
		PublicKey:    "AAAA",
		Created:      time.Date(2026, 5, 7, 11, 0, int(seq), 0, time.UTC),
		LogTimestamp: time.Date(2026, 5, 7, 11, 0, int(seq), 0, time.UTC),
	}
}

// TestLogAppendAndSize confirms Append assigns indices and Size
// reflects the appended count.
func TestLogAppendAndSize(t *testing.T) {
	log, _ := newTestLog(t)
	if log.Size() != 0 {
		t.Errorf("initial Size = %d, want 0", log.Size())
	}
	idx, err := log.Append(context.Background(), sampleEntry(0))
	if err != nil {
		t.Fatalf("Append 0: %v", err)
	}
	if idx != 0 {
		t.Errorf("Append 0 index = %d, want 0", idx)
	}
	idx, _ = log.Append(context.Background(), sampleEntry(1))
	if idx != 1 {
		t.Errorf("Append 1 index = %d, want 1", idx)
	}
	if log.Size() != 2 {
		t.Errorf("Size after 2 appends = %d, want 2", log.Size())
	}
}

// TestLogIssueSTHAndVerify confirms IssueSTH produces a signed
// STH that VerifySTH accepts under the log's domain pubkey.
func TestLogIssueSTHAndVerify(t *testing.T) {
	log, pub := newTestLog(t)
	for i := 0; i < 5; i++ {
		_, _ = log.Append(context.Background(), sampleEntry(i))
	}
	sth, err := log.IssueSTH(context.Background())
	if err != nil {
		t.Fatalf("IssueSTH: %v", err)
	}
	if sth.LogSize != 5 {
		t.Errorf("LogSize = %d, want 5", sth.LogSize)
	}
	if err := transparency.VerifySTH(crypto.SuiteBaseline.Signer(), pub, sth); err != nil {
		t.Errorf("VerifySTH: %v", err)
	}
}

// TestLogInclusionProof drives the full round-trip: append entries,
// issue an STH, fetch an inclusion proof for one leaf, verify the
// proof against the STH's root.
func TestLogInclusionProof(t *testing.T) {
	log, _ := newTestLog(t)
	for i := 0; i < 7; i++ {
		_, _ = log.Append(context.Background(), sampleEntry(i))
	}
	sth, _ := log.IssueSTH(context.Background())

	for leafIdx := int64(0); leafIdx < 7; leafIdx++ {
		proof, err := log.InclusionProof(context.Background(), leafIdx, sth.LogSize)
		if err != nil {
			t.Fatalf("InclusionProof leaf %d: %v", leafIdx, err)
		}
		var root [32]byte
		decoded, _ := base64.StdEncoding.DecodeString(sth.RootHash)
		copy(root[:], decoded)
		if err := transparency.VerifyInclusionProof(*proof, root); err != nil {
			t.Errorf("VerifyInclusionProof leaf %d: %v", leafIdx, err)
		}
	}
}

// TestLogConsistencyProof confirms a consistency proof from an
// earlier tree size to a later one verifies against both roots.
func TestLogConsistencyProof(t *testing.T) {
	log, _ := newTestLog(t)
	for i := 0; i < 3; i++ {
		_, _ = log.Append(context.Background(), sampleEntry(i))
	}
	earlySTH, _ := log.IssueSTH(context.Background())
	for i := 3; i < 8; i++ {
		_, _ = log.Append(context.Background(), sampleEntry(i))
	}
	laterSTH, _ := log.IssueSTH(context.Background())
	proof, err := log.ConsistencyProof(context.Background(), earlySTH.LogSize, laterSTH.LogSize)
	if err != nil {
		t.Fatalf("ConsistencyProof: %v", err)
	}
	var firstRoot, secondRoot [32]byte
	d1, _ := base64.StdEncoding.DecodeString(earlySTH.RootHash)
	copy(firstRoot[:], d1)
	d2, _ := base64.StdEncoding.DecodeString(laterSTH.RootHash)
	copy(secondRoot[:], d2)
	if err := transparency.VerifyConsistencyProof(*proof, firstRoot, secondRoot); err != nil {
		t.Errorf("VerifyConsistencyProof: %v", err)
	}
}

// TestLogEntryNotFound confirms an out-of-range index returns the
// typed sentinel.
func TestLogEntryNotFound(t *testing.T) {
	log, _ := newTestLog(t)
	if _, err := log.Entry(context.Background(), 0); err == nil {
		t.Error("Entry on empty log should fail")
	}
	_, _ = log.Append(context.Background(), sampleEntry(0))
	if _, err := log.Entry(context.Background(), 99); err == nil {
		t.Error("Entry on out-of-range should fail")
	}
}

// TestLogInclusionProofRejectsBadIndex confirms invalid arguments
// return typed sentinels.
func TestLogInclusionProofRejectsBadIndex(t *testing.T) {
	log, _ := newTestLog(t)
	for i := 0; i < 3; i++ {
		_, _ = log.Append(context.Background(), sampleEntry(i))
	}
	if _, err := log.InclusionProof(context.Background(), 0, 0); err == nil {
		t.Error("treeSize=0 accepted")
	}
	if _, err := log.InclusionProof(context.Background(), 5, 3); err == nil {
		t.Error("leafIndex >= treeSize accepted")
	}
	if _, err := log.InclusionProof(context.Background(), 0, 99); err == nil {
		t.Error("treeSize > current size accepted")
	}
}

// TestLogConsistencyProofRejectsBadSizes confirms ordering /
// out-of-range sizes are caught.
func TestLogConsistencyProofRejectsBadSizes(t *testing.T) {
	log, _ := newTestLog(t)
	for i := 0; i < 3; i++ {
		_, _ = log.Append(context.Background(), sampleEntry(i))
	}
	if _, err := log.ConsistencyProof(context.Background(), 5, 3); err == nil {
		t.Error("from > to accepted")
	}
	if _, err := log.ConsistencyProof(context.Background(), 0, 1); err == nil {
		t.Error("from = 0 accepted")
	}
	if _, err := log.ConsistencyProof(context.Background(), 1, 99); err == nil {
		t.Error("to > current size accepted")
	}
}
