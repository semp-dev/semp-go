package migration_test

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/semp-dev/semp-go/crypto"
	"github.com/semp-dev/semp-go/migration"
)

// keypairs returns three identity-style keypairs we reuse across
// the orchestration tests: old user identity, new user identity,
// new domain. The old domain key pair is added by AcceptSubmission.
type keypairs struct {
	oldIDPub, oldIDPriv []byte
	newIDPub, newIDPriv []byte
	newDomPub, newDomPriv []byte
	oldDomPub, oldDomPriv []byte
}

func newKeypairs(t *testing.T) keypairs {
	t.Helper()
	signer := crypto.SuiteBaseline.Signer()
	pubA, privA, err := signer.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair A: %v", err)
	}
	pubB, privB, err := signer.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair B: %v", err)
	}
	pubC, privC, err := signer.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair C: %v", err)
	}
	pubD, privD, err := signer.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair D: %v", err)
	}
	return keypairs{
		oldIDPub: pubA, oldIDPriv: privA,
		newIDPub: pubB, newIDPriv: privB,
		newDomPub: pubC, newDomPriv: privC,
		oldDomPub: pubD, oldDomPriv: privD,
	}
}

// submission builds a fresh cooperative SubmitInput populated with
// the given keypairs.
func submission(kp keypairs, mode migration.Mode) migration.SubmitInput {
	return migration.SubmitInput{
		Suite:                crypto.SuiteBaseline,
		OldAddress:           "alice@old.example",
		NewAddress:           "alice@new.example",
		OldIdentityKeyID:     "old-fp",
		NewIdentityKeyID:     "new-fp",
		OldIdentityPriv:      kp.oldIDPriv,
		NewIdentityPriv:      kp.newIDPriv,
		NewIdentityPublicKey: base64.StdEncoding.EncodeToString(kp.newIDPub),
		NewDomainKeyID:       "new-domain-fp",
		NewDomainPriv:        kp.newDomPriv,
		OldDomainKeyID:       "old-domain-fp",
		Mode:                 mode,
		NoticeWindow:     migration.RecommendedNoticeWindow,
		MigratedAt:           time.Now().UTC().Truncate(time.Second),
	}
}

// TestBuildSubmissionCooperative drives the §4.1 steps 3-7 happy
// path and confirms the three submitted signatures are present and
// the old_domain slot is allocated but empty.
func TestBuildSubmissionCooperative(t *testing.T) {
	kp := newKeypairs(t)
	r, err := migration.BuildSubmission(submission(kp, migration.ModeCooperative))
	if err != nil {
		t.Fatalf("BuildSubmission: %v", err)
	}
	if r.OldIdentitySignature.Value == "" || r.NewIdentitySignature.Value == "" || r.NewDomainSignature.Value == "" {
		t.Errorf("not all three submitted signatures populated: %+v", r)
	}
	if r.OldDomainSignature == nil || r.OldDomainSignature.Value != "" {
		t.Errorf("old_domain_signature should be allocated but unsigned, got %+v", r.OldDomainSignature)
	}
	if r.NoticeWindowUntil == nil {
		t.Error("NoticeWindowUntil should be set in cooperative mode")
	}
}

// TestBuildSubmissionUnilateral confirms the unilateral branch:
// three sigs, no old_domain slot, NoticeWindowUntil nil.
func TestBuildSubmissionUnilateral(t *testing.T) {
	kp := newKeypairs(t)
	r, err := migration.BuildSubmission(submission(kp, migration.ModeUnilateral))
	if err != nil {
		t.Fatalf("BuildSubmission unilateral: %v", err)
	}
	if r.OldDomainSignature != nil {
		t.Errorf("unilateral record should NOT have old_domain_signature slot, got %+v", r.OldDomainSignature)
	}
	if r.NoticeWindowUntil != nil {
		t.Errorf("unilateral NoticeWindowUntil should be nil, got %s", r.NoticeWindowUntil)
	}
}

// TestBuildSubmissionRejectsBadWindow walks each NoticeWindow
// rejection path.
func TestBuildSubmissionRejectsBadWindow(t *testing.T) {
	kp := newKeypairs(t)
	cases := []struct {
		name   string
		window time.Duration
	}{
		{"zero", 0},
		{"below min", migration.MinNoticeWindow - time.Hour},
		{"above max", migration.MaxNoticeWindow + time.Hour},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := submission(kp, migration.ModeCooperative)
			in.NoticeWindow = tc.window
			if _, err := migration.BuildSubmission(in); err == nil {
				t.Error("BuildSubmission accepted out-of-bounds window")
			}
		})
	}
}

// TestAcceptSubmissionRoundTrip covers the §4.1 step 8 happy path:
// new provider builds, old provider verifies + countersigns, full
// 4-sig record verifies via VerifyMigrationRecord.
func TestAcceptSubmissionRoundTrip(t *testing.T) {
	kp := newKeypairs(t)
	submitted, err := migration.BuildSubmission(submission(kp, migration.ModeCooperative))
	if err != nil {
		t.Fatalf("BuildSubmission: %v", err)
	}
	now := submitted.MigratedAt.Add(time.Minute)
	final, err := migration.AcceptSubmission(context.Background(), migration.AcceptInput{
		Suite:              crypto.SuiteBaseline,
		Record:             submitted,
		OldIdentityPub:     kp.oldIDPub,
		NewDomainPub:       kp.newDomPub,
		OldDomainKeyID:     "old-domain-fp",
		OldDomainPriv:      kp.oldDomPriv,
		Now:                now,
		OldIdentityCreated: submitted.MigratedAt.Add(-30 * 24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("AcceptSubmission: %v", err)
	}
	if final.OldDomainSignature == nil || final.OldDomainSignature.Value == "" {
		t.Fatalf("AcceptSubmission did not populate old_domain_signature: %+v", final.OldDomainSignature)
	}
	// Full 4-sig verification using the existing verifier.
	if err := migration.VerifyMigrationRecord(crypto.SuiteBaseline.Signer(), final,
		kp.oldIDPub, kp.newIDPub, kp.newDomPub, kp.oldDomPub); err != nil {
		t.Errorf("VerifyMigrationRecord on completed record: %v", err)
	}
}

// TestAcceptSubmissionRejectsUnilateral confirms the old endpoint
// refuses unilateral records (the old provider is not a participant
// in unilateral migration).
func TestAcceptSubmissionRejectsUnilateral(t *testing.T) {
	kp := newKeypairs(t)
	submitted, err := migration.BuildSubmission(submission(kp, migration.ModeUnilateral))
	if err != nil {
		t.Fatalf("BuildSubmission: %v", err)
	}
	_, err = migration.AcceptSubmission(context.Background(), migration.AcceptInput{
		Suite:              crypto.SuiteBaseline,
		Record:             submitted,
		OldIdentityPub:     kp.oldIDPub,
		NewDomainPub:       kp.newDomPub,
		OldDomainKeyID:     "old-domain-fp",
		OldDomainPriv:      kp.oldDomPriv,
		Now:                time.Now().UTC(),
		OldIdentityCreated: time.Now().UTC().Add(-time.Hour),
	})
	if err == nil {
		t.Error("AcceptSubmission accepted unilateral record")
	}
}

// TestAcceptSubmissionRejectsBadOldIdentitySig confirms the §4.2
// "MUST NOT countersign without verifying" rule fires when the
// supplied old_identity_pub does not match.
func TestAcceptSubmissionRejectsBadOldIdentitySig(t *testing.T) {
	kp := newKeypairs(t)
	submitted, _ := migration.BuildSubmission(submission(kp, migration.ModeCooperative))
	other := newKeypairs(t)
	_, err := migration.AcceptSubmission(context.Background(), migration.AcceptInput{
		Suite:              crypto.SuiteBaseline,
		Record:             submitted,
		OldIdentityPub:     other.oldIDPub, // wrong pubkey
		NewDomainPub:       kp.newDomPub,
		OldDomainKeyID:     "old-domain-fp",
		OldDomainPriv:      kp.oldDomPriv,
		Now:                submitted.MigratedAt.Add(time.Minute),
		OldIdentityCreated: submitted.MigratedAt.Add(-time.Hour),
	})
	if err == nil {
		t.Error("AcceptSubmission accepted record with mismatched old_identity_pub")
	}
}

// TestAcceptSubmissionNoticePolicy confirms the operator's
// per-window policy gate fires.
func TestAcceptSubmissionNoticePolicy(t *testing.T) {
	kp := newKeypairs(t)
	submitted, _ := migration.BuildSubmission(submission(kp, migration.ModeCooperative))
	policy := func(window time.Duration) error {
		if window > 60*24*time.Hour {
			return migration.ErrNoticeWindowRefused
		}
		return nil
	}
	_, err := migration.AcceptSubmission(context.Background(), migration.AcceptInput{
		Suite:              crypto.SuiteBaseline,
		Record:             submitted,
		OldIdentityPub:     kp.oldIDPub,
		NewDomainPub:       kp.newDomPub,
		OldDomainKeyID:     "old-domain-fp",
		OldDomainPriv:      kp.oldDomPriv,
		Now:                submitted.MigratedAt.Add(time.Minute),
		OldIdentityCreated: submitted.MigratedAt.Add(-time.Hour),
		NoticePolicy:   policy,
	})
	if err == nil {
		t.Fatal("AcceptSubmission accepted a window the operator policy refused")
	}
	if !errors.Is(err, migration.ErrNoticeWindowRefused) {
		t.Errorf("err does not wrap ErrNoticeWindowRefused: %v", err)
	}
}

// TestAcceptSubmissionLockoutDuplicate confirms the §4.2 "MUST NOT
// countersign a second migration record for the same old address
// while a prior record is in its forwarding window" rule fires
// when a Reservations registry sees a duplicate.
func TestAcceptSubmissionLockoutDuplicate(t *testing.T) {
	kp := newKeypairs(t)
	reg := migration.NewInMemoryLockoutRegistry()

	first, _ := migration.BuildSubmission(submission(kp, migration.ModeCooperative))
	if _, err := migration.AcceptSubmission(context.Background(), migration.AcceptInput{
		Suite:              crypto.SuiteBaseline,
		Record:             first,
		OldIdentityPub:     kp.oldIDPub,
		NewDomainPub:       kp.newDomPub,
		OldDomainKeyID:     "old-domain-fp",
		OldDomainPriv:      kp.oldDomPriv,
		Now:                first.MigratedAt.Add(time.Minute),
		OldIdentityCreated: first.MigratedAt.Add(-time.Hour),
		Reservations:       reg,
	}); err != nil {
		t.Fatalf("Accept first: %v", err)
	}

	second, _ := migration.BuildSubmission(submission(kp, migration.ModeCooperative))
	_, err := migration.AcceptSubmission(context.Background(), migration.AcceptInput{
		Suite:              crypto.SuiteBaseline,
		Record:             second,
		OldIdentityPub:     kp.oldIDPub,
		NewDomainPub:       kp.newDomPub,
		OldDomainKeyID:     "old-domain-fp",
		OldDomainPriv:      kp.oldDomPriv,
		Now:                second.MigratedAt.Add(time.Minute),
		OldIdentityCreated: second.MigratedAt.Add(-time.Hour),
		Reservations:       reg,
	})
	if !errors.Is(err, migration.ErrLocalPartLockedOut) {
		t.Errorf("Accept second: got %v, want ErrLocalPartLockedOut", err)
	}
}

// TestLockoutRegistryReleaseAndPrune covers the in-memory impl's
// lifecycle: Reserve -> IsLockedOut hits -> Release / Prune lifts.
func TestLockoutRegistryReleaseAndPrune(t *testing.T) {
	reg := migration.NewInMemoryLockoutRegistry()
	until := time.Now().UTC().Add(180 * 24 * time.Hour)
	if err := reg.Reserve(context.Background(), "alice", until, "rec-1"); err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	id, t1, locked, err := reg.IsLockedOut(context.Background(), "alice", time.Now().UTC())
	if err != nil || !locked || id != "rec-1" || !t1.Equal(until) {
		t.Errorf("IsLockedOut: got id=%q until=%s locked=%v err=%v", id, t1, locked, err)
	}
	// Release lifts the entry.
	if err := reg.Release(context.Background(), "alice"); err != nil {
		t.Fatalf("Release: %v", err)
	}
	if _, _, locked, _ := reg.IsLockedOut(context.Background(), "alice", time.Now().UTC()); locked {
		t.Error("IsLockedOut returned locked after Release")
	}
	// Prune sweeps expired entries.
	expired := time.Now().UTC().Add(-time.Hour)
	_ = reg.Reserve(context.Background(), "carol", expired, "rec-2")
	removed, _ := reg.PruneExpired(context.Background(), time.Now().UTC())
	if removed != 1 {
		t.Errorf("PruneExpired: removed=%d, want 1", removed)
	}
}

// TestMigrationNoticeBuilder confirms the §5.3 notice carries the
// expected fields and the URL pattern substitution works.
func TestMigrationNoticeBuilder(t *testing.T) {
	r := &migration.MigrationRecord{
		RecordID:   "rec-ulid",
		NewAddress: "alice@new.example",
	}
	notice, err := migration.BuildMigrationNotice(r,
		"https://old.example/.well-known/semp/migration/<record_id>")
	if err != nil {
		t.Fatalf("BuildMigrationNotice: %v", err)
	}
	if notice.NewAddress != "alice@new.example" {
		t.Errorf("NewAddress = %q", notice.NewAddress)
	}
	if notice.MigrationRecordID != "rec-ulid" {
		t.Errorf("MigrationRecordID = %q", notice.MigrationRecordID)
	}
	want := "https://old.example/.well-known/semp/migration/rec-ulid"
	if notice.MigrationRecordURL != want {
		t.Errorf("MigrationRecordURL = %q, want %q", notice.MigrationRecordURL, want)
	}
}

// TestMigrationNoticeRejectionShape pins the §5.3 envelope-rejection
// wire fields.
func TestMigrationNoticeRejectionShape(t *testing.T) {
	notice := migration.MigrationNotice{
		NewAddress:        "alice@new.example",
		MigrationRecordID: "rec-1",
	}
	rej := migration.NewMigrationNoticeRejection(notice, "")
	if rej.Type != "SEMP_ENVELOPE" || rej.Step != "rejected" || rej.ReasonCode != "policy_forbidden" {
		t.Errorf("rejection fields wrong: %+v", rej)
	}
	if rej.Reason == "" {
		t.Error("default reason should not be empty")
	}
	if rej.MigrationNotice != notice {
		t.Errorf("MigrationNotice round-trip mismatch")
	}
}

// TestVerifyThirdPartyCooperative confirms a successful 3rd-party
// verification on a cooperative record.
func TestVerifyThirdPartyCooperative(t *testing.T) {
	kp := newKeypairs(t)
	submitted, _ := migration.BuildSubmission(submission(kp, migration.ModeCooperative))
	final, err := migration.AcceptSubmission(context.Background(), migration.AcceptInput{
		Suite:              crypto.SuiteBaseline,
		Record:             submitted,
		OldIdentityPub:     kp.oldIDPub,
		NewDomainPub:       kp.newDomPub,
		OldDomainKeyID:     "old-domain-fp",
		OldDomainPriv:      kp.oldDomPriv,
		Now:                submitted.MigratedAt.Add(time.Minute),
		OldIdentityCreated: submitted.MigratedAt.Add(-time.Hour),
	})
	if err != nil {
		t.Fatalf("AcceptSubmission: %v", err)
	}
	if err := migration.VerifyThirdParty(migration.ThirdPartyVerifyInput{
		Suite:          crypto.SuiteBaseline,
		Record:         final,
		OldIdentityPub: kp.oldIDPub,
		NewDomainPub:   kp.newDomPub,
		OldDomainPub:   kp.oldDomPub,
	}); err != nil {
		t.Errorf("VerifyThirdParty: %v", err)
	}
}

// TestVerifyThirdPartyUnilateral confirms unilateral records pass
// without an old domain pubkey.
func TestVerifyThirdPartyUnilateral(t *testing.T) {
	kp := newKeypairs(t)
	r, _ := migration.BuildSubmission(submission(kp, migration.ModeUnilateral))
	if err := migration.VerifyThirdParty(migration.ThirdPartyVerifyInput{
		Suite:          crypto.SuiteBaseline,
		Record:         r,
		OldIdentityPub: kp.oldIDPub,
		NewDomainPub:   kp.newDomPub,
	}); err != nil {
		t.Errorf("VerifyThirdParty unilateral: %v", err)
	}
}

// TestApplyThirdPartyPolicyRunsAllHooks confirms every non-nil hook
// fires in spec order against an already-verified record.
func TestApplyThirdPartyPolicyRunsAllHooks(t *testing.T) {
	r := &migration.MigrationRecord{RecordID: "rec-1"}
	var calls []string
	hook := func(name string) migration.ThirdPartyHook {
		return func(_ context.Context, _ *migration.MigrationRecord) error {
			calls = append(calls, name)
			return nil
		}
	}
	policy := migration.ThirdPartyPolicy{
		UpdateKnownCorrespondents: hook("UpdateKnownCorrespondents"),
		CarryReputation:           hook("CarryReputation"),
		MigrateBlockListEntries:   hook("MigrateBlockListEntries"),
	}
	if err := migration.ApplyThirdPartyPolicy(context.Background(), r, policy); err != nil {
		t.Fatalf("ApplyThirdPartyPolicy: %v", err)
	}
	want := []string{"UpdateKnownCorrespondents", "CarryReputation", "MigrateBlockListEntries"}
	if len(calls) != len(want) {
		t.Fatalf("calls = %v, want %v", calls, want)
	}
	for i := range want {
		if calls[i] != want[i] {
			t.Errorf("call[%d] = %q, want %q", i, calls[i], want[i])
		}
	}
}

// TestApplyThirdPartyPolicySkipsNilHooks confirms nil hooks are
// silently skipped without aborting the run.
func TestApplyThirdPartyPolicySkipsNilHooks(t *testing.T) {
	r := &migration.MigrationRecord{RecordID: "rec-1"}
	called := false
	policy := migration.ThirdPartyPolicy{
		MigrateBlockListEntries: func(_ context.Context, _ *migration.MigrationRecord) error {
			called = true
			return nil
		},
	}
	if err := migration.ApplyThirdPartyPolicy(context.Background(), r, policy); err != nil {
		t.Fatalf("ApplyThirdPartyPolicy with nil hooks: %v", err)
	}
	if !called {
		t.Error("non-nil hook should still run when others are nil")
	}
}

// TestApplyThirdPartyPolicyAggregatesErrors confirms hook errors
// surface as *ThirdPartyPolicyErrors.
func TestApplyThirdPartyPolicyAggregatesErrors(t *testing.T) {
	r := &migration.MigrationRecord{RecordID: "rec-1"}
	policy := migration.ThirdPartyPolicy{
		UpdateKnownCorrespondents: func(_ context.Context, _ *migration.MigrationRecord) error {
			return errors.New("transport failure")
		},
		CarryReputation: func(_ context.Context, _ *migration.MigrationRecord) error {
			return nil // should still run
		},
		MigrateBlockListEntries: func(_ context.Context, _ *migration.MigrationRecord) error {
			return errors.New("schema issue")
		},
	}
	err := migration.ApplyThirdPartyPolicy(context.Background(), r, policy)
	if err == nil {
		t.Fatal("expected error")
	}
	var pe *migration.ThirdPartyPolicyErrors
	if !errors.As(err, &pe) {
		t.Fatalf("error is not *ThirdPartyPolicyErrors: %v", err)
	}
	if len(pe.Steps) != 2 {
		t.Errorf("error count = %d, want 2", len(pe.Steps))
	}
}
