package migration_test

import (
	"encoding/base64"
	"testing"
	"time"

	"semp.dev/semp-go/crypto"
	"semp.dev/semp-go/migration"
)

func newKeypair(t *testing.T) (pub, priv []byte, fp string) {
	t.Helper()
	signer := crypto.SuiteBaseline.Signer()
	pub, priv, err := signer.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	return pub, priv, base64.StdEncoding.EncodeToString(pub)[:16]
}

// TestCooperativeMigrationRoundTrip exercises the §3.3 four-pass
// signing sequence and verifies all four signatures.
func TestCooperativeMigrationRoundTrip(t *testing.T) {
	signer := crypto.SuiteBaseline.Signer()
	oldIDPub, oldIDPriv, oldIDFP := newKeypair(t)
	newIDPub, newIDPriv, newIDFP := newKeypair(t)
	newDomPub, newDomPriv, newDomFP := newKeypair(t)
	oldDomPub, oldDomPriv, oldDomFP := newKeypair(t)

	migratedAt := time.Now().UTC()
	until := migratedAt.Add(180 * 24 * time.Hour)
	r := &migration.MigrationRecord{
		RecordID:              "01JMIGRATION00000000000001",
		OldAddress:            "alice@old.example",
		NewAddress:            "alice@new.example",
		OldIdentityKeyID:      oldIDFP,
		NewIdentityKeyID:      newIDFP,
		NewIdentityPublicKey:  base64.StdEncoding.EncodeToString(newIDPub),
		MigratedAt:            migratedAt,
		ForwardingWindowUntil: &until,
		Mode:                  migration.ModeCooperative,
	}
	migration.PrepareSignatures(r, oldIDFP, newIDFP, newDomFP, oldDomFP)
	if err := migration.SignOldIdentity(signer, oldIDPriv, oldIDFP, r); err != nil {
		t.Fatalf("SignOldIdentity: %v", err)
	}
	if err := migration.SignNewIdentity(signer, newIDPriv, newIDFP, r); err != nil {
		t.Fatalf("SignNewIdentity: %v", err)
	}
	if err := migration.SignNewDomain(signer, newDomPriv, newDomFP, r); err != nil {
		t.Fatalf("SignNewDomain: %v", err)
	}
	if err := migration.SignOldDomain(signer, oldDomPriv, oldDomFP, r); err != nil {
		t.Fatalf("SignOldDomain: %v", err)
	}
	if err := migration.VerifyMigrationRecord(signer, r, oldIDPub, newIDPub, newDomPub, oldDomPub); err != nil {
		t.Errorf("VerifyMigrationRecord: %v", err)
	}
}

// TestUnilateralMigrationRoundTrip exercises the three-signature
// unilateral mode (old provider does not participate).
func TestUnilateralMigrationRoundTrip(t *testing.T) {
	signer := crypto.SuiteBaseline.Signer()
	oldIDPub, oldIDPriv, oldIDFP := newKeypair(t)
	newIDPub, newIDPriv, newIDFP := newKeypair(t)
	newDomPub, newDomPriv, newDomFP := newKeypair(t)

	migratedAt := time.Now().UTC()
	r := &migration.MigrationRecord{
		RecordID:             "01JMIGRATION00000000000001",
		OldAddress:           "alice@old.example",
		NewAddress:           "alice@new.example",
		OldIdentityKeyID:     oldIDFP,
		NewIdentityKeyID:     newIDFP,
		NewIdentityPublicKey: base64.StdEncoding.EncodeToString(newIDPub),
		MigratedAt:           migratedAt,
		Mode:                 migration.ModeUnilateral,
	}
	migration.PrepareSignatures(r, oldIDFP, newIDFP, newDomFP, "")
	if err := migration.SignOldIdentity(signer, oldIDPriv, oldIDFP, r); err != nil {
		t.Fatalf("SignOldIdentity: %v", err)
	}
	if err := migration.SignNewIdentity(signer, newIDPriv, newIDFP, r); err != nil {
		t.Fatalf("SignNewIdentity: %v", err)
	}
	if err := migration.SignNewDomain(signer, newDomPriv, newDomFP, r); err != nil {
		t.Fatalf("SignNewDomain: %v", err)
	}
	// No old domain signature in unilateral mode.
	if err := migration.VerifyMigrationRecord(signer, r, oldIDPub, newIDPub, newDomPub, nil); err != nil {
		t.Errorf("VerifyMigrationRecord (unilateral): %v", err)
	}
}

// TestSignOrderEnforced confirms each pass refuses to run before
// its predecessor has populated the prior signature slot.
func TestSignOrderEnforced(t *testing.T) {
	signer := crypto.SuiteBaseline.Signer()
	_, oldIDPriv, oldIDFP := newKeypair(t)
	newIDPub, newIDPriv, newIDFP := newKeypair(t)
	_, newDomPriv, newDomFP := newKeypair(t)

	migratedAt := time.Now().UTC()
	until := migratedAt.Add(180 * 24 * time.Hour)
	r := &migration.MigrationRecord{
		RecordID:              "01JMIG",
		OldAddress:            "a@o",
		NewAddress:            "a@n",
		OldIdentityKeyID:      oldIDFP,
		NewIdentityKeyID:      newIDFP,
		NewIdentityPublicKey:  base64.StdEncoding.EncodeToString(newIDPub),
		MigratedAt:            migratedAt,
		ForwardingWindowUntil: &until,
		Mode:                  migration.ModeCooperative,
	}
	migration.PrepareSignatures(r, oldIDFP, newIDFP, newDomFP, "old-dom-fp")
	// SignNewIdentity before SignOldIdentity must fail.
	if err := migration.SignNewIdentity(signer, newIDPriv, newIDFP, r); err == nil {
		t.Error("SignNewIdentity before SignOldIdentity: want error")
	}
	if err := migration.SignOldIdentity(signer, oldIDPriv, oldIDFP, r); err != nil {
		t.Fatalf("SignOldIdentity: %v", err)
	}
	// SignNewDomain before SignNewIdentity must fail.
	if err := migration.SignNewDomain(signer, newDomPriv, newDomFP, r); err == nil {
		t.Error("SignNewDomain before SignNewIdentity: want error")
	}
}

// TestSignOldDomainRejectsUnilateral confirms the old-domain pass
// is forbidden in unilateral mode.
func TestSignOldDomainRejectsUnilateral(t *testing.T) {
	signer := crypto.SuiteBaseline.Signer()
	_, oldIDPriv, oldIDFP := newKeypair(t)
	newIDPub, newIDPriv, newIDFP := newKeypair(t)
	_, newDomPriv, newDomFP := newKeypair(t)
	_, oldDomPriv, oldDomFP := newKeypair(t)

	migratedAt := time.Now().UTC()
	r := &migration.MigrationRecord{
		RecordID:             "01JMIG",
		OldAddress:           "a@o",
		NewAddress:           "a@n",
		OldIdentityKeyID:     oldIDFP,
		NewIdentityKeyID:     newIDFP,
		NewIdentityPublicKey: base64.StdEncoding.EncodeToString(newIDPub),
		MigratedAt:           migratedAt,
		Mode:                 migration.ModeUnilateral,
	}
	migration.PrepareSignatures(r, oldIDFP, newIDFP, newDomFP, "")
	_ = migration.SignOldIdentity(signer, oldIDPriv, oldIDFP, r)
	_ = migration.SignNewIdentity(signer, newIDPriv, newIDFP, r)
	_ = migration.SignNewDomain(signer, newDomPriv, newDomFP, r)
	if err := migration.SignOldDomain(signer, oldDomPriv, oldDomFP, r); err == nil {
		t.Error("SignOldDomain in unilateral mode: want error")
	}
}

// TestVerifyTamperBreaksLaterSignatures confirms the §3.3 chained
// property: tampering with an early-signature value invalidates the
// later signatures that committed to it.
func TestVerifyTamperBreaksLaterSignatures(t *testing.T) {
	signer := crypto.SuiteBaseline.Signer()
	oldIDPub, oldIDPriv, oldIDFP := newKeypair(t)
	newIDPub, newIDPriv, newIDFP := newKeypair(t)
	newDomPub, newDomPriv, newDomFP := newKeypair(t)
	oldDomPub, oldDomPriv, oldDomFP := newKeypair(t)

	migratedAt := time.Now().UTC()
	until := migratedAt.Add(180 * 24 * time.Hour)
	r := &migration.MigrationRecord{
		RecordID:              "01JMIG",
		OldAddress:            "a@o",
		NewAddress:            "a@n",
		OldIdentityKeyID:      oldIDFP,
		NewIdentityKeyID:      newIDFP,
		NewIdentityPublicKey:  base64.StdEncoding.EncodeToString(newIDPub),
		MigratedAt:            migratedAt,
		ForwardingWindowUntil: &until,
		Mode:                  migration.ModeCooperative,
	}
	migration.PrepareSignatures(r, oldIDFP, newIDFP, newDomFP, oldDomFP)
	_ = migration.SignOldIdentity(signer, oldIDPriv, oldIDFP, r)
	_ = migration.SignNewIdentity(signer, newIDPriv, newIDFP, r)
	_ = migration.SignNewDomain(signer, newDomPriv, newDomFP, r)
	_ = migration.SignOldDomain(signer, oldDomPriv, oldDomFP, r)

	// Tamper with old_identity_signature.value AFTER all four
	// signatures land. The next-pass signatures committed to its
	// old value, so verification of new_identity (or beyond) MUST
	// fail.
	r.OldIdentitySignature.Value = "AAAA" + r.OldIdentitySignature.Value[4:]
	if err := migration.VerifyMigrationRecord(signer, r, oldIDPub, newIDPub, newDomPub, oldDomPub); err == nil {
		t.Error("VerifyMigrationRecord accepted a record whose old_identity_signature was mutated after later signatures committed")
	}
}

// TestForwardingWindowBounds covers the §5.1 hard bounds.
func TestForwardingWindowBounds(t *testing.T) {
	now := time.Now().UTC()
	cases := []struct {
		name   string
		window time.Duration
		ok     bool
	}{
		{"below minimum", 7 * 24 * time.Hour, false},
		{"at minimum", migration.MinForwardingWindow, true},
		{"recommended", migration.RecommendedForwardingWindow, true},
		{"at maximum", migration.MaxForwardingWindow, true},
		{"above maximum", migration.MaxForwardingWindow + 24*time.Hour, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			until := now.Add(tc.window)
			r := &migration.MigrationRecord{
				Type:                  migration.RecordType,
				Version:               migration.RecordVersion,
				RecordID:              "id",
				OldAddress:            "a@o",
				NewAddress:            "a@n",
				OldIdentityKeyID:      "old-fp",
				NewIdentityKeyID:      "new-fp",
				NewIdentityPublicKey:  "AAA=",
				MigratedAt:            now,
				ForwardingWindowUntil: &until,
				Mode:                  migration.ModeCooperative,
			}
			err := r.Validate()
			if tc.ok && err != nil {
				t.Errorf("Validate(%s): got %v, want nil", tc.name, err)
			}
			if !tc.ok && err == nil {
				t.Errorf("Validate(%s): want error, got nil", tc.name)
			}
		})
	}
}

// TestCheckMigratedAtBoundDetectsBackdating exercises the §3.3
// "MUST NOT precede old identity key's created" rule, the spec's
// defense against an attacker who has compromised both identity
// keys backdating a migration record.
func TestCheckMigratedAtBoundDetectsBackdating(t *testing.T) {
	now := time.Now().UTC()
	oldKeyCreated := now.Add(-10 * 24 * time.Hour)

	good := &migration.MigrationRecord{MigratedAt: now.Add(-time.Hour)}
	if err := migration.CheckMigratedAtBound(good, oldKeyCreated, now); err != nil {
		t.Errorf("good record: %v", err)
	}

	// migrated_at before old_key_created: forbidden.
	backdated := &migration.MigrationRecord{MigratedAt: oldKeyCreated.Add(-time.Hour)}
	if err := migration.CheckMigratedAtBound(backdated, oldKeyCreated, now); err == nil {
		t.Error("CheckMigratedAtBound accepted backdated migrated_at")
	}

	// migrated_at far in the future: forbidden by clockskew.
	future := &migration.MigrationRecord{MigratedAt: now.Add(2 * time.Hour)}
	if err := migration.CheckMigratedAtBound(future, oldKeyCreated, now); err == nil {
		t.Error("CheckMigratedAtBound accepted future migrated_at")
	}
}
