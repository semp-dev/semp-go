package migration_test

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"semp.dev/semp-go/crypto"
	"semp.dev/semp-go/extensions"
	"semp.dev/semp-go/migration"
)

// TestRecordWithExtensionsRoundTrip drives the §3.3 four-pass
// signing on a record that carries an extensions entry, and
// confirms the chain verifies. Pins the spec change in commit
// 4941913: the §3.3 four-signature chain covers `extensions`
// uniformly.
func TestRecordWithExtensionsRoundTrip(t *testing.T) {
	signer := crypto.SuiteBaseline.Signer()
	oldIDPub, oldIDPriv, oldIDFP := newKeypair(t)
	newIDPub, newIDPriv, newIDFP := newKeypair(t)
	newDomPub, newDomPriv, newDomFP := newKeypair(t)
	oldDomPub, oldDomPriv, oldDomFP := newKeypair(t)

	migratedAt := time.Now().UTC()
	until := migratedAt.Add(180 * 24 * time.Hour)
	r := &migration.MigrationRecord{
		RecordID:              "01JMIGRATION-EXT-0000000001",
		OldAddress:            "alice@old.example",
		NewAddress:            "alice@new.example",
		OldIdentityKeyID:      oldIDFP,
		NewIdentityKeyID:      newIDFP,
		NewIdentityPublicKey:  base64.StdEncoding.EncodeToString(newIDPub),
		MigratedAt:            migratedAt,
		ForwardingWindowUntil: &until,
		Mode:                  migration.ModeCooperative,
		Extensions: extensions.Map{
			"semp.dev/example-delegation": extensions.Entry{
				Required: false,
				Data: map[string]any{
					"reason":     "delegated forward",
					"key_id":     "user-identity-fp",
					"authorized": true,
				},
			},
		},
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
		t.Errorf("VerifyMigrationRecord with extensions: %v", err)
	}
}

// TestExtensionsTamperBreaksAllSignatures confirms a post-hoc
// modification of the extensions map invalidates every signature
// in the §3.3 chain. This pins the "all four signers cover
// extensions" spec property — without it, the extensions slot
// would not be safe to carry a delegation that downstream parties
// rely on.
func TestExtensionsTamperBreaksAllSignatures(t *testing.T) {
	signer := crypto.SuiteBaseline.Signer()
	oldIDPub, oldIDPriv, oldIDFP := newKeypair(t)
	newIDPub, newIDPriv, newIDFP := newKeypair(t)
	newDomPub, newDomPriv, newDomFP := newKeypair(t)
	oldDomPub, oldDomPriv, oldDomFP := newKeypair(t)

	migratedAt := time.Now().UTC()
	until := migratedAt.Add(180 * 24 * time.Hour)
	r := &migration.MigrationRecord{
		RecordID:              "01JMIGRATION-EXT-0000000002",
		OldAddress:            "alice@old.example",
		NewAddress:            "alice@new.example",
		OldIdentityKeyID:      oldIDFP,
		NewIdentityKeyID:      newIDFP,
		NewIdentityPublicKey:  base64.StdEncoding.EncodeToString(newIDPub),
		MigratedAt:            migratedAt,
		ForwardingWindowUntil: &until,
		Mode:                  migration.ModeCooperative,
		Extensions: extensions.Map{
			"semp.dev/witness": extensions.Entry{
				Required: false,
				Data:     map[string]any{"witness_id": "witness-A"},
			},
		},
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

	// Mutate the extensions data. This MUST invalidate the
	// signatures because all four covered extensions.
	r.Extensions["semp.dev/witness"] = extensions.Entry{
		Required: false,
		Data:     map[string]any{"witness_id": "witness-B-attacker"},
	}
	err := migration.VerifyMigrationRecord(signer, r, oldIDPub, newIDPub, newDomPub, oldDomPub)
	if err == nil {
		t.Fatal("VerifyMigrationRecord accepted post-hoc extensions mutation")
	}
	// First failure should be the old_identity pass, since the
	// chain verifies in §3.3 order.
	if !strings.Contains(err.Error(), "old_identity_signature") {
		t.Errorf("expected old_identity_signature failure first; got %v", err)
	}
}

// TestRecordWithoutExtensionsOmitsField pins the
// backwards-compatibility property: a record with no Extensions
// serializes WITHOUT an "extensions" key, so the wire shape is
// identical to records produced before commit 4941913.
func TestRecordWithoutExtensionsOmitsField(t *testing.T) {
	r := &migration.MigrationRecord{
		Type:                 migration.RecordType,
		Version:              migration.RecordVersion,
		RecordID:             "01JMIGRATION-EXT-0000000003",
		OldAddress:           "a@old.example",
		NewAddress:           "a@new.example",
		OldIdentityKeyID:     "old-fp",
		NewIdentityKeyID:     "new-fp",
		NewIdentityPublicKey: "AAAA",
		MigratedAt:           time.Now().UTC(),
		Mode:                 migration.ModeUnilateral,
	}
	bytes, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if strings.Contains(string(bytes), `"extensions"`) {
		t.Errorf("record without extensions should omit the field, got %s", bytes)
	}
}

// TestRecordWithEmptyExtensionsOmitsField confirms the omitempty
// path also fires when the field is set to an empty map (rather
// than nil). Operators that initialize Extensions as
// extensions.Map{} should still get the same wire shape as nil.
func TestRecordWithEmptyExtensionsOmitsField(t *testing.T) {
	r := &migration.MigrationRecord{
		Type:                 migration.RecordType,
		Version:              migration.RecordVersion,
		RecordID:             "01JMIGRATION-EXT-0000000004",
		OldAddress:           "a@old.example",
		NewAddress:           "a@new.example",
		OldIdentityKeyID:     "old-fp",
		NewIdentityKeyID:     "new-fp",
		NewIdentityPublicKey: "AAAA",
		MigratedAt:           time.Now().UTC(),
		Mode:                 migration.ModeUnilateral,
		Extensions:           extensions.Map{},
	}
	bytes, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if strings.Contains(string(bytes), `"extensions"`) {
		t.Errorf("record with empty extensions should omit the field, got %s", bytes)
	}
}
