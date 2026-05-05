package recovery_test

import (
	"encoding/base64"
	"testing"
	"time"

	"semp.dev/semp-go/crypto"
	"semp.dev/semp-go/recovery"
)

func newKeypair(t *testing.T) (pub, priv []byte, fp string) {
	t.Helper()
	signer := crypto.SuiteBaseline.Signer()
	pub, priv, err := signer.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	return pub, priv, base64.StdEncoding.EncodeToString(pub)[:16] // truncate as fingerprint
}

// TestSuccessorRecordRoundTrip exercises the §7.2 happy path:
// recovery sig + new-key sig + domain sig all round-trip and verify.
func TestSuccessorRecordRoundTrip(t *testing.T) {
	signer := crypto.SuiteBaseline.Signer()
	recPub, recPriv, recFP := newKeypair(t)
	newPub, newPriv, newFP := newKeypair(t)
	domPub, domPriv, domFP := newKeypair(t)

	r := &recovery.SuccessorRecord{
		UserID:       "alice@example.com",
		PriorKeyID:   "old-fp",
		NewKeyID:     newFP,
		NewPublicKey: base64.StdEncoding.EncodeToString(newPub),
		RecoveredAt:  time.Now().UTC(),
	}
	recovery.PrepareSuccessorSignatures(r, recFP, newFP, domFP)
	if err := recovery.SignSuccessorRecovery(signer, recPriv, recFP, r); err != nil {
		t.Fatalf("SignSuccessorRecovery: %v", err)
	}
	if err := recovery.SignSuccessorNewKey(signer, newPriv, newFP, r); err != nil {
		t.Fatalf("SignSuccessorNewKey: %v", err)
	}
	if err := recovery.SignSuccessorDomain(signer, domPriv, domFP, r); err != nil {
		t.Fatalf("SignSuccessorDomain: %v", err)
	}
	if err := recovery.VerifySuccessorRecord(signer, r, recPub, newPub, domPub); err != nil {
		t.Errorf("VerifySuccessorRecord: %v", err)
	}
}

// TestSuccessorRecordTamperRecovery confirms a mutation to a covered
// field breaks all three signatures (each covers the same canonical
// bytes per §7.3).
func TestSuccessorRecordTamperRecovery(t *testing.T) {
	signer := crypto.SuiteBaseline.Signer()
	recPub, recPriv, recFP := newKeypair(t)
	newPub, newPriv, newFP := newKeypair(t)
	domPub, domPriv, domFP := newKeypair(t)

	r := &recovery.SuccessorRecord{
		UserID:       "alice@example.com",
		PriorKeyID:   "old-fp",
		NewKeyID:     newFP,
		NewPublicKey: base64.StdEncoding.EncodeToString(newPub),
		RecoveredAt:  time.Now().UTC(),
	}
	recovery.PrepareSuccessorSignatures(r, recFP, newFP, domFP)
	if err := recovery.SignSuccessorRecovery(signer, recPriv, recFP, r); err != nil {
		t.Fatalf("SignSuccessorRecovery: %v", err)
	}
	if err := recovery.SignSuccessorNewKey(signer, newPriv, newFP, r); err != nil {
		t.Fatalf("SignSuccessorNewKey: %v", err)
	}
	if err := recovery.SignSuccessorDomain(signer, domPriv, domFP, r); err != nil {
		t.Fatalf("SignSuccessorDomain: %v", err)
	}

	// Tamper with NewKeyID; all three signatures cover it.
	r.NewKeyID = "attacker-fp"
	if err := recovery.VerifySuccessorRecord(signer, r, recPub, newPub, domPub); err == nil {
		t.Error("VerifySuccessorRecord accepted a tampered NewKeyID")
	}
}

// TestSuccessorRecordWrongRecoveryPub confirms the recovery
// signature's verifier rejects a substitute public key.
func TestSuccessorRecordWrongRecoveryPub(t *testing.T) {
	signer := crypto.SuiteBaseline.Signer()
	_, recPriv, recFP := newKeypair(t)
	newPub, newPriv, newFP := newKeypair(t)
	domPub, domPriv, domFP := newKeypair(t)
	wrongRecPub, _, _ := newKeypair(t)

	r := &recovery.SuccessorRecord{
		UserID:       "alice@example.com",
		PriorKeyID:   "old-fp",
		NewKeyID:     newFP,
		NewPublicKey: base64.StdEncoding.EncodeToString(newPub),
		RecoveredAt:  time.Now().UTC(),
	}
	recovery.PrepareSuccessorSignatures(r, recFP, newFP, domFP)
	_ = recovery.SignSuccessorRecovery(signer, recPriv, recFP, r)
	_ = recovery.SignSuccessorNewKey(signer, newPriv, newFP, r)
	_ = recovery.SignSuccessorDomain(signer, domPriv, domFP, r)

	if err := recovery.VerifySuccessorRecord(signer, r, wrongRecPub, newPub, domPub); err == nil {
		t.Error("VerifySuccessorRecord accepted a wrong recovery_verify_pk")
	}
}

// TestRecoverySetManifestRoundTrip exercises the §5.2 happy path.
func TestRecoverySetManifestRoundTrip(t *testing.T) {
	signer := crypto.SuiteBaseline.Signer()
	idPub, idPriv, idFP := newKeypair(t)

	dev1Pub, _, _ := newKeypair(t)
	dev2Pub, _, _ := newKeypair(t)
	dev3Pub, _, _ := newKeypair(t)

	mkContrib := func(idx int, devID string, pub []byte) recovery.RecoveryContributor {
		return recovery.RecoveryContributor{
			ShareIndex: idx,
			DeviceID:   devID,
			DeviceIdentityPubkey: recovery.DeviceIdentityPubkey{
				Algorithm: "ed25519",
				PublicKey: base64.StdEncoding.EncodeToString(pub),
				KeyID:     base64.StdEncoding.EncodeToString(pub)[:16],
			},
		}
	}

	m := &recovery.RecoverySetManifest{
		BundleID:    "01JBUNDLE000000000000000001",
		Threshold:   2,
		TotalShares: 3,
		Contributors: []recovery.RecoveryContributor{
			mkContrib(1, "device-1", dev1Pub),
			mkContrib(2, "device-2", dev2Pub),
			mkContrib(3, "device-3", dev3Pub),
		},
		IssuedAt: time.Now().UTC(),
	}
	if err := recovery.SignManifest(signer, idPriv, idFP, m); err != nil {
		t.Fatalf("SignManifest: %v", err)
	}
	if err := recovery.VerifyManifest(signer, idPub, m); err != nil {
		t.Errorf("VerifyManifest: %v", err)
	}
}

// TestRecoverySetManifestRejectsDuplicates confirms §5.2's
// uniqueness rules on share_index and device_id.
func TestRecoverySetManifestRejectsDuplicates(t *testing.T) {
	signer := crypto.SuiteBaseline.Signer()
	_, idPriv, idFP := newKeypair(t)

	devPub, _, _ := newKeypair(t)
	contrib := recovery.RecoveryContributor{
		ShareIndex: 1,
		DeviceID:   "device-x",
		DeviceIdentityPubkey: recovery.DeviceIdentityPubkey{
			Algorithm: "ed25519",
			PublicKey: base64.StdEncoding.EncodeToString(devPub),
			KeyID:     "fp",
		},
	}
	dupIdx := &recovery.RecoverySetManifest{
		BundleID: "b", Threshold: 1, TotalShares: 2, IssuedAt: time.Now().UTC(),
		Contributors: []recovery.RecoveryContributor{
			contrib,
			{ShareIndex: 1, DeviceID: "device-y", DeviceIdentityPubkey: contrib.DeviceIdentityPubkey},
		},
	}
	if err := recovery.SignManifest(signer, idPriv, idFP, dupIdx); err == nil {
		t.Error("SignManifest accepted a manifest with duplicate share_index")
	}

	dupDev := &recovery.RecoverySetManifest{
		BundleID: "b", Threshold: 1, TotalShares: 2, IssuedAt: time.Now().UTC(),
		Contributors: []recovery.RecoveryContributor{
			contrib,
			{ShareIndex: 2, DeviceID: "device-x", DeviceIdentityPubkey: contrib.DeviceIdentityPubkey},
		},
	}
	if err := recovery.SignManifest(signer, idPriv, idFP, dupDev); err == nil {
		t.Error("SignManifest accepted a manifest with duplicate device_id")
	}
}

// TestRecoverySetManifestRejectsThresholdMismatch covers the
// invariant total_shares >= threshold and contributors.length ==
// total_shares.
func TestRecoverySetManifestRejectsThresholdMismatch(t *testing.T) {
	signer := crypto.SuiteBaseline.Signer()
	_, idPriv, idFP := newKeypair(t)

	bad := &recovery.RecoverySetManifest{
		BundleID: "b", Threshold: 5, TotalShares: 3, IssuedAt: time.Now().UTC(),
	}
	if err := recovery.SignManifest(signer, idPriv, idFP, bad); err == nil {
		t.Error("SignManifest accepted total_shares < threshold")
	}

	bad2 := &recovery.RecoverySetManifest{
		BundleID: "b", Threshold: 2, TotalShares: 3, IssuedAt: time.Now().UTC(),
		Contributors: []recovery.RecoveryContributor{ /* empty - length != total_shares */ },
	}
	if err := recovery.SignManifest(signer, idPriv, idFP, bad2); err == nil {
		t.Error("SignManifest accepted contributors length != total_shares")
	}
}

// TestShareRecordRoundTrip exercises the §5.3 happy path.
func TestShareRecordRoundTrip(t *testing.T) {
	signer := crypto.SuiteBaseline.Signer()
	devPub, devPriv, devFP := newKeypair(t)

	share := &recovery.RecoveryShareRecord{
		BundleID:    "01JBUNDLE000000000000000001",
		ShareIndex:  1,
		DeviceID:    "device-1",
		Threshold:   2,
		TotalShares: 3,
		ShareValue:  base64.StdEncoding.EncodeToString([]byte("share-bytes-here")),
		IssuedAt:    time.Now().UTC(),
	}
	if err := recovery.SignShareRecord(signer, devPriv, devFP, share); err != nil {
		t.Fatalf("SignShareRecord: %v", err)
	}
	if err := recovery.VerifyShareRecord(signer, devPub, share); err != nil {
		t.Errorf("VerifyShareRecord: %v", err)
	}
}

// TestCheckShareMatchesManifest covers the §5.3 step-2 cross-check
// that a share's bundle_id, share_index, device_id, threshold, and
// total_shares all match the manifest's contributor entry.
func TestCheckShareMatchesManifest(t *testing.T) {
	devPub, _, _ := newKeypair(t)
	contrib := recovery.RecoveryContributor{
		ShareIndex: 2,
		DeviceID:   "device-2",
		DeviceIdentityPubkey: recovery.DeviceIdentityPubkey{
			Algorithm: "ed25519",
			PublicKey: base64.StdEncoding.EncodeToString(devPub),
			KeyID:     "fp-2",
		},
	}
	m := &recovery.RecoverySetManifest{
		BundleID: "01JBUNDLE000000000000000001", Threshold: 2, TotalShares: 3,
		IssuedAt:     time.Now().UTC(),
		Contributors: []recovery.RecoveryContributor{contrib},
	}
	good := &recovery.RecoveryShareRecord{
		BundleID: "01JBUNDLE000000000000000001", ShareIndex: 2, DeviceID: "device-2",
		Threshold: 2, TotalShares: 3, ShareValue: "v", IssuedAt: time.Now().UTC(),
	}
	if err := recovery.CheckShareMatchesManifest(good, m); err != nil {
		t.Errorf("matching share+manifest: got %v, want nil", err)
	}

	cases := []struct {
		name   string
		mutate func(s *recovery.RecoveryShareRecord)
	}{
		{"bundle mismatch", func(s *recovery.RecoveryShareRecord) { s.BundleID = "other-bundle" }},
		{"index missing in manifest", func(s *recovery.RecoveryShareRecord) { s.ShareIndex = 1 }},
		{"device mismatch", func(s *recovery.RecoveryShareRecord) { s.DeviceID = "attacker-device" }},
		{"threshold mismatch", func(s *recovery.RecoveryShareRecord) { s.Threshold = 3 }},
		{"total_shares mismatch", func(s *recovery.RecoveryShareRecord) { s.TotalShares = 5 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := *good
			tc.mutate(&s)
			if err := recovery.CheckShareMatchesManifest(&s, m); err == nil {
				t.Errorf("%s: want error, got nil", tc.name)
			}
		})
	}
}
