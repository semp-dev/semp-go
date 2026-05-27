package keys_test

import (
	"context"
	"testing"
	"time"

	"github.com/semp-dev/semp-go/crypto"
	"github.com/semp-dev/semp-go/keys"
	"github.com/semp-dev/semp-go/recovery"
)

func newSigKeypair(t *testing.T) (pub, priv []byte, fp keys.Fingerprint) {
	t.Helper()
	signer := crypto.SuiteBaseline.Signer()
	pub, priv, err := signer.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	return pub, priv, keys.Compute(pub)
}

func newKEMKeypair(t *testing.T) (pub, priv []byte, fp keys.Fingerprint) {
	t.Helper()
	pub, priv, err := crypto.SuiteBaseline.KEM().GenerateKeyPair()
	if err != nil {
		t.Fatalf("KEM GenerateKeyPair: %v", err)
	}
	return pub, priv, keys.Compute(pub)
}

// TestCompromiseRotationRoundTrip confirms a full cascade builds,
// every device-side signature verifies, and the cross-checks pass.
func TestCompromiseRotationRoundTrip(t *testing.T) {
	suite := crypto.SuiteBaseline

	priorPub, priorPriv, priorFP := newSigKeypair(t)
	newIdPub, newIdPriv, newIdFP := newSigKeypair(t)
	_, _, newEncFP := newKEMKeypair(t)
	newEncPub, _, _ := newKEMKeypair(t)
	recoveryPub, recoveryPriv, _ := newSigKeypair(t)
	recoveryKeyID := "recovery-fp-001"

	rotation, err := keys.BuildCompromiseRotation(&keys.CompromiseRotationInput{
		Suite:               suite,
		UserID:              "alice@example.com",
		CompromisedDeviceID: "01JCOMPROMISED00000000000001",
		RevokingDeviceID:    "01JREVOKING000000000000000001",
		PriorIdentityPriv:   priorPriv,
		PriorIdentityFP:     priorFP,
		NewIdentityPriv:     newIdPriv,
		NewIdentityPub:      newIdPub,
		NewIdentityFP:       newIdFP,
		NewEncryptionPub:    newEncPub,
		NewEncryptionFP:     newEncFP,
		RecoveryPriv:        recoveryPriv,
		RecoveryKeyID:       recoveryKeyID,
		Now:                 time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("BuildCompromiseRotation: %v", err)
	}

	// Every artifact present.
	if rotation.DeviceRevocation == nil {
		t.Error("missing DeviceRevocation")
	}
	if rotation.Successor == nil {
		t.Error("missing Successor")
	}
	if rotation.PriorIdentityRevocation == nil {
		t.Error("missing PriorIdentityRevocation")
	}
	if string(rotation.NewIdentityKeyID) != string(newIdFP) {
		t.Errorf("NewIdentityKeyID mismatch")
	}

	// Successor sigs: recovery + new_key populated, domain empty.
	if rotation.Successor.RecoverySignature.Value == "" {
		t.Error("recovery_signature missing")
	}
	if rotation.Successor.NewKeySignature.Value == "" {
		t.Error("new_key_signature missing")
	}
	if rotation.Successor.DomainSignature.Value != "" {
		t.Error("domain_signature should be empty until home server adds it")
	}

	// Full verification (home server's path).
	if err := keys.VerifyCompromiseRotation(context.Background(), suite, rotation, priorPub, recoveryPub); err != nil {
		t.Errorf("VerifyCompromiseRotation: %v", err)
	}

	// Successor record's two-sig verify still passes through the
	// recovery package's own helper.
	if err := recovery.VerifySuccessorTwoSignatures(suite.Signer(), rotation.Successor, recoveryPub, newIdPub); err != nil {
		t.Errorf("recovery.VerifySuccessorTwoSignatures: %v", err)
	}
}

// TestCompromiseRotationVerifyRejectsTamperedReason confirms that
// flipping the device revocation reason away from key_compromise
// makes the cascade verifier fail (a partial cascade is a §10.5.5
// violation).
func TestCompromiseRotationVerifyRejectsTamperedReason(t *testing.T) {
	suite := crypto.SuiteBaseline
	priorPub, priorPriv, priorFP := newSigKeypair(t)
	newIdPub, newIdPriv, newIdFP := newSigKeypair(t)
	newEncPub, _, newEncFP := newKEMKeypair(t)
	recoveryPub, recoveryPriv, _ := newSigKeypair(t)

	rotation, err := keys.BuildCompromiseRotation(&keys.CompromiseRotationInput{
		Suite: suite, UserID: "alice@example.com",
		CompromisedDeviceID: "d-old", RevokingDeviceID: "d-new",
		PriorIdentityPriv: priorPriv, PriorIdentityFP: priorFP,
		NewIdentityPriv: newIdPriv, NewIdentityPub: newIdPub, NewIdentityFP: newIdFP,
		NewEncryptionPub: newEncPub, NewEncryptionFP: newEncFP,
		RecoveryPriv: recoveryPriv, RecoveryKeyID: "rfp",
	})
	if err != nil {
		t.Fatalf("BuildCompromiseRotation: %v", err)
	}
	rotation.DeviceRevocation.Reason = keys.DeviceRevocationLost
	if err := keys.VerifyCompromiseRotation(context.Background(), suite, rotation, priorPub, recoveryPub); err == nil {
		t.Error("VerifyCompromiseRotation accepted reason != key_compromise")
	}
}

// TestCompromiseRotationVerifyRejectsBadReplacement confirms the
// cross-check that prior_identity_revocation.replacement_key_id
// MUST equal cascade.new_identity_key_id.
func TestCompromiseRotationVerifyRejectsBadReplacement(t *testing.T) {
	suite := crypto.SuiteBaseline
	priorPub, priorPriv, priorFP := newSigKeypair(t)
	newIdPub, newIdPriv, newIdFP := newSigKeypair(t)
	newEncPub, _, newEncFP := newKEMKeypair(t)
	recoveryPub, recoveryPriv, _ := newSigKeypair(t)

	rotation, err := keys.BuildCompromiseRotation(&keys.CompromiseRotationInput{
		Suite: suite, UserID: "alice@example.com",
		CompromisedDeviceID: "d-old", RevokingDeviceID: "d-new",
		PriorIdentityPriv: priorPriv, PriorIdentityFP: priorFP,
		NewIdentityPriv: newIdPriv, NewIdentityPub: newIdPub, NewIdentityFP: newIdFP,
		NewEncryptionPub: newEncPub, NewEncryptionFP: newEncFP,
		RecoveryPriv: recoveryPriv, RecoveryKeyID: "rfp",
	})
	if err != nil {
		t.Fatalf("BuildCompromiseRotation: %v", err)
	}
	// Replace cascade.new_identity_key_id with a different fingerprint
	// AFTER the bundle is built. The signed prior-identity revocation
	// still names the original new fp; the cross-check catches the
	// mismatch.
	rotation.NewIdentityKeyID = "attacker-fp"
	if err := keys.VerifyCompromiseRotation(context.Background(), suite, rotation, priorPub, recoveryPub); err == nil {
		t.Error("VerifyCompromiseRotation accepted mismatched replacement_key_id")
	}
}

// TestCompromiseRotationVerifyRejectsWrongRecoveryPub confirms that
// the recovery_signature half of the successor record is verified
// against the right key.
func TestCompromiseRotationVerifyRejectsWrongRecoveryPub(t *testing.T) {
	suite := crypto.SuiteBaseline
	priorPub, priorPriv, priorFP := newSigKeypair(t)
	newIdPub, newIdPriv, newIdFP := newSigKeypair(t)
	newEncPub, _, newEncFP := newKEMKeypair(t)
	_, recoveryPriv, _ := newSigKeypair(t)
	wrongRecoveryPub, _, _ := newSigKeypair(t)

	rotation, err := keys.BuildCompromiseRotation(&keys.CompromiseRotationInput{
		Suite: suite, UserID: "alice@example.com",
		CompromisedDeviceID: "d-old", RevokingDeviceID: "d-new",
		PriorIdentityPriv: priorPriv, PriorIdentityFP: priorFP,
		NewIdentityPriv: newIdPriv, NewIdentityPub: newIdPub, NewIdentityFP: newIdFP,
		NewEncryptionPub: newEncPub, NewEncryptionFP: newEncFP,
		RecoveryPriv: recoveryPriv, RecoveryKeyID: "rfp",
	})
	if err != nil {
		t.Fatalf("BuildCompromiseRotation: %v", err)
	}
	if err := keys.VerifyCompromiseRotation(context.Background(), suite, rotation, priorPub, wrongRecoveryPub); err == nil {
		t.Error("VerifyCompromiseRotation accepted wrong recovery_verify_pk")
	}
}

// TestCompromiseRotationRejectsSameKeys confirms the input-time
// guard on identical prior and new identity fingerprints.
func TestCompromiseRotationRejectsSameKeys(t *testing.T) {
	suite := crypto.SuiteBaseline
	pub, priv, fp := newSigKeypair(t)
	encPub, _, encFP := newKEMKeypair(t)
	_, recoveryPriv, _ := newSigKeypair(t)

	_, err := keys.BuildCompromiseRotation(&keys.CompromiseRotationInput{
		Suite: suite, UserID: "alice@example.com",
		CompromisedDeviceID: "d-old", RevokingDeviceID: "d-new",
		PriorIdentityPriv: priv, PriorIdentityFP: fp,
		NewIdentityPriv: priv, NewIdentityPub: pub, NewIdentityFP: fp, // same
		NewEncryptionPub: encPub, NewEncryptionFP: encFP,
		RecoveryPriv: recoveryPriv, RecoveryKeyID: "rfp",
	})
	if err == nil {
		t.Error("BuildCompromiseRotation accepted prior == new identity fingerprint")
	}
}
