package keys_test

import (
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	"github.com/semp-dev/semp-go/crypto"
	"github.com/semp-dev/semp-go/keys"
)

// strPtr returns a pointer to s. Used for the *string fields on
// device records (CertificateID, ReplacementDeviceID).
func strPtr(s string) *string { return &s }

func newKeypair(t *testing.T) (pub, priv []byte, fp keys.Fingerprint) {
	t.Helper()
	signer := crypto.SuiteBaseline.Signer()
	pub, priv, err := signer.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	return pub, priv, keys.Compute(pub)
}

// TestDeviceRegistrationRoundTrip exercises the §10.1 + §10.2 flow:
// the existing full-access device authorizes (inner signature) and
// the user identity key signs (outer). Both verifications round-trip.
func TestDeviceRegistrationRoundTrip(t *testing.T) {
	signer := crypto.SuiteBaseline.Signer()

	// Identity key (the user's account-level key shared by every
	// full-access device).
	idPub, idPriv, idFP := newKeypair(t)

	// Existing full-access device's device key.
	authPub, authPriv, authFP := newKeypair(t)

	// New device's device key.
	newDevPub, _, _ := newKeypair(t)
	newDevPubB64 := base64.StdEncoding.EncodeToString(newDevPub)

	enrollNonce := make([]byte, 32)
	if _, err := rand.Read(enrollNonce); err != nil {
		t.Fatalf("rand: %v", err)
	}

	reg := &keys.DeviceRegistration{
		UserID:                        "alice@example.com",
		DeviceID:                      "01JNEWDEVICE0000000000000001",
		DeviceName:                    "Alice's Phone",
		DeviceType:                    "phone",
		DevicePublicKey:               newDevPubB64,
		DeviceIdentityPubkeyAlgorithm: "ed25519",
		EnrolledAt:                    time.Now().UTC(),
		Role:                          keys.DeviceRoleFullAccess,
		CertificateID:                 nil,
	}
	if err := keys.SignDeviceAuthorization(signer, authPriv, "01JOLDDEVICE0000000000000001", authFP, enrollNonce, reg, keys.DeviceAuthQRScan); err != nil {
		t.Fatalf("SignDeviceAuthorization: %v", err)
	}
	if err := keys.SignDeviceRegistration(signer, idPriv, idFP, reg); err != nil {
		t.Fatalf("SignDeviceRegistration: %v", err)
	}

	// Outer signature verifies under identity public key.
	if err := keys.VerifyDeviceRegistration(signer, idPub, reg); err != nil {
		t.Errorf("VerifyDeviceRegistration: %v", err)
	}
	// Inner authorization verifies under authorizing device public key.
	if err := keys.VerifyDeviceAuthorization(signer, authPub, enrollNonce, reg); err != nil {
		t.Errorf("VerifyDeviceAuthorization: %v", err)
	}
}

// TestDeviceRegistrationTamperOuter confirms a mutation to a covered
// outer field breaks the identity-key signature.
func TestDeviceRegistrationTamperOuter(t *testing.T) {
	signer := crypto.SuiteBaseline.Signer()
	idPub, idPriv, idFP := newKeypair(t)
	_, authPriv, authFP := newKeypair(t)
	newDevPub, _, _ := newKeypair(t)
	enrollNonce := []byte("01234567890123456789012345678901")

	reg := &keys.DeviceRegistration{
		UserID:                        "alice@example.com",
		DeviceID:                      "01JNEWDEVICE0000000000000001",
		DeviceName:                    "Alice's Phone",
		DeviceType:                    "phone",
		DevicePublicKey:               base64.StdEncoding.EncodeToString(newDevPub),
		DeviceIdentityPubkeyAlgorithm: "ed25519",
		EnrolledAt:                    time.Now().UTC(),
		Role:                          keys.DeviceRoleFullAccess,
	}
	if err := keys.SignDeviceAuthorization(signer, authPriv, "auth-dev", authFP, enrollNonce, reg, keys.DeviceAuthQRScan); err != nil {
		t.Fatalf("SignDeviceAuthorization: %v", err)
	}
	if err := keys.SignDeviceRegistration(signer, idPriv, idFP, reg); err != nil {
		t.Fatalf("SignDeviceRegistration: %v", err)
	}

	// Tamper with DeviceName (covered field).
	reg.DeviceName = "Mallory's Phone"
	if err := keys.VerifyDeviceRegistration(signer, idPub, reg); err == nil {
		t.Error("VerifyDeviceRegistration accepted a tampered DeviceName")
	}
}

// TestDeviceRegistrationTamperAuthorization confirms a mutation to
// any of the four authorization-payload fields breaks the inner
// authorizing-device signature.
func TestDeviceRegistrationTamperAuthorization(t *testing.T) {
	signer := crypto.SuiteBaseline.Signer()
	_, idPriv, idFP := newKeypair(t)
	authPub, authPriv, authFP := newKeypair(t)
	newDevPub, _, _ := newKeypair(t)
	enrollNonce := []byte("01234567890123456789012345678901")

	reg := &keys.DeviceRegistration{
		UserID:                        "alice@example.com",
		DeviceID:                      "01JNEWDEVICE0000000000000001",
		DeviceName:                    "Alice's Phone",
		DeviceType:                    "phone",
		DevicePublicKey:               base64.StdEncoding.EncodeToString(newDevPub),
		DeviceIdentityPubkeyAlgorithm: "ed25519",
		EnrolledAt:                    time.Now().UTC(),
		Role:                          keys.DeviceRoleFullAccess,
	}
	if err := keys.SignDeviceAuthorization(signer, authPriv, "auth-dev", authFP, enrollNonce, reg, keys.DeviceAuthQRScan); err != nil {
		t.Fatalf("SignDeviceAuthorization: %v", err)
	}
	if err := keys.SignDeviceRegistration(signer, idPriv, idFP, reg); err != nil {
		t.Fatalf("SignDeviceRegistration: %v", err)
	}

	// Verify under a DIFFERENT enroll nonce (simulates an attacker
	// who replays a stale QR code).
	staleNonce := []byte("99999999999999999999999999999999")
	if err := keys.VerifyDeviceAuthorization(signer, authPub, staleNonce, reg); err == nil {
		t.Error("VerifyDeviceAuthorization accepted a stale enroll nonce")
	}

	// Tamper with DeviceID and use the original nonce; binding still
	// breaks because device_id is part of the signed payload.
	reg.DeviceID = "01JATTACKERDEVICE000000000001"
	if err := keys.VerifyDeviceAuthorization(signer, authPub, enrollNonce, reg); err == nil {
		t.Error("VerifyDeviceAuthorization accepted a tampered DeviceID")
	}
}

// TestDeviceRegistrationDelegatedRequiresCertificateID confirms the
// §10.1 role/certificate_id consistency rule.
func TestDeviceRegistrationDelegatedRequiresCertificateID(t *testing.T) {
	signer := crypto.SuiteBaseline.Signer()
	_, idPriv, idFP := newKeypair(t)
	_, authPriv, authFP := newKeypair(t)
	newDevPub, _, _ := newKeypair(t)
	enrollNonce := []byte("01234567890123456789012345678901")

	reg := &keys.DeviceRegistration{
		UserID:                        "alice@example.com",
		DeviceID:                      "01JBOTDEVICE0000000000000001",
		DeviceName:                    "Spam Filter",
		DeviceType:                    "server",
		DevicePublicKey:               base64.StdEncoding.EncodeToString(newDevPub),
		DeviceIdentityPubkeyAlgorithm: "ed25519",
		EnrolledAt:                    time.Now().UTC(),
		Role:                          keys.DeviceRoleDelegated,
		CertificateID:                 nil, // missing on purpose
	}
	if err := keys.SignDeviceAuthorization(signer, authPriv, "auth-dev", authFP, enrollNonce, reg, keys.DeviceAuthQRScan); err != nil {
		t.Fatalf("SignDeviceAuthorization: %v", err)
	}
	if err := keys.SignDeviceRegistration(signer, idPriv, idFP, reg); err == nil {
		t.Error("SignDeviceRegistration accepted a delegated registration with nil certificate_id")
	}

	// With certificate_id set, signing succeeds.
	reg.CertificateID = strPtr("01JCERT00000000000000000001")
	if err := keys.SignDeviceRegistration(signer, idPriv, idFP, reg); err != nil {
		t.Errorf("SignDeviceRegistration with certificate_id: %v", err)
	}
}

// TestDeviceRegistrationFullAccessRejectsCertificateID confirms the
// other half of the §10.1 role rule.
func TestDeviceRegistrationFullAccessRejectsCertificateID(t *testing.T) {
	signer := crypto.SuiteBaseline.Signer()
	_, idPriv, idFP := newKeypair(t)
	_, authPriv, authFP := newKeypair(t)
	newDevPub, _, _ := newKeypair(t)
	enrollNonce := []byte("01234567890123456789012345678901")

	reg := &keys.DeviceRegistration{
		UserID:                        "alice@example.com",
		DeviceID:                      "01JDESKTOP0000000000000000001",
		DeviceName:                    "Alice's Desktop",
		DeviceType:                    "computer",
		DevicePublicKey:               base64.StdEncoding.EncodeToString(newDevPub),
		DeviceIdentityPubkeyAlgorithm: "ed25519",
		EnrolledAt:                    time.Now().UTC(),
		Role:                          keys.DeviceRoleFullAccess,
		CertificateID:                 strPtr("01JCERT00000000000000000001"), // forbidden on full_access
	}
	if err := keys.SignDeviceAuthorization(signer, authPriv, "auth-dev", authFP, enrollNonce, reg, keys.DeviceAuthQRScan); err != nil {
		t.Fatalf("SignDeviceAuthorization: %v", err)
	}
	if err := keys.SignDeviceRegistration(signer, idPriv, idFP, reg); err == nil {
		t.Error("SignDeviceRegistration accepted a full_access registration with certificate_id set")
	}
}

// TestDeviceRevocationRoundTrip exercises the §10.5 happy path.
func TestDeviceRevocationRoundTrip(t *testing.T) {
	signer := crypto.SuiteBaseline.Signer()
	idPub, idPriv, idFP := newKeypair(t)

	rev := &keys.DeviceRevocation{
		UserID:            "alice@example.com",
		DeviceID:          "01JOLDDEVICE0000000000000001",
		Reason:            keys.DeviceRevocationLost,
		RevokedAt:         time.Now().UTC(),
		RevokedByDeviceID: "01JNEWDEVICE0000000000000001",
	}
	if err := keys.SignDeviceRevocation(signer, idPriv, idFP, rev); err != nil {
		t.Fatalf("SignDeviceRevocation: %v", err)
	}
	if err := keys.VerifyDeviceRevocation(signer, idPub, rev); err != nil {
		t.Errorf("VerifyDeviceRevocation: %v", err)
	}
}

// TestDeviceRevocationSupersededRequiresReplacement confirms the
// §10.5.1 replacement_device_id rule.
func TestDeviceRevocationSupersededRequiresReplacement(t *testing.T) {
	signer := crypto.SuiteBaseline.Signer()
	_, idPriv, idFP := newKeypair(t)

	rev := &keys.DeviceRevocation{
		UserID:              "alice@example.com",
		DeviceID:            "01JOLDDEVICE0000000000000001",
		Reason:              keys.DeviceRevocationSuperseded,
		RevokedAt:           time.Now().UTC(),
		RevokedByDeviceID:   "01JNEWDEVICE0000000000000001",
		ReplacementDeviceID: nil, // missing on purpose
	}
	if err := keys.SignDeviceRevocation(signer, idPriv, idFP, rev); err == nil {
		t.Error("SignDeviceRevocation accepted superseded with nil replacement_device_id")
	}

	// Other reasons MUST NOT have a replacement set.
	rev2 := &keys.DeviceRevocation{
		UserID:              "alice@example.com",
		DeviceID:            "01JOLDDEVICE0000000000000001",
		Reason:              keys.DeviceRevocationKeyCompromise,
		RevokedAt:           time.Now().UTC(),
		RevokedByDeviceID:   "01JNEWDEVICE0000000000000001",
		ReplacementDeviceID: strPtr("01JNEWDEVICE0000000000000001"),
	}
	if err := keys.SignDeviceRevocation(signer, idPriv, idFP, rev2); err == nil {
		t.Error("SignDeviceRevocation accepted key_compromise with non-nil replacement_device_id")
	}
}

// TestDeviceRevocationRequiresIdentityRotation exercises the helper
// that callers use to decide whether to drive the §10.5.5 mandatory
// rotation flow.
func TestDeviceRevocationRequiresIdentityRotation(t *testing.T) {
	cases := []struct {
		reason keys.DeviceRevocationReason
		want   bool
	}{
		{keys.DeviceRevocationKeyCompromise, true},
		{keys.DeviceRevocationLost, false},
		{keys.DeviceRevocationRetired, false},
		{keys.DeviceRevocationSuperseded, false},
	}
	for _, tc := range cases {
		if got := tc.reason.RequiresIdentityRotation(); got != tc.want {
			t.Errorf("%s.RequiresIdentityRotation = %v, want %v", tc.reason, got, tc.want)
		}
	}
}

// TestDeviceDirectoryRoundTrip exercises the §10.6 happy path,
// including that the canonical signature is independent of input
// device-array ordering (devices are sorted by device_id before
// canonicalization).
func TestDeviceDirectoryRoundTrip(t *testing.T) {
	signer := crypto.SuiteBaseline.Signer()
	idPub, idPriv, idFP := newKeypair(t)

	dev1Pub, _, _ := newKeypair(t)
	dev2Pub, _, _ := newKeypair(t)
	dev3Pub, _, _ := newKeypair(t)

	mkEntry := func(id string, pub []byte, role keys.DeviceRole, certID *string) keys.DeviceDirectoryEntry {
		return keys.DeviceDirectoryEntry{
			DeviceID:                      id,
			DevicePublicKey:               base64.StdEncoding.EncodeToString(pub),
			DeviceIdentityPubkeyAlgorithm: "ed25519",
			Role:                          role,
			CertificateID:                 certID,
			EnrolledAt:                    time.Now().UTC(),
			DeviceName:                    "device-" + id,
			DeviceType:                    "test",
		}
	}

	dir := &keys.DeviceDirectory{
		UserID:   "alice@example.com",
		Revision: 1,
		IssuedAt: time.Now().UTC(),
		Devices: []keys.DeviceDirectoryEntry{
			mkEntry("01JBOT00000000000000000001", dev3Pub, keys.DeviceRoleDelegated, strPtr("01JCERT00000000000000000001")),
			mkEntry("01JDESKTOP0000000000000001", dev1Pub, keys.DeviceRoleFullAccess, nil),
			mkEntry("01JPHONE0000000000000000001", dev2Pub, keys.DeviceRoleFullAccess, nil),
		},
	}
	if err := keys.SignDeviceDirectory(signer, idPriv, idFP, dir); err != nil {
		t.Fatalf("SignDeviceDirectory: %v", err)
	}
	if err := keys.VerifyDeviceDirectory(signer, idPub, dir); err != nil {
		t.Errorf("VerifyDeviceDirectory: %v", err)
	}

	// Reorder the input slice; the signature MUST still verify
	// because canonicalization sorts internally.
	reordered := *dir
	reordered.Devices = []keys.DeviceDirectoryEntry{
		dir.Devices[2],
		dir.Devices[0],
		dir.Devices[1],
	}
	if err := keys.VerifyDeviceDirectory(signer, idPub, &reordered); err != nil {
		t.Errorf("VerifyDeviceDirectory after reorder: %v", err)
	}
}

// TestDeviceDirectoryRejectsDuplicateDeviceID exercises the §10.6.3
// uniqueness rule.
func TestDeviceDirectoryRejectsDuplicateDeviceID(t *testing.T) {
	signer := crypto.SuiteBaseline.Signer()
	_, idPriv, idFP := newKeypair(t)

	devPub, _, _ := newKeypair(t)
	entry := keys.DeviceDirectoryEntry{
		DeviceID:                      "01JDUPLICATE0000000000000001",
		DevicePublicKey:               base64.StdEncoding.EncodeToString(devPub),
		DeviceIdentityPubkeyAlgorithm: "ed25519",
		Role:                          keys.DeviceRoleFullAccess,
		EnrolledAt:                    time.Now().UTC(),
	}
	dir := &keys.DeviceDirectory{
		UserID:   "alice@example.com",
		Revision: 1,
		IssuedAt: time.Now().UTC(),
		Devices:  []keys.DeviceDirectoryEntry{entry, entry}, // duplicate
	}
	if err := keys.SignDeviceDirectory(signer, idPriv, idFP, dir); err == nil {
		t.Error("SignDeviceDirectory accepted a directory with duplicate device_id")
	}
}

// TestDeviceDirectoryRejectsRevisionZero exercises the §10.6.1
// monotonic-revision lower bound (any directory MUST be at least
// revision 1; rollback detection by consumers requires a positive
// counter).
func TestDeviceDirectoryRejectsRevisionZero(t *testing.T) {
	signer := crypto.SuiteBaseline.Signer()
	_, idPriv, idFP := newKeypair(t)

	dir := &keys.DeviceDirectory{
		UserID:   "alice@example.com",
		Revision: 0,
		IssuedAt: time.Now().UTC(),
		Devices:  []keys.DeviceDirectoryEntry{},
	}
	if err := keys.SignDeviceDirectory(signer, idPriv, idFP, dir); err == nil {
		t.Error("SignDeviceDirectory accepted revision = 0")
	}
}
