package keys_test

import (
	"context"
	"testing"
	"time"

	"semp.dev/semp-go/crypto"
	"semp.dev/semp-go/keys"
	"semp.dev/semp-go/keys/memstore"
)

// TestSignDeviceCertificateRoundTrip signs a device certificate with
// a fabricated primary identity key, then verifies both via the
// direct VerifyDeviceCertificate path and the VerifyChain path
// (which additionally walks the store to confirm the issuer is
// authorized for the cert's UserID).
func TestSignDeviceCertificateRoundTrip(t *testing.T) {
	suite := crypto.SuiteBaseline
	signer := suite.Signer()

	primaryPub, primaryPriv, err := signer.GenerateKeyPair()
	if err != nil {
		t.Fatalf("primary keypair: %v", err)
	}
	primaryFP := keys.Compute(primaryPub)

	// Delegated device key (just a fingerprint — we never actually
	// sign anything with it in this test).
	delegatedPub, _, _ := signer.GenerateKeyPair()
	delegatedFP := keys.Compute(delegatedPub)

	cert := &keys.DeviceCertificate{
		Type:               "SEMP_DEVICE_CERTIFICATE",
		Version:            "1.0.0",
		UserID:             "alice@example.com",
		DeviceID:           "01JTESTDEVICE000000000000001",
		DeviceKeyID:        delegatedFP,
		IssuingDeviceKeyID: primaryFP,
		Scope: keys.Scope{
			Send: keys.SendScope{
				Mode:  keys.SendModeRestricted,
				Allow: []string{"bob@example.com"},
			},
			Receive: true,
		},
		IssuedAt: time.Date(2026, 4, 10, 0, 0, 0, 0, time.UTC),
	}

	if err := keys.SignDeviceCertificate(signer, primaryPriv, cert); err != nil {
		t.Fatalf("SignDeviceCertificate: %v", err)
	}
	if cert.Signature.Value == "" {
		t.Fatal("Signature.Value not populated after SignDeviceCertificate")
	}
	if cert.Signature.KeyID != primaryFP {
		t.Errorf("Signature.KeyID = %s, want %s", cert.Signature.KeyID, primaryFP)
	}

	// Direct verify: pass the issuer's public key.
	if err := keys.VerifyDeviceCertificate(signer, cert, primaryPub); err != nil {
		t.Errorf("VerifyDeviceCertificate on untampered cert: %v", err)
	}

	// VerifyChain: requires the issuer to be registered as an
	// identity key in the store for the cert's UserID.
	store := memstore.New()
	store.PutUserKey("alice@example.com", keys.TypeIdentity, "ed25519", primaryPub)
	if err := cert.VerifyChain(context.Background(), suite, store); err != nil {
		t.Errorf("VerifyChain on registered issuer: %v", err)
	}

	// VerifyChain without the issuer in the store MUST fail.
	emptyStore := memstore.New()
	if err := cert.VerifyChain(context.Background(), suite, emptyStore); err == nil {
		t.Error("VerifyChain accepted a cert whose issuer is not registered")
	}

	// Tampering with a covered field (DeviceKeyID) MUST break verify.
	tampered := *cert
	tampered.DeviceKeyID = "attacker-chosen-fp"
	if err := keys.VerifyDeviceCertificate(signer, &tampered, primaryPub); err == nil {
		t.Error("VerifyDeviceCertificate accepted a tampered DeviceKeyID")
	}
}

// TestSignDeviceCertificateWrongKey confirms a signature by one
// primary device key does not verify under a different public key.
func TestSignDeviceCertificateWrongKey(t *testing.T) {
	suite := crypto.SuiteBaseline
	signer := suite.Signer()

	_, realPriv, _ := signer.GenerateKeyPair()
	wrongPub, _, _ := signer.GenerateKeyPair()

	cert := &keys.DeviceCertificate{
		Type:               "SEMP_DEVICE_CERTIFICATE",
		Version:            "1.0.0",
		UserID:             "alice@example.com",
		DeviceID:           "id",
		DeviceKeyID:        "dev-fp",
		IssuingDeviceKeyID: "primary-fp",
		Scope:              keys.Scope{Send: keys.SendScope{Mode: keys.SendModeAll}},
		IssuedAt:           time.Now(),
	}
	if err := keys.SignDeviceCertificate(signer, realPriv, cert); err != nil {
		t.Fatalf("SignDeviceCertificate: %v", err)
	}
	if err := keys.VerifyDeviceCertificate(signer, cert, wrongPub); err == nil {
		t.Error("VerifyDeviceCertificate accepted the wrong public key")
	}
}

// TestVerifyChainRevokedIssuer confirms that a revoked issuing
// identity key causes VerifyChain to fail even if the signature
// itself is cryptographically valid.
func TestVerifyChainRevokedIssuer(t *testing.T) {
	suite := crypto.SuiteBaseline
	signer := suite.Signer()
	primaryPub, primaryPriv, _ := signer.GenerateKeyPair()
	primaryFP := keys.Compute(primaryPub)

	cert := &keys.DeviceCertificate{
		Type:               "SEMP_DEVICE_CERTIFICATE",
		Version:            "1.0.0",
		UserID:             "alice@example.com",
		DeviceID:           "id",
		DeviceKeyID:        "dev-fp",
		IssuingDeviceKeyID: primaryFP,
		Scope:              keys.Scope{Send: keys.SendScope{Mode: keys.SendModeAll}},
		IssuedAt:           time.Now(),
	}
	if err := keys.SignDeviceCertificate(signer, primaryPriv, cert); err != nil {
		t.Fatalf("SignDeviceCertificate: %v", err)
	}

	store := memstore.New()
	store.PutUserKey("alice@example.com", keys.TypeIdentity, "ed25519", primaryPub)
	// Mark the issuer key as revoked.
	if err := store.PutRevocation(context.Background(), primaryFP, &keys.Revocation{
		Reason:    keys.ReasonKeyCompromise,
		RevokedAt: time.Now(),
	}); err != nil {
		t.Fatalf("PutRevocation: %v", err)
	}
	if err := cert.VerifyChain(context.Background(), suite, store); err == nil {
		t.Error("VerifyChain accepted a certificate whose issuing key is revoked")
	}
}

// TestVerifyChainExpired confirms that a certificate whose Expires
// timestamp is in the past is rejected, even if the signature and
// chain are otherwise valid.
func TestVerifyChainExpired(t *testing.T) {
	suite := crypto.SuiteBaseline
	signer := suite.Signer()
	primaryPub, primaryPriv, _ := signer.GenerateKeyPair()
	primaryFP := keys.Compute(primaryPub)

	cert := &keys.DeviceCertificate{
		Type:               "SEMP_DEVICE_CERTIFICATE",
		Version:            "1.0.0",
		UserID:             "alice@example.com",
		DeviceID:           "id",
		DeviceKeyID:        "dev-fp",
		IssuingDeviceKeyID: primaryFP,
		Scope:              keys.Scope{Send: keys.SendScope{Mode: keys.SendModeAll}},
		IssuedAt:           time.Now().Add(-48 * time.Hour),
		Expires:            time.Now().Add(-time.Hour),
	}
	if err := keys.SignDeviceCertificate(signer, primaryPriv, cert); err != nil {
		t.Fatalf("SignDeviceCertificate: %v", err)
	}
	store := memstore.New()
	store.PutUserKey("alice@example.com", keys.TypeIdentity, "ed25519", primaryPub)
	if err := cert.VerifyChain(context.Background(), suite, store); err == nil {
		t.Error("VerifyChain accepted an expired certificate")
	}
}

// TestSendScopeAllows exercises the allow-list decision logic
// across every mode the spec defines.
func TestSendScopeAllows(t *testing.T) {
	cases := []struct {
		name      string
		scope     keys.SendScope
		recipient string
		want      bool
	}{
		{"mode=all permits everyone", keys.SendScope{Mode: keys.SendModeAll}, "alice@example.com", true},
		{"mode=none forbids everyone", keys.SendScope{Mode: keys.SendModeNone}, "alice@example.com", false},
		{
			"restricted permits exact match",
			keys.SendScope{Mode: keys.SendModeRestricted, Allow: []string{"bob@example.com"}},
			"bob@example.com", true,
		},
		{
			"restricted denies unlisted address",
			keys.SendScope{Mode: keys.SendModeRestricted, Allow: []string{"bob@example.com"}},
			"carol@example.com", false,
		},
		{
			"restricted permits domain entry",
			keys.SendScope{Mode: keys.SendModeRestricted, Allow: []string{"partner.example"}},
			"alice@partner.example", true,
		},
		{
			"restricted denies address outside domain",
			keys.SendScope{Mode: keys.SendModeRestricted, Allow: []string{"partner.example"}},
			"alice@evil.example", false,
		},
		{
			"restricted is case-insensitive on domain",
			keys.SendScope{Mode: keys.SendModeRestricted, Allow: []string{"Partner.Example"}},
			"alice@partner.EXAMPLE", true,
		},
		{
			"unknown mode fails closed",
			keys.SendScope{Mode: "wild-west"},
			"alice@example.com", false,
		},
	}
	for _, tc := range cases {
		if got := tc.scope.Allows(tc.recipient); got != tc.want {
			t.Errorf("%s: Allows(%q) = %v, want %v", tc.name, tc.recipient, got, tc.want)
		}
	}
}
