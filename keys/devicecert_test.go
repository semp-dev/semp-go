package keys_test

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	"semp.dev/semp-go/brief"
	"semp.dev/semp-go/crypto"
	"semp.dev/semp-go/keys"
	"semp.dev/semp-go/keys/memstore"
)

// minimalScope returns a Scope that satisfies the §10.3.3 "every
// field REQUIRED" rule. Adjust returned fields in callers that want
// to exercise non-default behavior.
func minimalScope() keys.Scope {
	return keys.Scope{
		Send:      keys.ScopeMatcher{Mode: keys.MatcherModeUnrestricted, RateLimits: []keys.RateLimitTier{}},
		Receive:   keys.ScopeMatcher{Mode: keys.MatcherModeUnrestricted, RateLimits: []keys.RateLimitTier{}, DeliveryStage: 1},
		Blocklist: keys.ScopeResource{Read: false, Write: false, RateLimits: []keys.RateLimitTier{}},
		Keys:      keys.ScopeResource{Read: false, Write: false, RateLimits: []keys.RateLimitTier{}},
		Devices:   keys.ScopeResource{Read: false, Write: false, RateLimits: []keys.RateLimitTier{}},
	}
}

// newTestCert assembles a DeviceCertificate with the supplied
// delegated public key, account, and scope. issuedAt and expiresAt
// default to "now and 30 days from now"; tests can override.
func newTestCert(devicePub []byte, account string, issuerKeyID keys.Fingerprint, scope keys.Scope) *keys.DeviceCertificate {
	now := time.Now().UTC()
	return &keys.DeviceCertificate{
		Type:            "SEMP_DEVICE_CERTIFICATE",
		Version:         "1.0.0",
		DeviceID:        "01JTESTDEVICE000000000000001",
		DevicePublicKey: base64.StdEncoding.EncodeToString(devicePub),
		Account:         account,
		IssuedBy:        "01JTESTISSUER0000000000000001",
		IssuedAt:        now,
		ExpiresAt:       now.Add(30 * 24 * time.Hour),
		Scope:           scope,
	}
}

func TestSignDeviceCertificateRoundTrip(t *testing.T) {
	suite := crypto.SuiteBaseline
	signer := suite.Signer()

	primaryPub, primaryPriv, err := signer.GenerateKeyPair()
	if err != nil {
		t.Fatalf("primary keypair: %v", err)
	}
	primaryFP := keys.Compute(primaryPub)
	delegatedPub, _, _ := signer.GenerateKeyPair()

	scope := minimalScope()
	scope.Send = keys.ScopeMatcher{
		Mode: keys.MatcherModeRestricted,
		Allow: []keys.ScopeEntry{
			{Type: keys.EntityTypeUser, Address: "bob@example.com"},
		},
		RateLimits: []keys.RateLimitTier{},
	}
	cert := newTestCert(delegatedPub, "alice@example.com", primaryFP, scope)

	if err := keys.SignDeviceCertificate(signer, primaryPriv, primaryFP, cert); err != nil {
		t.Fatalf("SignDeviceCertificate: %v", err)
	}
	if cert.Signature.Value == "" {
		t.Fatal("Signature.Value not populated after SignDeviceCertificate")
	}
	if cert.Signature.KeyID != primaryFP {
		t.Errorf("Signature.KeyID = %s, want %s", cert.Signature.KeyID, primaryFP)
	}

	if err := keys.VerifyDeviceCertificate(signer, cert, primaryPub); err != nil {
		t.Errorf("VerifyDeviceCertificate on untampered cert: %v", err)
	}

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

	// Tampering with a covered field MUST break verify.
	tampered := *cert
	tampered.Account = "mallory@attacker.example"
	if err := keys.VerifyDeviceCertificate(signer, &tampered, primaryPub); err == nil {
		t.Error("VerifyDeviceCertificate accepted a tampered Account")
	}
}

func TestSignDeviceCertificateWrongKey(t *testing.T) {
	suite := crypto.SuiteBaseline
	signer := suite.Signer()

	realPub, realPriv, _ := signer.GenerateKeyPair()
	wrongPub, _, _ := signer.GenerateKeyPair()
	delegatedPub, _, _ := signer.GenerateKeyPair()

	cert := newTestCert(delegatedPub, "alice@example.com", keys.Compute(realPub), minimalScope())
	if err := keys.SignDeviceCertificate(signer, realPriv, keys.Compute(realPub), cert); err != nil {
		t.Fatalf("SignDeviceCertificate: %v", err)
	}
	if err := keys.VerifyDeviceCertificate(signer, cert, wrongPub); err == nil {
		t.Error("VerifyDeviceCertificate accepted the wrong public key")
	}
}

func TestVerifyChainRevokedIssuer(t *testing.T) {
	suite := crypto.SuiteBaseline
	signer := suite.Signer()
	primaryPub, primaryPriv, _ := signer.GenerateKeyPair()
	primaryFP := keys.Compute(primaryPub)
	delegatedPub, _, _ := signer.GenerateKeyPair()

	cert := newTestCert(delegatedPub, "alice@example.com", primaryFP, minimalScope())
	if err := keys.SignDeviceCertificate(signer, primaryPriv, primaryFP, cert); err != nil {
		t.Fatalf("SignDeviceCertificate: %v", err)
	}

	store := memstore.New()
	store.PutUserKey("alice@example.com", keys.TypeIdentity, "ed25519", primaryPub)
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

func TestVerifyChainExpired(t *testing.T) {
	suite := crypto.SuiteBaseline
	signer := suite.Signer()
	primaryPub, primaryPriv, _ := signer.GenerateKeyPair()
	primaryFP := keys.Compute(primaryPub)
	delegatedPub, _, _ := signer.GenerateKeyPair()

	now := time.Now().UTC()
	cert := newTestCert(delegatedPub, "alice@example.com", primaryFP, minimalScope())
	cert.IssuedAt = now.Add(-48 * time.Hour)
	cert.ExpiresAt = now.Add(-time.Hour)
	if err := keys.SignDeviceCertificate(signer, primaryPriv, primaryFP, cert); err != nil {
		t.Fatalf("SignDeviceCertificate: %v", err)
	}
	store := memstore.New()
	store.PutUserKey("alice@example.com", keys.TypeIdentity, "ed25519", primaryPub)
	if err := cert.VerifyChain(context.Background(), suite, store); err == nil {
		t.Error("VerifyChain accepted an expired certificate")
	}
}

// TestScopeMatcherAllows exercises every matcher mode and entry type
// per KEY.md §10.3.3.1.
func TestScopeMatcherAllows(t *testing.T) {
	cases := []struct {
		name string
		m    keys.ScopeMatcher
		addr brief.Address
		want bool
	}{
		{
			"unrestricted permits everyone",
			keys.ScopeMatcher{Mode: keys.MatcherModeUnrestricted},
			"alice@example.com", true,
		},
		{
			"none forbids everyone",
			keys.ScopeMatcher{Mode: keys.MatcherModeNone},
			"alice@example.com", false,
		},
		{
			"restricted permits exact user match",
			keys.ScopeMatcher{
				Mode:  keys.MatcherModeRestricted,
				Allow: []keys.ScopeEntry{{Type: keys.EntityTypeUser, Address: "bob@example.com"}},
			},
			"bob@example.com", true,
		},
		{
			"restricted denies unlisted user",
			keys.ScopeMatcher{
				Mode:  keys.MatcherModeRestricted,
				Allow: []keys.ScopeEntry{{Type: keys.EntityTypeUser, Address: "bob@example.com"}},
			},
			"carol@example.com", false,
		},
		{
			"restricted permits domain entry",
			keys.ScopeMatcher{
				Mode:  keys.MatcherModeRestricted,
				Allow: []keys.ScopeEntry{{Type: keys.EntityTypeDomain, Domain: "partner.example"}},
			},
			"alice@partner.example", true,
		},
		{
			"denylist denies listed user",
			keys.ScopeMatcher{
				Mode: keys.MatcherModeDenylist,
				Deny: []keys.ScopeEntry{{Type: keys.EntityTypeUser, Address: "spammer@example.com"}},
			},
			"spammer@example.com", false,
		},
		{
			"denylist permits unlisted user",
			keys.ScopeMatcher{
				Mode: keys.MatcherModeDenylist,
				Deny: []keys.ScopeEntry{{Type: keys.EntityTypeUser, Address: "spammer@example.com"}},
			},
			"alice@example.com", true,
		},
		{
			"unknown mode fails closed",
			keys.ScopeMatcher{Mode: "wild-west"},
			"alice@example.com", false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.m.AllowsRecipient(tc.addr); got != tc.want {
				t.Errorf("AllowsRecipient(%q) = %v, want %v", tc.addr, got, tc.want)
			}
		})
	}
}

// TestScopeValidate covers the §10.3.3 well-formedness rules: each
// matcher mode constrains allow/deny shape; rate-limit tiers have
// caps; resource and matcher fields are independently required.
func TestScopeValidate(t *testing.T) {
	good := minimalScope()
	if err := good.Validate(); err != nil {
		t.Errorf("minimalScope: Validate = %v, want nil", err)
	}

	// Restricted mode requires non-empty allow.
	bad := minimalScope()
	bad.Send = keys.ScopeMatcher{Mode: keys.MatcherModeRestricted, RateLimits: []keys.RateLimitTier{}}
	if err := bad.Validate(); err == nil {
		t.Error("Validate accepted restricted matcher with empty allow")
	}

	// Denylist mode requires non-empty deny.
	bad2 := minimalScope()
	bad2.Send = keys.ScopeMatcher{Mode: keys.MatcherModeDenylist, RateLimits: []keys.RateLimitTier{}}
	if err := bad2.Validate(); err == nil {
		t.Error("Validate accepted denylist matcher with empty deny")
	}

	// Unrestricted MUST NOT have allow or deny.
	bad3 := minimalScope()
	bad3.Send = keys.ScopeMatcher{
		Mode:       keys.MatcherModeUnrestricted,
		Allow:      []keys.ScopeEntry{{Type: keys.EntityTypeUser, Address: "x@y"}},
		RateLimits: []keys.RateLimitTier{},
	}
	if err := bad3.Validate(); err == nil {
		t.Error("Validate accepted unrestricted matcher with non-empty allow")
	}

	// delivery_stage MUST be omitted on send.
	bad4 := minimalScope()
	bad4.Send.DeliveryStage = 1
	if err := bad4.Validate(); err == nil {
		t.Error("Validate accepted delivery_stage on send matcher")
	}

	// Rate-limit tier with negative amount.
	bad5 := minimalScope()
	bad5.Blocklist.RateLimits = []keys.RateLimitTier{{PeriodSeconds: 60, AmountAllowed: -1}}
	if err := bad5.Validate(); err == nil {
		t.Error("Validate accepted rate-limit tier with negative amount_allowed")
	}

	// Rate-limit tier with zero period.
	bad6 := minimalScope()
	bad6.Blocklist.RateLimits = []keys.RateLimitTier{{PeriodSeconds: 0, AmountAllowed: 1}}
	if err := bad6.Validate(); err == nil {
		t.Error("Validate accepted rate-limit tier with period_seconds = 0")
	}

	// Too many tiers.
	bad7 := minimalScope()
	tiers := make([]keys.RateLimitTier, keys.MaxScopeRateLimitTiers+1)
	for i := range tiers {
		tiers[i] = keys.RateLimitTier{PeriodSeconds: 60, AmountAllowed: 100}
	}
	bad7.Keys.RateLimits = tiers
	if err := bad7.Validate(); err == nil {
		t.Error("Validate accepted rate-limit array exceeding 16 tiers")
	}
}

// TestDeviceCertificateValidateLifetime confirms the §10.3.8 cap on
// certificate lifetime.
func TestDeviceCertificateValidateLifetime(t *testing.T) {
	now := time.Now().UTC()
	cert := newTestCert([]byte("pub"), "alice@example.com", "primary-fp", minimalScope())
	cert.IssuedAt = now
	cert.ExpiresAt = now.Add(366 * 24 * time.Hour) // > 365 days
	if err := cert.Validate(); err == nil {
		t.Error("Validate accepted a certificate exceeding the 365-day lifetime cap")
	}
	cert.ExpiresAt = now.Add(364 * 24 * time.Hour)
	if err := cert.Validate(); err != nil {
		t.Errorf("Validate rejected a 364-day certificate: %v", err)
	}
}
