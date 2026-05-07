package keys_test

import (
	"context"
	"errors"
	"testing"
	"time"

	semp "semp.dev/semp-go"
	"semp.dev/semp-go/crypto"
	"semp.dev/semp-go/keys"
)

func mkScope(blocklistRead, blocklistWrite, keysRead, keysWrite, devicesRead, devicesWrite bool) keys.Scope {
	return keys.Scope{
		Send:    keys.ScopeMatcher{Mode: keys.MatcherModeUnrestricted, RateLimits: []keys.RateLimitTier{}},
		Receive: keys.ScopeMatcher{Mode: keys.MatcherModeUnrestricted, DeliveryStage: 1, RateLimits: []keys.RateLimitTier{}},
		Blocklist: keys.ScopeResource{Read: blocklistRead, Write: blocklistWrite, RateLimits: []keys.RateLimitTier{}},
		Keys:      keys.ScopeResource{Read: keysRead, Write: keysWrite, RateLimits: []keys.RateLimitTier{}},
		Devices:   keys.ScopeResource{Read: devicesRead, Write: devicesWrite, RateLimits: []keys.RateLimitTier{}},
	}
}

// TestCheckResourceReadGranted confirms the happy path returns nil.
func TestCheckResourceReadGranted(t *testing.T) {
	scope := mkScope(true, false, true, false, true, false)
	for _, kind := range []keys.ScopeResourceKind{
		keys.ScopeResourceBlocklist, keys.ScopeResourceKeys, keys.ScopeResourceDevices,
	} {
		if err := keys.CheckResourceRead(scope, kind); err != nil {
			t.Errorf("CheckResourceRead(%s) granted: %v", kind, err)
		}
	}
}

// TestCheckResourceReadDenied confirms a false read flag triggers
// scope_exceeded.
func TestCheckResourceReadDenied(t *testing.T) {
	scope := mkScope(false, false, false, false, false, false)
	err := keys.CheckResourceRead(scope, keys.ScopeResourceBlocklist)
	if err == nil {
		t.Fatal("CheckResourceRead accepted with read=false")
	}
	if got := semp.CodeOf(err); got != semp.ReasonScopeExceeded {
		t.Errorf("reason code = %q, want scope_exceeded", got)
	}
}

// TestCheckResourceWriteEnforcement confirms write follows the same
// pattern.
func TestCheckResourceWriteEnforcement(t *testing.T) {
	scope := mkScope(true, false, true, false, true, false)
	if err := keys.CheckResourceWrite(scope, keys.ScopeResourceBlocklist); err == nil {
		t.Error("CheckResourceWrite accepted with write=false")
	}
	scope.Blocklist.Write = true
	if err := keys.CheckResourceWrite(scope, keys.ScopeResourceBlocklist); err != nil {
		t.Errorf("CheckResourceWrite granted: %v", err)
	}
}

// TestCheckResourceUnknownKind confirms an unknown ScopeResourceKind
// surfaces a plain error rather than masking with scope_exceeded.
func TestCheckResourceUnknownKind(t *testing.T) {
	scope := mkScope(true, true, true, true, true, true)
	if err := keys.CheckResourceRead(scope, keys.ScopeResourceKind("custom")); err == nil {
		t.Error("CheckResourceRead accepted unknown kind")
	}
}

// TestRateLimitCounterEnforcesTiers walks a single tier of 3
// operations per minute and verifies the 4th is denied.
func TestRateLimitCounterEnforcesTiers(t *testing.T) {
	c := keys.NewInMemoryRateLimitCounter()
	tiers := []keys.RateLimitTier{{PeriodSeconds: 60, AmountAllowed: 3}}
	now := time.Date(2026, 5, 7, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 3; i++ {
		ok, err := c.Allow(context.Background(), "alice/blocklist", tiers, now.Add(time.Duration(i)*time.Second))
		if err != nil {
			t.Fatalf("Allow %d: %v", i, err)
		}
		if !ok {
			t.Errorf("Allow %d denied; want allowed", i)
		}
	}
	// 4th hit within the window is denied.
	ok, _ := c.Allow(context.Background(), "alice/blocklist", tiers, now.Add(10*time.Second))
	if ok {
		t.Error("Allow 4 within 1-minute window granted; want denied")
	}
	// After the window passes, the 4th hit is allowed again.
	ok, _ = c.Allow(context.Background(), "alice/blocklist", tiers, now.Add(2*time.Minute))
	if !ok {
		t.Error("Allow after window expiry denied; want allowed")
	}
}

// TestRateLimitCounterMultipleTiers confirms a hit must fit within
// EVERY tier (the §10.3.3.3 conservative aggregation).
func TestRateLimitCounterMultipleTiers(t *testing.T) {
	c := keys.NewInMemoryRateLimitCounter()
	tiers := []keys.RateLimitTier{
		{PeriodSeconds: 60, AmountAllowed: 10}, // 10/min
		{PeriodSeconds: 1, AmountAllowed: 1},   // 1/sec — tighter
	}
	now := time.Date(2026, 5, 7, 12, 0, 0, 0, time.UTC)
	if ok, _ := c.Allow(context.Background(), "k", tiers, now); !ok {
		t.Fatal("first hit denied")
	}
	// Second hit within 1 second: tighter tier rejects.
	if ok, _ := c.Allow(context.Background(), "k", tiers, now.Add(500*time.Millisecond)); ok {
		t.Error("second sub-second hit granted; per-second tier should reject")
	}
}

// TestRateLimitCounterAmountZeroPermanent confirms a tier with
// amount_allowed=0 prohibits any operation.
func TestRateLimitCounterAmountZeroPermanent(t *testing.T) {
	c := keys.NewInMemoryRateLimitCounter()
	tiers := []keys.RateLimitTier{{PeriodSeconds: 60, AmountAllowed: 0}}
	if ok, _ := c.Allow(context.Background(), "k", tiers, time.Now()); ok {
		t.Error("amount_allowed=0 tier granted an operation")
	}
}

// TestCheckRateLimitEmptyTiers confirms an empty tier list is
// unconditionally permitted (§10.3.3.3 "no rate cap").
func TestCheckRateLimitEmptyTiers(t *testing.T) {
	if err := keys.CheckRateLimit(context.Background(), nil, "k", nil, time.Now()); err != nil {
		t.Errorf("CheckRateLimit(nil tiers) errored: %v", err)
	}
}

// TestCheckRateLimitDenialReason confirms denials surface as
// *semp.Error with reason rate_limited.
func TestCheckRateLimitDenialReason(t *testing.T) {
	c := keys.NewInMemoryRateLimitCounter()
	tiers := []keys.RateLimitTier{{PeriodSeconds: 60, AmountAllowed: 1}}
	now := time.Now().UTC()
	_ = keys.CheckRateLimit(context.Background(), c, "k", tiers, now)
	err := keys.CheckRateLimit(context.Background(), c, "k", tiers, now.Add(time.Second))
	if err == nil {
		t.Fatal("second CheckRateLimit accepted; want denial")
	}
	if got := semp.CodeOf(err); got != semp.ReasonRateLimited {
		t.Errorf("reason code = %q, want rate_limited", got)
	}
}

// TestRateLimitNotCountedOnReject confirms a denied operation is
// NOT recorded against the counters per §10.3.4. Otherwise a
// denied burst could compound and cap a victim's quota.
func TestRateLimitNotCountedOnReject(t *testing.T) {
	c := keys.NewInMemoryRateLimitCounter()
	tiers := []keys.RateLimitTier{{PeriodSeconds: 60, AmountAllowed: 1}}
	now := time.Date(2026, 5, 7, 12, 0, 0, 0, time.UTC)
	// One allowed, then nine attempts denied.
	if ok, _ := c.Allow(context.Background(), "k", tiers, now); !ok {
		t.Fatal("first hit denied")
	}
	for i := 0; i < 9; i++ {
		if ok, _ := c.Allow(context.Background(), "k", tiers, now.Add(time.Duration(i+1)*time.Second)); ok {
			t.Fatalf("attempt %d granted; want denied", i+2)
		}
	}
	// After the 1-minute window of the FIRST hit elapses, a fresh
	// hit at +61s should be allowed (the denied attempts MUST NOT
	// have been counted).
	if ok, _ := c.Allow(context.Background(), "k", tiers, now.Add(61*time.Second)); !ok {
		t.Error("hit after window elapsed denied; denied attempts MUST NOT be counted")
	}
}

// stubIssuer implements IssuerInfo for tests.
type stubIssuer struct {
	pub     []byte
	role    keys.DeviceRole
	revoked bool
	found   bool
	err     error
}

func (s stubIssuer) IssuerLookup(_ context.Context, _ string) ([]byte, keys.DeviceRole, bool, bool, error) {
	return s.pub, s.role, s.revoked, s.found, s.err
}

// TestValidateIssuanceHappyPath signs a real cert and confirms
// ValidateIssuance accepts it.
func TestValidateIssuanceHappyPath(t *testing.T) {
	signer := crypto.SuiteBaseline.Signer()
	pub, priv, err := signer.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	c := mkSignedCert(t, signer, priv, "primary-fp")
	err = keys.ValidateIssuance(context.Background(), signer, stubIssuer{
		pub:   pub,
		role:  keys.DeviceRoleFullAccess,
		found: true,
	}, c, time.Now().UTC())
	if err != nil {
		t.Errorf("ValidateIssuance happy path: %v", err)
	}
}

// TestValidateIssuanceRejectsDelegatedIssuer confirms §10.3.9: a
// delegated device cannot issue certificates.
func TestValidateIssuanceRejectsDelegatedIssuer(t *testing.T) {
	signer := crypto.SuiteBaseline.Signer()
	pub, priv, _ := signer.GenerateKeyPair()
	c := mkSignedCert(t, signer, priv, "primary-fp")
	err := keys.ValidateIssuance(context.Background(), signer, stubIssuer{
		pub:   pub,
		role:  keys.DeviceRoleDelegated,
		found: true,
	}, c, time.Now().UTC())
	if err == nil {
		t.Fatal("ValidateIssuance accepted delegated issuer")
	}
	if got := semp.CodeOf(err); got != semp.ReasonScopeExceeded {
		t.Errorf("reason code = %q, want scope_exceeded", got)
	}
}

// TestValidateIssuanceRejectsRevokedIssuer confirms a revoked
// issuer fails the issuance check.
func TestValidateIssuanceRejectsRevokedIssuer(t *testing.T) {
	signer := crypto.SuiteBaseline.Signer()
	pub, priv, _ := signer.GenerateKeyPair()
	c := mkSignedCert(t, signer, priv, "primary-fp")
	err := keys.ValidateIssuance(context.Background(), signer, stubIssuer{
		pub:     pub,
		role:    keys.DeviceRoleFullAccess,
		revoked: true,
		found:   true,
	}, c, time.Now().UTC())
	if err == nil {
		t.Fatal("ValidateIssuance accepted revoked issuer")
	}
	if got := semp.CodeOf(err); got != semp.ReasonAuthFailed {
		t.Errorf("reason code = %q, want auth_failed", got)
	}
}

// TestValidateIssuanceRejectsUnknownIssuer confirms an unknown
// issuer (not in the directory) fails with auth_failed.
func TestValidateIssuanceRejectsUnknownIssuer(t *testing.T) {
	signer := crypto.SuiteBaseline.Signer()
	_, priv, _ := signer.GenerateKeyPair()
	c := mkSignedCert(t, signer, priv, "primary-fp")
	err := keys.ValidateIssuance(context.Background(), signer, stubIssuer{found: false}, c, time.Now().UTC())
	if err == nil {
		t.Fatal("ValidateIssuance accepted unknown issuer")
	}
	if got := semp.CodeOf(err); got != semp.ReasonAuthFailed {
		t.Errorf("reason code = %q, want auth_failed", got)
	}
}

// TestValidateIssuanceRejectsBadSignature confirms a signature
// against the wrong public key fails with auth_failed.
func TestValidateIssuanceRejectsBadSignature(t *testing.T) {
	signer := crypto.SuiteBaseline.Signer()
	_, priv, _ := signer.GenerateKeyPair()
	otherPub, _, _ := signer.GenerateKeyPair()
	c := mkSignedCert(t, signer, priv, "primary-fp")
	err := keys.ValidateIssuance(context.Background(), signer, stubIssuer{
		pub:   otherPub, // wrong issuer pubkey
		role:  keys.DeviceRoleFullAccess,
		found: true,
	}, c, time.Now().UTC())
	if err == nil {
		t.Fatal("ValidateIssuance accepted mismatched signature")
	}
	if got := semp.CodeOf(err); got != semp.ReasonAuthFailed {
		t.Errorf("reason code = %q, want auth_failed", got)
	}
}

// TestValidateIssuanceRejectsExpired confirms an already-expired
// cert is caught with certificate_expired.
func TestValidateIssuanceRejectsExpired(t *testing.T) {
	signer := crypto.SuiteBaseline.Signer()
	pub, priv, _ := signer.GenerateKeyPair()
	c := mkSignedCert(t, signer, priv, "primary-fp")
	// Inspect a "now" past expires_at.
	err := keys.ValidateIssuance(context.Background(), signer, stubIssuer{
		pub:   pub,
		role:  keys.DeviceRoleFullAccess,
		found: true,
	}, c, c.ExpiresAt.Add(time.Hour))
	if err == nil {
		t.Fatal("ValidateIssuance accepted expired cert")
	}
	if got := semp.CodeOf(err); got != semp.ReasonCertificateExpired {
		t.Errorf("reason code = %q, want certificate_expired", got)
	}
}

// TestValidateIssuanceLookupErrorPropagates confirms a transport
// error from IssuerLookup propagates without being mapped to a
// reason code.
func TestValidateIssuanceLookupErrorPropagates(t *testing.T) {
	signer := crypto.SuiteBaseline.Signer()
	_, priv, _ := signer.GenerateKeyPair()
	c := mkSignedCert(t, signer, priv, "primary-fp")
	want := errors.New("directory transport error")
	err := keys.ValidateIssuance(context.Background(), signer, stubIssuer{err: want}, c, time.Now().UTC())
	if err == nil || !errors.Is(err, want) {
		t.Errorf("transport error not propagated: got %v", err)
	}
}

// mkSignedCert builds a structurally-valid scoped certificate and
// signs it with priv under issuerKeyID.
func mkSignedCert(t *testing.T, signer crypto.Signer, priv []byte, issuerKeyID string) *keys.DeviceCertificate {
	t.Helper()
	now := time.Now().UTC()
	c := &keys.DeviceCertificate{
		Type:            "SEMP_DEVICE_CERTIFICATE",
		DeviceID:        "01JDELEGATE0000000000000000",
		DevicePublicKey: "delegate-pubkey-base64",
		Account:         "alice@example.com",
		IssuedBy:        "01JPRIMARY00000000000000000",
		IssuedAt:        now,
		ExpiresAt:       now.Add(180 * 24 * time.Hour),
		Scope: keys.Scope{
			Send: keys.ScopeMatcher{Mode: keys.MatcherModeUnrestricted, RateLimits: []keys.RateLimitTier{}},
			Receive: keys.ScopeMatcher{
				Mode:          keys.MatcherModeUnrestricted,
				DeliveryStage: 1,
				RateLimits:    []keys.RateLimitTier{},
			},
			Blocklist: keys.ScopeResource{Read: true, Write: true, RateLimits: []keys.RateLimitTier{}},
			Keys:      keys.ScopeResource{Read: true, Write: false, RateLimits: []keys.RateLimitTier{}},
			Devices:   keys.ScopeResource{Read: true, Write: false, RateLimits: []keys.RateLimitTier{}},
		},
	}
	if err := keys.SignDeviceCertificate(signer, priv, keys.Fingerprint(issuerKeyID), c); err != nil {
		t.Fatalf("SignDeviceCertificate: %v", err)
	}
	return c
}
