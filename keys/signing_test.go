package keys_test

import (
	"encoding/base64"
	"testing"
	"time"

	"semp.dev/semp-go/crypto"
	"semp.dev/semp-go/keys"
)

// TestSignRecordVerifyRoundTrip signs a user key record with a
// fabricated domain keypair, then verifies the signature via
// VerifyRecordSignature. Flipping any byte of the signed bytes in
// the record (anything EXCEPT the signatures / revocation fields,
// which are elided from the canonical form) MUST cause verification
// to fail.
func TestSignRecordVerifyRoundTrip(t *testing.T) {
	suite := crypto.SuiteBaseline
	signer := suite.Signer()

	domainPub, domainPriv, err := signer.GenerateKeyPair()
	if err != nil {
		t.Fatalf("domain keypair: %v", err)
	}
	domainFP := keys.Compute(domainPub)

	rec := &keys.Record{
		Address:   "alice@example.com",
		Type:      keys.TypeEncryption,
		Algorithm: "x25519-chacha20-poly1305",
		PublicKey: base64.StdEncoding.EncodeToString([]byte("alice-encryption-public-key-32b")),
		KeyID:     "alice-enc-fp",
		Created:   time.Date(2026, 4, 10, 0, 0, 0, 0, time.UTC),
		Expires:   time.Date(2027, 4, 10, 0, 0, 0, 0, time.UTC),
	}

	if err := keys.SignRecord(signer, domainPriv, "example.com", domainFP, rec); err != nil {
		t.Fatalf("SignRecord: %v", err)
	}
	if len(rec.Signatures) != 1 {
		t.Fatalf("expected 1 signature after SignRecord, got %d", len(rec.Signatures))
	}
	if rec.Signatures[0].KeyID != domainFP {
		t.Errorf("signature KeyID = %s, want %s", rec.Signatures[0].KeyID, domainFP)
	}

	// Happy-path verification.
	if err := keys.VerifyRecordSignature(signer, rec, domainFP, domainPub); err != nil {
		t.Errorf("VerifyRecordSignature on untampered record: %v", err)
	}

	// Tampering with a covered field (PublicKey) MUST break verification.
	tampered := *rec
	tampered.PublicKey = base64.StdEncoding.EncodeToString([]byte("mallory-encryption-public-keybs"))
	if err := keys.VerifyRecordSignature(signer, &tampered, domainFP, domainPub); err == nil {
		t.Error("VerifyRecordSignature accepted a tampered PublicKey")
	}

	// Tampering with an ELIDED field (Revocation) MUST NOT break
	// verification, because the canonical bytes exclude it. This
	// is by design: a revocation can be attached after signing
	// without invalidating signatures already present.
	revoked := *rec
	// Deep-copy the signatures slice so the assert below doesn't
	// race with the happy-path loop above.
	revoked.Signatures = append([]keys.Signature(nil), rec.Signatures...)
	revoked.Revocation = &keys.Revocation{
		Reason:    keys.ReasonKeyCompromise,
		RevokedAt: time.Now(),
	}
	if err := keys.VerifyRecordSignature(signer, &revoked, domainFP, domainPub); err != nil {
		t.Errorf("VerifyRecordSignature rejected a record with a post-signing Revocation: %v", err)
	}
}

// TestSignRecordWrongPublicKey confirms that a signature produced by
// one keypair does not verify under a different public key.
func TestSignRecordWrongPublicKey(t *testing.T) {
	suite := crypto.SuiteBaseline
	signer := suite.Signer()

	_, domainPriv, _ := signer.GenerateKeyPair()
	wrongPub, _, _ := signer.GenerateKeyPair()

	rec := &keys.Record{
		Address:   "alice@example.com",
		Type:      keys.TypeEncryption,
		Algorithm: "x25519-chacha20-poly1305",
		PublicKey: base64.StdEncoding.EncodeToString([]byte("alice-encryption-public-key-32b")),
		KeyID:     "alice-enc-fp",
		Created:   time.Now(),
		Expires:   time.Now().Add(24 * time.Hour),
	}
	if err := keys.SignRecord(signer, domainPriv, "example.com", "domain-fp", rec); err != nil {
		t.Fatalf("SignRecord: %v", err)
	}
	if err := keys.VerifyRecordSignature(signer, rec, "domain-fp", wrongPub); err == nil {
		t.Error("VerifyRecordSignature accepted the wrong public key")
	}
}

// TestSignResponseResultVerifyRoundTrip exercises the response-level
// signature path (OriginSignature). Signing populates
// r.OriginSignature; verification accepts the untampered value and
// rejects a tampered address.
func TestSignResponseResultVerifyRoundTrip(t *testing.T) {
	suite := crypto.SuiteBaseline
	signer := suite.Signer()
	domainPub, domainPriv, _ := signer.GenerateKeyPair()
	domainFP := keys.Compute(domainPub)

	result := &keys.ResponseResult{
		Address: "alice@example.com",
		Status:  keys.StatusFound,
		Domain:  "example.com",
		UserKeys: []*keys.Record{
			{
				Address:   "alice@example.com",
				Type:      keys.TypeEncryption,
				Algorithm: "x25519-chacha20-poly1305",
				PublicKey: base64.StdEncoding.EncodeToString([]byte("alice-encryption-public-key-32b")),
				KeyID:     "alice-enc-fp",
				Created:   time.Date(2026, 4, 10, 0, 0, 0, 0, time.UTC),
				Expires:   time.Date(2027, 4, 10, 0, 0, 0, 0, time.UTC),
			},
		},
	}
	if err := keys.SignResponseResult(signer, domainPriv, domainFP, result); err != nil {
		t.Fatalf("SignResponseResult: %v", err)
	}
	if result.OriginSignature == nil {
		t.Fatal("OriginSignature not populated after SignResponseResult")
	}
	if result.OriginSignature.KeyID != domainFP {
		t.Errorf("OriginSignature.KeyID = %s, want %s", result.OriginSignature.KeyID, domainFP)
	}

	if err := keys.VerifyResponseResult(signer, result, domainPub); err != nil {
		t.Errorf("VerifyResponseResult on untampered result: %v", err)
	}

	// Tamper with the Address (a covered field) — verification must fail.
	tampered := *result
	tampered.Address = "mallory@example.com"
	if err := keys.VerifyResponseResult(signer, &tampered, domainPub); err == nil {
		t.Error("VerifyResponseResult accepted a tampered Address")
	}
}

// TestVerifierRejectsRevokedUserKey confirms that Verifier.Verify
// fails when a user key in the response is revoked, per
// CLIENT.md §3.3.3 ("A revoked key MUST NOT be used").
func TestVerifierRejectsRevokedUserKey(t *testing.T) {
	suite := crypto.SuiteBaseline
	signer := suite.Signer()
	domainPub, domainPriv, _ := signer.GenerateKeyPair()
	domainFP := keys.Compute(domainPub)

	// Build a valid signed result...
	rec := &keys.Record{
		Address:   "alice@example.com",
		Type:      keys.TypeEncryption,
		Algorithm: "x25519-chacha20-poly1305",
		PublicKey: base64.StdEncoding.EncodeToString([]byte("alice-encryption-public-key-32b")),
		KeyID:     "alice-enc-fp",
		Created:   time.Now(),
		Expires:   time.Now().Add(24 * time.Hour),
	}
	if err := keys.SignRecord(signer, domainPriv, "example.com", domainFP, rec); err != nil {
		t.Fatalf("SignRecord: %v", err)
	}
	domainKeyRec := &keys.Record{
		Type:      keys.TypeDomain,
		Algorithm: "ed25519",
		PublicKey: base64.StdEncoding.EncodeToString(domainPub),
		KeyID:     domainFP,
		Created:   time.Now(),
		Expires:   time.Now().Add(365 * 24 * time.Hour),
	}
	result := keys.ResponseResult{
		Address:   "alice@example.com",
		Status:    keys.StatusFound,
		Domain:    "example.com",
		DomainKey: domainKeyRec,
		UserKeys:  []*keys.Record{rec},
	}
	if err := keys.SignResponseResult(signer, domainPriv, domainFP, &result); err != nil {
		t.Fatalf("SignResponseResult: %v", err)
	}
	resp := &keys.Response{
		Type:    keys.RequestType,
		Step:    keys.RequestStepResponse,
		Version: "1.0.0",
		ID:      "test",
		Results: []keys.ResponseResult{result},
	}

	// Happy path: verify accepts the response.
	verifier := &keys.Verifier{Suite: suite}
	if err := verifier.Verify(resp); err != nil {
		t.Fatalf("Verify on clean response: %v", err)
	}

	// Now attach a revocation to the user record. Verification MUST
	// fail, even though the signatures are still valid (revocation
	// is elided from the canonical bytes by design).
	resp.Results[0].UserKeys[0].Revocation = &keys.Revocation{
		Reason:    keys.ReasonKeyCompromise,
		RevokedAt: time.Now(),
	}
	if err := verifier.Verify(resp); err == nil {
		t.Error("Verifier accepted a response with a revoked user key")
	}
}

// TestVerifierRejectsMissingDomainKey confirms that a found result
// without a DomainKey cannot be verified (there's no public key to
// verify origin_signature against).
func TestVerifierRejectsMissingDomainKey(t *testing.T) {
	suite := crypto.SuiteBaseline
	resp := &keys.Response{
		Type:    keys.RequestType,
		Step:    keys.RequestStepResponse,
		Version: "1.0.0",
		ID:      "test",
		Results: []keys.ResponseResult{
			{
				Address:   "alice@example.com",
				Status:    keys.StatusFound,
				Domain:    "example.com",
				DomainKey: nil, // missing!
				OriginSignature: &keys.Signature{
					KeyID: "fp",
					Value: base64.StdEncoding.EncodeToString([]byte("garbage")),
				},
			},
		},
	}
	verifier := &keys.Verifier{Suite: suite}
	if err := verifier.Verify(resp); err == nil {
		t.Error("Verifier accepted a result with no DomainKey")
	}
}

// TestVerifierSkipsNotFoundResults confirms that results with
// Status != StatusFound are not verified (and therefore do not
// need DomainKey or OriginSignature to be populated).
func TestVerifierSkipsNotFoundResults(t *testing.T) {
	suite := crypto.SuiteBaseline
	resp := &keys.Response{
		Type:    keys.RequestType,
		Step:    keys.RequestStepResponse,
		Version: "1.0.0",
		ID:      "test",
		Results: []keys.ResponseResult{
			{Address: "ghost@example.com", Status: keys.StatusNotFound, Domain: "example.com"},
			{Address: "error@example.com", Status: keys.StatusError, Domain: "example.com", ErrorReason: "nope"},
		},
	}
	verifier := &keys.Verifier{Suite: suite}
	if err := verifier.Verify(resp); err != nil {
		t.Errorf("Verifier rejected a response with only not_found/error results: %v", err)
	}
}
