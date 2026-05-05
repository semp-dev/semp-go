package recovery

import (
	"encoding/base64"
	"errors"
	"fmt"

	"semp.dev/semp-go/crypto"
	"semp.dev/semp-go/internal/canonical"
)

// SignatureAlgorithmEd25519 is the only signature algorithm defined
// for recovery records in the current spec. The constant is exported
// for callers that need to seed Algorithm fields on partial records.
const SignatureAlgorithmEd25519 = "ed25519"

// canonicalBytesElidingField returns the canonical JSON form of v
// with the named top-level signature object's `value` field elided.
// Used by every signing/verification path in this package because
// the records carry one or more signature objects whose value MUST
// be excluded from the input bytes.
func canonicalBytesElidingField(v any, fieldName string) ([]byte, error) {
	if v == nil {
		return nil, errors.New("recovery: nil record")
	}
	return canonical.MarshalWithElision(v, func(root any) error {
		m, ok := root.(map[string]any)
		if !ok {
			return fmt.Errorf("recovery: expected top-level object, got %T", root)
		}
		sig, ok := m[fieldName].(map[string]any)
		if !ok {
			return fmt.Errorf("recovery: record has no %s object", fieldName)
		}
		sig["value"] = ""
		return nil
	})
}

// canonicalBytesElidingThreeSignatures returns the canonical bytes
// of a SuccessorRecord with all THREE signature `value` fields
// elided to "". The successor record is signed three times over the
// same input (§7.3); each signing path passes through this helper
// to ensure each signature covers the same bytes.
func canonicalBytesElidingThreeSignatures(r *SuccessorRecord) ([]byte, error) {
	if r == nil {
		return nil, errors.New("recovery: nil successor record")
	}
	return canonical.MarshalWithElision(r, func(root any) error {
		m, ok := root.(map[string]any)
		if !ok {
			return fmt.Errorf("recovery: expected top-level object, got %T", root)
		}
		for _, fieldName := range []string{"recovery_signature", "new_key_signature", "domain_signature"} {
			sig, ok := m[fieldName].(map[string]any)
			if !ok {
				return fmt.Errorf("recovery: successor record missing %s", fieldName)
			}
			sig["value"] = ""
		}
		return nil
	})
}

// PrepareSuccessorSignatures pre-populates the Algorithm and KeyID
// fields on all three signature blocks so the canonical bytes are
// stable across the three signing passes. Callers MUST invoke this
// (or set the fields manually) before calling any of the
// SignSuccessor* functions; otherwise the first signature pass
// would compute over canonical bytes that differ from the second
// and third passes.
//
// The Value fields are left empty; each signing pass populates its
// own.
func PrepareSuccessorSignatures(r *SuccessorRecord, recoveryKeyID, newKeyID, domainKeyID string) {
	if r == nil {
		return
	}
	r.RecoverySignature.Algorithm = SignatureAlgorithmEd25519
	r.RecoverySignature.KeyID = recoveryKeyID
	r.RecoverySignature.Value = ""
	r.NewKeySignature.Algorithm = SignatureAlgorithmEd25519
	r.NewKeySignature.KeyID = newKeyID
	r.NewKeySignature.Value = ""
	r.DomainSignature.Algorithm = SignatureAlgorithmEd25519
	r.DomainSignature.KeyID = domainKeyID
	r.DomainSignature.Value = ""
}

// SignSuccessorRecovery applies the recovery_signature to r per
// RECOVERY.md §7.3. recoveryPriv is the private half of the
// recovery key pair derived from the recovery secret per §3.3;
// recoveryKeyID is its fingerprint, which MUST equal the
// recovery_verify_pk fingerprint published with the bundle by the
// prior identity key.
//
// The caller MUST have invoked PrepareSuccessorSignatures (or
// otherwise populated the Algorithm and KeyID fields on all three
// signature blocks) before calling this function. The recovery
// signature covers the canonical bytes with all three signature
// values elided; if Algorithm/KeyID change between passes, the
// signatures cover different canonical inputs and verification
// fails.
func SignSuccessorRecovery(signer crypto.Signer, recoveryPriv []byte, recoveryKeyID string, r *SuccessorRecord) error {
	if signer == nil {
		return errors.New("recovery: nil signer")
	}
	if r == nil {
		return errors.New("recovery: nil successor record")
	}
	if len(recoveryPriv) == 0 {
		return errors.New("recovery: empty recovery private key")
	}
	if recoveryKeyID == "" {
		return errors.New("recovery: empty recovery key fingerprint")
	}
	if err := r.Validate(); err != nil {
		return err
	}
	if r.RecoverySignature.Algorithm == "" || r.RecoverySignature.KeyID == "" {
		return errors.New("recovery: call PrepareSuccessorSignatures before SignSuccessorRecovery")
	}
	if r.RecoverySignature.KeyID != recoveryKeyID {
		return fmt.Errorf("recovery: recovery_signature.key_id %q does not match passed key %q",
			r.RecoverySignature.KeyID, recoveryKeyID)
	}
	r.RecoverySignature.Value = ""
	canonicalBytes, err := canonicalBytesElidingThreeSignatures(r)
	if err != nil {
		return err
	}
	prefixed := crypto.PrefixedMessage(crypto.SigCtxSuccessorRecord, canonicalBytes)
	sig, err := signer.Sign(recoveryPriv, prefixed)
	if err != nil {
		return fmt.Errorf("recovery: sign successor recovery: %w", err)
	}
	r.RecoverySignature.Value = base64.StdEncoding.EncodeToString(sig)
	return nil
}

// SignSuccessorNewKey applies the new_key_signature to r per
// RECOVERY.md §7.3.
func SignSuccessorNewKey(signer crypto.Signer, newIdentityPriv []byte, newKeyID string, r *SuccessorRecord) error {
	if signer == nil {
		return errors.New("recovery: nil signer")
	}
	if r == nil {
		return errors.New("recovery: nil successor record")
	}
	if len(newIdentityPriv) == 0 {
		return errors.New("recovery: empty new-identity private key")
	}
	if newKeyID == "" {
		return errors.New("recovery: empty new-identity key fingerprint")
	}
	if err := r.Validate(); err != nil {
		return err
	}
	if r.NewKeySignature.Algorithm == "" || r.NewKeySignature.KeyID == "" {
		return errors.New("recovery: call PrepareSuccessorSignatures before SignSuccessorNewKey")
	}
	if r.NewKeySignature.KeyID != newKeyID {
		return fmt.Errorf("recovery: new_key_signature.key_id %q does not match passed key %q",
			r.NewKeySignature.KeyID, newKeyID)
	}
	r.NewKeySignature.Value = ""
	canonicalBytes, err := canonicalBytesElidingThreeSignatures(r)
	if err != nil {
		return err
	}
	prefixed := crypto.PrefixedMessage(crypto.SigCtxSuccessorRecord, canonicalBytes)
	sig, err := signer.Sign(newIdentityPriv, prefixed)
	if err != nil {
		return fmt.Errorf("recovery: sign successor new-key: %w", err)
	}
	r.NewKeySignature.Value = base64.StdEncoding.EncodeToString(sig)
	return nil
}

// SignSuccessorDomain applies the domain_signature to r per
// RECOVERY.md §7.3.
func SignSuccessorDomain(signer crypto.Signer, domainPriv []byte, domainKeyID string, r *SuccessorRecord) error {
	if signer == nil {
		return errors.New("recovery: nil signer")
	}
	if r == nil {
		return errors.New("recovery: nil successor record")
	}
	if len(domainPriv) == 0 {
		return errors.New("recovery: empty domain private key")
	}
	if domainKeyID == "" {
		return errors.New("recovery: empty domain key fingerprint")
	}
	if err := r.Validate(); err != nil {
		return err
	}
	if r.DomainSignature.Algorithm == "" || r.DomainSignature.KeyID == "" {
		return errors.New("recovery: call PrepareSuccessorSignatures before SignSuccessorDomain")
	}
	if r.DomainSignature.KeyID != domainKeyID {
		return fmt.Errorf("recovery: domain_signature.key_id %q does not match passed key %q",
			r.DomainSignature.KeyID, domainKeyID)
	}
	r.DomainSignature.Value = ""
	canonicalBytes, err := canonicalBytesElidingThreeSignatures(r)
	if err != nil {
		return err
	}
	prefixed := crypto.PrefixedMessage(crypto.SigCtxSuccessorRecord, canonicalBytes)
	sig, err := signer.Sign(domainPriv, prefixed)
	if err != nil {
		return fmt.Errorf("recovery: sign successor domain: %w", err)
	}
	r.DomainSignature.Value = base64.StdEncoding.EncodeToString(sig)
	return nil
}

// VerifySuccessorRecord checks all three signatures on r against
// the supplied public keys per RECOVERY.md §7.5. recoveryVerifyPub
// is the recovery_verify_pk published in the prior key record;
// newKeyPub is the new identity public key embedded in r;
// domainPub is the home server's current domain signing key.
//
// Returns a typed error naming which signature failed when more
// than one path is at fault.
func VerifySuccessorRecord(signer crypto.Signer, r *SuccessorRecord, recoveryVerifyPub, newKeyPub, domainPub []byte) error {
	if signer == nil {
		return errors.New("recovery: nil signer")
	}
	if r == nil {
		return errors.New("recovery: nil successor record")
	}
	if err := r.Validate(); err != nil {
		return err
	}
	if r.RecoverySignature.Value == "" || r.NewKeySignature.Value == "" || r.DomainSignature.Value == "" {
		return errors.New("recovery: successor record missing one or more signatures")
	}
	canonicalBytes, err := canonicalBytesElidingThreeSignatures(r)
	if err != nil {
		return err
	}
	prefixed := crypto.PrefixedMessage(crypto.SigCtxSuccessorRecord, canonicalBytes)

	if err := verifyOne(signer, "recovery_signature", recoveryVerifyPub, r.RecoverySignature.Value, prefixed); err != nil {
		return err
	}
	if err := verifyOne(signer, "new_key_signature", newKeyPub, r.NewKeySignature.Value, prefixed); err != nil {
		return err
	}
	if err := verifyOne(signer, "domain_signature", domainPub, r.DomainSignature.Value, prefixed); err != nil {
		return err
	}
	return nil
}

func verifyOne(signer crypto.Signer, fieldName string, pub []byte, sigB64 string, prefixed []byte) error {
	if len(pub) == 0 {
		return fmt.Errorf("recovery: empty public key for %s", fieldName)
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return fmt.Errorf("recovery: %s base64: %w", fieldName, err)
	}
	if err := signer.Verify(pub, prefixed, sig); err != nil {
		return fmt.Errorf("recovery: verify %s: %w", fieldName, err)
	}
	return nil
}

// Validate reports whether r is structurally well-formed per
// RECOVERY.md §7. Does not verify signatures.
func (r *SuccessorRecord) Validate() error {
	if r == nil {
		return errors.New("recovery: nil successor record")
	}
	if r.Type == "" {
		r.Type = SuccessorRecordType
	}
	if r.Version == "" {
		r.Version = RecordVersion
	}
	if r.Type != SuccessorRecordType {
		return fmt.Errorf("recovery: successor type %q, want %q", r.Type, SuccessorRecordType)
	}
	if r.UserID == "" {
		return errors.New("recovery: successor record missing user_id")
	}
	if r.PriorKeyID == "" {
		return errors.New("recovery: successor record missing prior_key_id")
	}
	if r.NewKeyID == "" {
		return errors.New("recovery: successor record missing new_key_id")
	}
	if r.NewPublicKey == "" {
		return errors.New("recovery: successor record missing new_public_key")
	}
	if r.RecoveredAt.IsZero() {
		return errors.New("recovery: successor record missing recovered_at")
	}
	return nil
}

// SignManifest applies the user-identity signature to m per
// RECOVERY.md §5.2.
func SignManifest(signer crypto.Signer, identityPriv []byte, identityKeyID string, m *RecoverySetManifest) error {
	if signer == nil {
		return errors.New("recovery: nil signer")
	}
	if m == nil {
		return errors.New("recovery: nil manifest")
	}
	if len(identityPriv) == 0 {
		return errors.New("recovery: empty identity private key")
	}
	if identityKeyID == "" {
		return errors.New("recovery: empty identity key fingerprint")
	}
	if err := m.Validate(); err != nil {
		return err
	}
	m.Signature.Algorithm = SignatureAlgorithmEd25519
	m.Signature.KeyID = identityKeyID
	m.Signature.Value = ""
	canonicalBytes, err := canonicalBytesElidingField(m, "signature")
	if err != nil {
		return err
	}
	prefixed := crypto.PrefixedMessage(crypto.SigCtxRecoveryManifest, canonicalBytes)
	sig, err := signer.Sign(identityPriv, prefixed)
	if err != nil {
		return fmt.Errorf("recovery: sign manifest: %w", err)
	}
	m.Signature.Value = base64.StdEncoding.EncodeToString(sig)
	return nil
}

// VerifyManifest verifies m.Signature against identityPub per
// RECOVERY.md §5.2 (consumer rule: the signature is verified
// against the user's current identity key).
func VerifyManifest(signer crypto.Signer, identityPub []byte, m *RecoverySetManifest) error {
	if signer == nil {
		return errors.New("recovery: nil signer")
	}
	if m == nil {
		return errors.New("recovery: nil manifest")
	}
	if len(identityPub) == 0 {
		return errors.New("recovery: empty identity public key")
	}
	if m.Signature.Value == "" {
		return errors.New("recovery: manifest is unsigned")
	}
	if err := m.Validate(); err != nil {
		return err
	}
	sig, err := base64.StdEncoding.DecodeString(m.Signature.Value)
	if err != nil {
		return fmt.Errorf("recovery: manifest signature base64: %w", err)
	}
	canonicalBytes, err := canonicalBytesElidingField(m, "signature")
	if err != nil {
		return err
	}
	prefixed := crypto.PrefixedMessage(crypto.SigCtxRecoveryManifest, canonicalBytes)
	if err := signer.Verify(identityPub, prefixed, sig); err != nil {
		return fmt.Errorf("recovery: verify manifest signature: %w", err)
	}
	return nil
}

// Validate reports whether m is structurally well-formed per
// RECOVERY.md §5.2.
func (m *RecoverySetManifest) Validate() error {
	if m == nil {
		return errors.New("recovery: nil manifest")
	}
	if m.Type == "" {
		m.Type = RecoverySetManifestType
	}
	if m.Version == "" {
		m.Version = RecordVersion
	}
	if m.Type != RecoverySetManifestType {
		return fmt.Errorf("recovery: manifest type %q, want %q", m.Type, RecoverySetManifestType)
	}
	if m.BundleID == "" {
		return errors.New("recovery: manifest missing bundle_id")
	}
	if m.Threshold < 1 {
		return fmt.Errorf("recovery: manifest threshold %d MUST be >= 1", m.Threshold)
	}
	if m.TotalShares < m.Threshold {
		return fmt.Errorf("recovery: manifest total_shares %d MUST be >= threshold %d",
			m.TotalShares, m.Threshold)
	}
	if len(m.Contributors) != m.TotalShares {
		return fmt.Errorf("recovery: manifest contributors length %d MUST equal total_shares %d",
			len(m.Contributors), m.TotalShares)
	}
	if m.IssuedAt.IsZero() {
		return errors.New("recovery: manifest missing issued_at")
	}
	seenIndex := make(map[int]struct{}, len(m.Contributors))
	seenDevice := make(map[string]struct{}, len(m.Contributors))
	for i, c := range m.Contributors {
		if c.ShareIndex < 1 || c.ShareIndex > m.TotalShares {
			return fmt.Errorf("recovery: manifest contributors[%d] share_index %d out of [1, %d]",
				i, c.ShareIndex, m.TotalShares)
		}
		if _, ok := seenIndex[c.ShareIndex]; ok {
			return fmt.Errorf("recovery: manifest share_index %d appears more than once", c.ShareIndex)
		}
		seenIndex[c.ShareIndex] = struct{}{}
		if c.DeviceID == "" {
			return fmt.Errorf("recovery: manifest contributors[%d] missing device_id", i)
		}
		if _, ok := seenDevice[c.DeviceID]; ok {
			return fmt.Errorf("recovery: manifest device_id %q appears more than once", c.DeviceID)
		}
		seenDevice[c.DeviceID] = struct{}{}
		if c.DeviceIdentityPubkey.PublicKey == "" {
			return fmt.Errorf("recovery: manifest contributors[%d] missing device_identity_pubkey.public_key", i)
		}
		if c.DeviceIdentityPubkey.Algorithm == "" {
			return fmt.Errorf("recovery: manifest contributors[%d] missing device_identity_pubkey.algorithm", i)
		}
	}
	return nil
}

// SignShareRecord applies the device-identity signature to s per
// RECOVERY.md §5.3. devicePriv is the private half of the device
// key whose public part is recorded in the manifest contributor
// entry for s.ShareIndex; deviceKeyID is its fingerprint.
func SignShareRecord(signer crypto.Signer, devicePriv []byte, deviceKeyID string, s *RecoveryShareRecord) error {
	if signer == nil {
		return errors.New("recovery: nil signer")
	}
	if s == nil {
		return errors.New("recovery: nil share record")
	}
	if len(devicePriv) == 0 {
		return errors.New("recovery: empty device private key")
	}
	if deviceKeyID == "" {
		return errors.New("recovery: empty device key fingerprint")
	}
	if err := s.Validate(); err != nil {
		return err
	}
	s.DeviceSignature.Algorithm = SignatureAlgorithmEd25519
	s.DeviceSignature.KeyID = deviceKeyID
	s.DeviceSignature.Value = ""
	canonicalBytes, err := canonicalBytesElidingField(s, "device_signature")
	if err != nil {
		return err
	}
	prefixed := crypto.PrefixedMessage(crypto.SigCtxRecoveryShare, canonicalBytes)
	sig, err := signer.Sign(devicePriv, prefixed)
	if err != nil {
		return fmt.Errorf("recovery: sign share record: %w", err)
	}
	s.DeviceSignature.Value = base64.StdEncoding.EncodeToString(sig)
	return nil
}

// VerifyShareRecord verifies s.DeviceSignature against devicePub
// per RECOVERY.md §5.3. The caller is expected to look up devicePub
// from the manifest's contributor entry for s.ShareIndex; this
// function does NOT cross-check that linkage. Pair with
// CheckShareMatchesManifest for the full §5.3 receive-side check.
func VerifyShareRecord(signer crypto.Signer, devicePub []byte, s *RecoveryShareRecord) error {
	if signer == nil {
		return errors.New("recovery: nil signer")
	}
	if s == nil {
		return errors.New("recovery: nil share record")
	}
	if len(devicePub) == 0 {
		return errors.New("recovery: empty device public key")
	}
	if s.DeviceSignature.Value == "" {
		return errors.New("recovery: share record is unsigned")
	}
	if err := s.Validate(); err != nil {
		return err
	}
	sig, err := base64.StdEncoding.DecodeString(s.DeviceSignature.Value)
	if err != nil {
		return fmt.Errorf("recovery: share signature base64: %w", err)
	}
	canonicalBytes, err := canonicalBytesElidingField(s, "device_signature")
	if err != nil {
		return err
	}
	prefixed := crypto.PrefixedMessage(crypto.SigCtxRecoveryShare, canonicalBytes)
	if err := signer.Verify(devicePub, prefixed, sig); err != nil {
		return fmt.Errorf("recovery: verify share signature: %w", err)
	}
	return nil
}

// Validate reports whether s is structurally well-formed per
// RECOVERY.md §5.3.
func (s *RecoveryShareRecord) Validate() error {
	if s == nil {
		return errors.New("recovery: nil share record")
	}
	if s.Type == "" {
		s.Type = RecoveryShareRecordType
	}
	if s.Version == "" {
		s.Version = RecordVersion
	}
	if s.Type != RecoveryShareRecordType {
		return fmt.Errorf("recovery: share type %q, want %q", s.Type, RecoveryShareRecordType)
	}
	if s.BundleID == "" {
		return errors.New("recovery: share record missing bundle_id")
	}
	if s.ShareIndex < 1 {
		return fmt.Errorf("recovery: share record share_index %d MUST be >= 1", s.ShareIndex)
	}
	if s.Threshold < 1 || s.TotalShares < s.Threshold || s.ShareIndex > s.TotalShares {
		return fmt.Errorf("recovery: share record (threshold=%d, total_shares=%d, share_index=%d) is inconsistent",
			s.Threshold, s.TotalShares, s.ShareIndex)
	}
	if s.DeviceID == "" {
		return errors.New("recovery: share record missing device_id")
	}
	if s.ShareValue == "" {
		return errors.New("recovery: share record missing share_value")
	}
	if s.IssuedAt.IsZero() {
		return errors.New("recovery: share record missing issued_at")
	}
	return nil
}

// CheckShareMatchesManifest cross-checks that s belongs to m per
// RECOVERY.md §5.3 step 2: the share's bundle_id, share_index,
// device_id, threshold, and total_shares MUST all match the
// manifest's contributor entry for s.ShareIndex. Returns nil when
// every check passes.
//
// CheckShareMatchesManifest does NOT verify either signature; pair
// it with VerifyManifest and VerifyShareRecord for the full
// receive-side check.
func CheckShareMatchesManifest(s *RecoveryShareRecord, m *RecoverySetManifest) error {
	if s == nil {
		return errors.New("recovery: nil share record")
	}
	if m == nil {
		return errors.New("recovery: nil manifest")
	}
	if s.BundleID != m.BundleID {
		return fmt.Errorf("recovery: share bundle_id %q does not match manifest bundle_id %q",
			s.BundleID, m.BundleID)
	}
	if s.Threshold != m.Threshold {
		return fmt.Errorf("recovery: share threshold %d does not match manifest threshold %d",
			s.Threshold, m.Threshold)
	}
	if s.TotalShares != m.TotalShares {
		return fmt.Errorf("recovery: share total_shares %d does not match manifest total_shares %d",
			s.TotalShares, m.TotalShares)
	}
	for _, c := range m.Contributors {
		if c.ShareIndex != s.ShareIndex {
			continue
		}
		if c.DeviceID != s.DeviceID {
			return fmt.Errorf("recovery: share device_id %q does not match manifest device_id %q for share_index %d",
				s.DeviceID, c.DeviceID, s.ShareIndex)
		}
		return nil
	}
	return fmt.Errorf("recovery: manifest has no contributor entry for share_index %d", s.ShareIndex)
}
