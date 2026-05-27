package migration

import (
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/semp-dev/semp-go/clockskew"
	"github.com/semp-dev/semp-go/crypto"
	"github.com/semp-dev/semp-go/canonical"
)

// SignatureAlgorithmEd25519 is the only signature algorithm
// defined for migration records in the current spec.
const SignatureAlgorithmEd25519 = "ed25519"

// canonicalBytesElidingSignature returns the canonical JSON form
// of r with ONLY the named signature object's `value` field elided
// per MIGRATION.md §3.3. Other signatures keep whatever value they
// have at this moment (empty for not-yet-signed slots, populated
// for already-signed slots), so the chained-signature property of
// §3.3 holds: each later signature commits to the prior ones.
func canonicalBytesElidingSignature(r *MigrationRecord, fieldName string) ([]byte, error) {
	if r == nil {
		return nil, errors.New("migration: nil record")
	}
	return canonical.MarshalWithElision(r, func(v any) error {
		root, ok := v.(map[string]any)
		if !ok {
			return fmt.Errorf("migration: expected top-level object, got %T", v)
		}
		sig, ok := root[fieldName].(map[string]any)
		if !ok {
			return fmt.Errorf("migration: record has no %s object", fieldName)
		}
		sig["value"] = ""
		return nil
	})
}

// signSlot signs r at the given slot. It elides only the slot's
// value during canonicalization, prefixes with
// SEMP-MIGRATION-RECORD:, and signs with priv. The slot's
// Algorithm and KeyID MUST be set before calling.
func signSlot(signer crypto.Signer, priv []byte, r *MigrationRecord, fieldName string, slot *Signature) error {
	if signer == nil {
		return errors.New("migration: nil signer")
	}
	if r == nil {
		return errors.New("migration: nil record")
	}
	if slot == nil {
		return errors.New("migration: nil signature slot")
	}
	if len(priv) == 0 {
		return errors.New("migration: empty private key")
	}
	if slot.Algorithm == "" || slot.KeyID == "" {
		return fmt.Errorf("migration: %s requires algorithm and key_id set before signing", fieldName)
	}
	slot.Value = ""
	canonicalBytes, err := canonicalBytesElidingSignature(r, fieldName)
	if err != nil {
		return err
	}
	prefixed := crypto.PrefixedMessage(crypto.SigCtxMigrationRecord, canonicalBytes)
	sig, err := signer.Sign(priv, prefixed)
	if err != nil {
		return fmt.Errorf("migration: sign %s: %w", fieldName, err)
	}
	slot.Value = base64.StdEncoding.EncodeToString(sig)
	return nil
}

// signatureOrder returns the slots in the §3.3 signing order.
// Index N corresponds to pass N (zero-indexed). The fourth entry
// is nil when r.OldDomainSignature is nil (unilateral mode).
func signatureOrder(r *MigrationRecord) []**Signature {
	old := &r.OldIdentitySignature
	newID := &r.NewIdentitySignature
	newDom := &r.NewDomainSignature
	if r.Mode == ModeCooperative && r.OldDomainSignature != nil {
		oldDom := r.OldDomainSignature
		return []**Signature{&old, &newID, &newDom, &oldDom}
	}
	return []**Signature{&old, &newID, &newDom}
}

// verifyPass verifies the signature at order index passIdx against
// pub. Recreates the canonical-bytes input that signing pass passIdx
// saw: the signing slot's value elided, every PRIOR slot at its
// final value, every LATER slot also elided to "" (since they had
// not been signed yet at that moment per §3.3's
// "Signatures are added in the order ... Each signature binds ...
// all prior signatures").
//
// fieldNames is the JSON field-name list parallel to the order
// returned by signatureOrder; passIdx selects the current pass.
func verifyPass(signer crypto.Signer, pub []byte, r *MigrationRecord, passIdx int, fieldName string) error {
	if signer == nil {
		return errors.New("migration: nil signer")
	}
	if r == nil {
		return errors.New("migration: nil record")
	}
	order := signatureOrder(r)
	if passIdx < 0 || passIdx >= len(order) {
		return fmt.Errorf("migration: pass index %d out of range", passIdx)
	}
	slot := *order[passIdx]
	if slot == nil {
		return fmt.Errorf("migration: %s signature slot is missing", fieldName)
	}
	if len(pub) == 0 {
		return fmt.Errorf("migration: empty %s public key", fieldName)
	}
	if slot.Value == "" {
		return fmt.Errorf("migration: %s is unsigned", fieldName)
	}
	sig, err := base64.StdEncoding.DecodeString(slot.Value)
	if err != nil {
		return fmt.Errorf("migration: %s base64: %w", fieldName, err)
	}

	// Save current values for slots from passIdx onward, clear them
	// to mimic the signing-time state, compute canonical bytes,
	// restore.
	type saved struct {
		slot     *Signature
		original string
	}
	cleared := make([]saved, 0, len(order)-passIdx)
	for i := passIdx; i < len(order); i++ {
		s := *order[i]
		if s == nil {
			continue
		}
		cleared = append(cleared, saved{slot: s, original: s.Value})
		s.Value = ""
	}
	defer func() {
		for _, c := range cleared {
			c.slot.Value = c.original
		}
	}()

	canonicalBytes, err := canonicalBytesElidingSignature(r, fieldName)
	if err != nil {
		return err
	}
	prefixed := crypto.PrefixedMessage(crypto.SigCtxMigrationRecord, canonicalBytes)
	if err := signer.Verify(pub, prefixed, sig); err != nil {
		return fmt.Errorf("migration: verify %s: %w", fieldName, err)
	}
	return nil
}

// PrepareSignatures pre-populates the Algorithm and KeyID fields on
// every signature slot so the canonical bytes for each later
// signing pass match what the slot verifier will reconstruct. Each
// later signature commits to the prior signatures' final state per
// §3.3, including their Algorithm and KeyID - if those fields
// changed between passes (because pass N populated them after
// pass N-1 had already signed), the chain would not verify.
//
// In cooperative mode, oldDomainKeyID names the old provider's
// signing key. In unilateral mode, oldDomainKeyID is ignored and
// no fourth signature slot is allocated.
func PrepareSignatures(r *MigrationRecord, oldIdentityKeyID, newIdentityKeyID, newDomainKeyID, oldDomainKeyID string) {
	if r == nil {
		return
	}
	r.OldIdentitySignature.Algorithm = SignatureAlgorithmEd25519
	r.OldIdentitySignature.KeyID = oldIdentityKeyID
	r.OldIdentitySignature.Value = ""
	r.NewIdentitySignature.Algorithm = SignatureAlgorithmEd25519
	r.NewIdentitySignature.KeyID = newIdentityKeyID
	r.NewIdentitySignature.Value = ""
	r.NewDomainSignature.Algorithm = SignatureAlgorithmEd25519
	r.NewDomainSignature.KeyID = newDomainKeyID
	r.NewDomainSignature.Value = ""
	if r.Mode == ModeCooperative {
		r.OldDomainSignature = &Signature{
			Algorithm: SignatureAlgorithmEd25519,
			KeyID:     oldDomainKeyID,
			Value:     "",
		}
	} else {
		r.OldDomainSignature = nil
	}
}

// SignOldIdentity is signing pass 1 of the §3.3 sequence. The
// caller MUST have invoked PrepareSignatures (or otherwise set the
// Algorithm and KeyID fields on every slot) before this call.
//
// oldIdentityPriv is the private half of the identity key
// currently active at the old address. oldIdentityKeyID is its
// fingerprint and MUST match what PrepareSignatures populated.
func SignOldIdentity(signer crypto.Signer, oldIdentityPriv []byte, oldIdentityKeyID string, r *MigrationRecord) error {
	if r == nil {
		return errors.New("migration: nil record")
	}
	if r.Type == "" {
		r.Type = RecordType
	}
	if r.Version == "" {
		r.Version = RecordVersion
	}
	if err := r.Validate(); err != nil {
		return err
	}
	if r.OldIdentitySignature.Algorithm == "" || r.OldIdentitySignature.KeyID == "" {
		return errors.New("migration: call PrepareSignatures before SignOldIdentity")
	}
	if r.OldIdentitySignature.KeyID != oldIdentityKeyID {
		return fmt.Errorf("migration: old_identity_signature.key_id %q does not match passed key %q",
			r.OldIdentitySignature.KeyID, oldIdentityKeyID)
	}
	return signSlot(signer, oldIdentityPriv, r, "old_identity_signature", &r.OldIdentitySignature)
}

// SignNewIdentity is signing pass 2 of the §3.3 sequence. The
// caller MUST have populated old_identity_signature already.
func SignNewIdentity(signer crypto.Signer, newIdentityPriv []byte, newIdentityKeyID string, r *MigrationRecord) error {
	if r == nil {
		return errors.New("migration: nil record")
	}
	if r.OldIdentitySignature.Value == "" {
		return errors.New("migration: SignOldIdentity MUST run before SignNewIdentity")
	}
	if err := r.Validate(); err != nil {
		return err
	}
	if r.NewIdentitySignature.Algorithm == "" || r.NewIdentitySignature.KeyID == "" {
		return errors.New("migration: call PrepareSignatures before SignNewIdentity")
	}
	if r.NewIdentitySignature.KeyID != newIdentityKeyID {
		return fmt.Errorf("migration: new_identity_signature.key_id %q does not match passed key %q",
			r.NewIdentitySignature.KeyID, newIdentityKeyID)
	}
	return signSlot(signer, newIdentityPriv, r, "new_identity_signature", &r.NewIdentitySignature)
}

// SignNewDomain is signing pass 3 of the §3.3 sequence. The caller
// MUST have populated old_identity and new_identity signatures
// already.
func SignNewDomain(signer crypto.Signer, newDomainPriv []byte, newDomainKeyID string, r *MigrationRecord) error {
	if r == nil {
		return errors.New("migration: nil record")
	}
	if r.OldIdentitySignature.Value == "" || r.NewIdentitySignature.Value == "" {
		return errors.New("migration: SignNewDomain requires old_identity and new_identity signatures present")
	}
	if err := r.Validate(); err != nil {
		return err
	}
	if r.NewDomainSignature.Algorithm == "" || r.NewDomainSignature.KeyID == "" {
		return errors.New("migration: call PrepareSignatures before SignNewDomain")
	}
	if r.NewDomainSignature.KeyID != newDomainKeyID {
		return fmt.Errorf("migration: new_domain_signature.key_id %q does not match passed key %q",
			r.NewDomainSignature.KeyID, newDomainKeyID)
	}
	return signSlot(signer, newDomainPriv, r, "new_domain_signature", &r.NewDomainSignature)
}

// SignOldDomain is signing pass 4 of the §3.3 sequence. Required
// only in cooperative mode; in unilateral mode the caller skips
// this pass and r.OldDomainSignature remains nil.
//
// The caller MUST have populated all three prior signatures.
func SignOldDomain(signer crypto.Signer, oldDomainPriv []byte, oldDomainKeyID string, r *MigrationRecord) error {
	if r == nil {
		return errors.New("migration: nil record")
	}
	if r.Mode != ModeCooperative {
		return fmt.Errorf("migration: SignOldDomain only valid for mode=cooperative (got %q)", r.Mode)
	}
	if r.OldIdentitySignature.Value == "" || r.NewIdentitySignature.Value == "" || r.NewDomainSignature.Value == "" {
		return errors.New("migration: SignOldDomain requires all three prior signatures present")
	}
	if err := r.Validate(); err != nil {
		return err
	}
	if r.OldDomainSignature == nil {
		return errors.New("migration: call PrepareSignatures before SignOldDomain (cooperative mode)")
	}
	if r.OldDomainSignature.Algorithm == "" || r.OldDomainSignature.KeyID == "" {
		return errors.New("migration: call PrepareSignatures before SignOldDomain")
	}
	if r.OldDomainSignature.KeyID != oldDomainKeyID {
		return fmt.Errorf("migration: old_domain_signature.key_id %q does not match passed key %q",
			r.OldDomainSignature.KeyID, oldDomainKeyID)
	}
	return signSlot(signer, oldDomainPriv, r, "old_domain_signature", r.OldDomainSignature)
}

// VerifyMigrationRecord verifies all four signatures (or three for
// unilateral mode) in the §3.3 order: old identity, new identity,
// new domain, old domain. Returns a typed error naming the failed
// pass.
//
// The caller supplies the four public keys: oldIdentityPub
// (resolved from r.OldIdentityKeyID at the old key endpoint),
// newIdentityPub (matches r.NewIdentityPublicKey or fetched from
// the new address), newDomainPub (the new provider's published
// signing key), and oldDomainPub (the old provider's published
// signing key; pass nil when mode == unilateral and
// OldDomainSignature is nil).
func VerifyMigrationRecord(signer crypto.Signer, r *MigrationRecord, oldIdentityPub, newIdentityPub, newDomainPub, oldDomainPub []byte) error {
	if r == nil {
		return errors.New("migration: nil record")
	}
	if err := r.Validate(); err != nil {
		return err
	}
	if err := verifyPass(signer, oldIdentityPub, r, 0, "old_identity_signature"); err != nil {
		return err
	}
	if err := verifyPass(signer, newIdentityPub, r, 1, "new_identity_signature"); err != nil {
		return err
	}
	if err := verifyPass(signer, newDomainPub, r, 2, "new_domain_signature"); err != nil {
		return err
	}
	if r.Mode == ModeCooperative {
		if r.OldDomainSignature == nil {
			return errors.New("migration: cooperative record missing old_domain_signature")
		}
		if err := verifyPass(signer, oldDomainPub, r, 3, "old_domain_signature"); err != nil {
			return err
		}
	} else {
		if r.OldDomainSignature != nil {
			return errors.New("migration: unilateral record MUST NOT carry old_domain_signature")
		}
	}
	return nil
}

// Validate reports whether r is structurally well-formed per
// MIGRATION.md §3.2. Does not verify signatures or check
// migrated_at against the old identity key's created timestamp;
// callers pair Validate with VerifyMigrationRecord and with
// CheckMigratedAtBound for the full receive-side check.
func (r *MigrationRecord) Validate() error {
	if r == nil {
		return errors.New("migration: nil record")
	}
	if r.Type != RecordType {
		return fmt.Errorf("migration: type %q, want %q", r.Type, RecordType)
	}
	if r.RecordID == "" {
		return errors.New("migration: missing record_id")
	}
	if r.OldAddress == "" {
		return errors.New("migration: missing old_address")
	}
	if r.NewAddress == "" {
		return errors.New("migration: missing new_address")
	}
	if r.OldIdentityKeyID == "" {
		return errors.New("migration: missing old_identity_key_id")
	}
	if r.NewIdentityKeyID == "" {
		return errors.New("migration: missing new_identity_key_id")
	}
	if r.NewIdentityPublicKey == "" {
		return errors.New("migration: missing new_identity_public_key")
	}
	if r.MigratedAt.IsZero() {
		return errors.New("migration: missing migrated_at")
	}
	switch r.Mode {
	case ModeCooperative:
		if r.NoticeWindowUntil == nil {
			return errors.New("migration: cooperative mode MUST set notice_window_until")
		}
		w := r.NoticeWindowUntil.Sub(r.MigratedAt)
		if w < MinNoticeWindow {
			return fmt.Errorf("migration: cooperative notice window %s below minimum %s",
				w, MinNoticeWindow)
		}
		if w > MaxNoticeWindow {
			return fmt.Errorf("migration: cooperative notice window %s exceeds maximum %s",
				w, MaxNoticeWindow)
		}
	case ModeUnilateral:
		// notice_window_until is OPTIONAL in unilateral mode;
		// callers may set it if they want to advertise a window
		// from the old provider's residual cooperation, or leave
		// it nil.
	default:
		return fmt.Errorf("migration: mode %q is not a valid mode", r.Mode)
	}
	return nil
}

// CheckMigratedAtBound enforces the §3.3 rule "migrated_at MUST be
// at or after the created timestamp of the old_identity_key_id key
// record and MUST NOT be in the future relative to the verifier's
// clock beyond ordinary clock-skew tolerance".
//
// oldKeyCreated is the `created` timestamp of the old identity key
// record (resolved from the old key endpoint). now is the
// verifier's wall clock.
func CheckMigratedAtBound(r *MigrationRecord, oldKeyCreated, now time.Time) error {
	if r == nil {
		return errors.New("migration: nil record")
	}
	if !oldKeyCreated.IsZero() && r.MigratedAt.Before(oldKeyCreated) {
		return fmt.Errorf("migration: migrated_at %s precedes old identity key created %s",
			r.MigratedAt.UTC().Format(time.RFC3339), oldKeyCreated.UTC().Format(time.RFC3339))
	}
	return clockskew.CheckFutureTimestamp(r.MigratedAt, now, clockskew.Default())
}
