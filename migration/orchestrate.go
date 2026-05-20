package migration

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"semp.dev/semp-go/crypto"
)

// SubmitInput bundles the inputs the new provider side uses to
// build a cooperative migration submission per MIGRATION.md §4.1
// steps 3-7. The user supplies their old + new identity keys; the
// new provider supplies its domain key.
//
// For Mode == ModeUnilateral, NoticeWindow is ignored and
// NoticeWindowUntil on the resulting record is nil. The old-
// domain signature slot is left empty and BuildSubmission's output
// is the final published form (no countersign step).
type SubmitInput struct {
	Suite crypto.Suite

	OldAddress       string
	NewAddress       string
	OldIdentityKeyID string
	NewIdentityKeyID string

	// OldIdentityPriv signs old_identity_signature.
	OldIdentityPriv []byte

	// NewIdentityPriv signs new_identity_signature.
	NewIdentityPriv []byte

	// NewIdentityPublicKey is the base64-encoded new identity
	// public key embedded in the record body.
	NewIdentityPublicKey string

	// NewDomainKeyID + NewDomainPriv signs new_domain_signature.
	NewDomainKeyID string
	NewDomainPriv  []byte

	// OldDomainKeyID is the old provider's domain signing key
	// fingerprint. The new provider obtains this from the old
	// provider's discovery configuration before submitting; it is
	// embedded in the old_domain_signature slot's KeyID up front
	// so the chained-signature canonical bytes are stable across
	// the four signing passes (PrepareSignatures requirement).
	// Ignored for ModeUnilateral.
	OldDomainKeyID string

	Mode Mode

	// NoticeWindow applies to ModeCooperative only. Must satisfy
	// MinNoticeWindow <= window <= MaxNoticeWindow per §5.1;
	// values outside the bounds return an error.
	NoticeWindow time.Duration

	MigratedAt time.Time

	// RecordID is optional; auto-generated when empty.
	RecordID string
}

// BuildSubmission constructs and signs the migration record the new
// provider submits to the old provider's migration endpoint per
// §4.1 steps 3-7.
//
// In cooperative mode the returned record has three signatures
// populated (old_identity, new_identity, new_domain) and the
// old_domain slot prepared but empty; the new provider POSTs the
// record to the old provider's migration endpoint, which then runs
// AcceptSubmission to verify and countersign.
//
// In unilateral mode the record has the same three signatures and
// no old_domain slot allocated; the record is final at this point
// and the user publishes it via the new provider's discovery
// configuration.
func BuildSubmission(in SubmitInput) (*MigrationRecord, error) {
	if in.Suite == nil {
		return nil, errors.New("migration: nil suite")
	}
	if in.OldAddress == "" || in.NewAddress == "" {
		return nil, errors.New("migration: old_address and new_address are required")
	}
	if in.OldIdentityKeyID == "" || in.NewIdentityKeyID == "" {
		return nil, errors.New("migration: old_identity_key_id and new_identity_key_id are required")
	}
	if in.NewIdentityPublicKey == "" {
		return nil, errors.New("migration: new_identity_public_key is required")
	}
	if in.NewDomainKeyID == "" {
		return nil, errors.New("migration: new_domain_key_id is required")
	}
	if len(in.OldIdentityPriv) == 0 || len(in.NewIdentityPriv) == 0 || len(in.NewDomainPriv) == 0 {
		return nil, errors.New("migration: old_identity_priv, new_identity_priv, and new_domain_priv are all required")
	}
	if in.MigratedAt.IsZero() {
		return nil, errors.New("migration: migrated_at is required")
	}
	switch in.Mode {
	case ModeCooperative:
		if in.NoticeWindow < MinNoticeWindow {
			return nil, fmt.Errorf("migration: notice window %s below minimum %s",
				in.NoticeWindow, MinNoticeWindow)
		}
		if in.NoticeWindow > MaxNoticeWindow {
			return nil, fmt.Errorf("migration: notice window %s above maximum %s",
				in.NoticeWindow, MaxNoticeWindow)
		}
		if in.OldDomainKeyID == "" {
			return nil, errors.New("migration: cooperative mode requires OldDomainKeyID (looked up from old provider's discovery configuration)")
		}
	case ModeUnilateral:
		// no window
	default:
		return nil, fmt.Errorf("migration: unknown mode %q", in.Mode)
	}

	recordID := in.RecordID
	if recordID == "" {
		var err error
		recordID, err = newRecordID()
		if err != nil {
			return nil, fmt.Errorf("migration: generate record_id: %w", err)
		}
	}

	r := &MigrationRecord{
		Type:                 RecordType,
		Version:              RecordVersion,
		RecordID:             recordID,
		OldAddress:           in.OldAddress,
		NewAddress:           in.NewAddress,
		OldIdentityKeyID:     in.OldIdentityKeyID,
		NewIdentityKeyID:     in.NewIdentityKeyID,
		NewIdentityPublicKey: in.NewIdentityPublicKey,
		MigratedAt:           in.MigratedAt,
		Mode:                 in.Mode,
	}
	if in.Mode == ModeCooperative {
		until := in.MigratedAt.Add(in.NoticeWindow)
		r.NoticeWindowUntil = &until
	}

	// Pre-populate Algorithm + KeyID on every slot so the chained-
	// signature canonical bytes are stable across passes. In
	// cooperative mode this allocates the old_domain_signature slot
	// with the old provider's KeyID populated up front; the old
	// provider populates only the .Value field at AcceptSubmission
	// time.
	PrepareSignatures(r, in.OldIdentityKeyID, in.NewIdentityKeyID, in.NewDomainKeyID, in.OldDomainKeyID)

	// Sign passes 1-3 in spec order.
	if err := SignOldIdentity(in.Suite.Signer(), in.OldIdentityPriv, in.OldIdentityKeyID, r); err != nil {
		return nil, fmt.Errorf("migration: SignOldIdentity: %w", err)
	}
	if err := SignNewIdentity(in.Suite.Signer(), in.NewIdentityPriv, in.NewIdentityKeyID, r); err != nil {
		return nil, fmt.Errorf("migration: SignNewIdentity: %w", err)
	}
	if err := SignNewDomain(in.Suite.Signer(), in.NewDomainPriv, in.NewDomainKeyID, r); err != nil {
		return nil, fmt.Errorf("migration: SignNewDomain: %w", err)
	}
	return r, nil
}

// AcceptInput bundles the inputs the old provider's migration
// endpoint uses to verify a submitted cooperative record per §4.1
// step 8 and §4.2.
type AcceptInput struct {
	Suite crypto.Suite

	// Record is the 3-sig record submitted by the new provider.
	Record *MigrationRecord

	// OldIdentityPub is the bytes of the old identity public key
	// (looked up from the old provider's prior key state by
	// Record.OldIdentityKeyID).
	OldIdentityPub []byte

	// NewDomainPub is the new provider's current domain signing
	// key (looked up from the new provider's discovery
	// configuration).
	NewDomainPub []byte

	// OldDomainPriv + OldDomainKeyID sign the old_domain
	// countersignature.
	OldDomainKeyID string
	OldDomainPriv  []byte

	// Now is the current wall-clock; used for migrated_at clock-skew
	// validation per §7.1 step 6.
	Now time.Time

	// OldIdentityCreated is the old identity key's creation
	// timestamp; used by CheckMigratedAtBound for the §3.4 lower
	// bound.
	OldIdentityCreated time.Time

	// NoticePolicy is the operator's per-window-bound check.
	// Returns nil if the requested window is acceptable; an
	// operator-defined error otherwise (typically wrapping
	// ErrNoticeWindowRefused). When nil, the policy accepts any
	// window within Min/Max bounds (already enforced by Validate).
	NoticePolicy func(window time.Duration) error

	// Reservations, when non-nil, registers the §6.1 lockout for
	// the migrated local-part after countersigning succeeds. The
	// reservation runs through NoticeWindowUntil.
	Reservations LockoutRegistry
}

// AcceptSubmission verifies the submitted record per §4.1 step 8
// and §4.2 obligations, countersigns with the old domain key, and
// (when configured) records the §6.1 lockout. Returns the 4-sig
// record ready for publication.
//
// Per §4.2 the old provider:
//   - Verifies all signatures on the submitted record before
//     countersigning.
//   - Refuses to modify the record after the user has signed it.
//   - Countersigns with its domain key.
//   - Holds the local-part in lockout for the notice window.
//
// AcceptSubmission rejects:
//   - Unilateral records (the old provider is not a participant in
//     unilateral migration; the old endpoint MUST NOT countersign).
//   - Records with a non-matching mode / shape (Validate failure).
//   - Records whose three submitted signatures fail verification.
//   - Records with a notice window that the operator's policy
//     refuses (NoticePolicy returns non-nil).
//   - Records whose migrated_at fails the §3.4 / §7.1 step 6 bound
//     check (in the past beyond clock-skew tolerance, or before
//     OldIdentityCreated).
//   - Records whose old local-part already has a prior lockout
//     reservation (§4.2 "MUST NOT countersign a second migration
//     record for the same old address while a prior record is in
//     its notice window").
func AcceptSubmission(ctx context.Context, in AcceptInput) (*MigrationRecord, error) {
	if in.Suite == nil {
		return nil, errors.New("migration: nil suite")
	}
	if in.Record == nil {
		return nil, errors.New("migration: nil record")
	}
	if in.Record.Mode != ModeCooperative {
		return nil, fmt.Errorf("migration: AcceptSubmission requires mode=%s, got %s",
			ModeCooperative, in.Record.Mode)
	}
	if len(in.OldIdentityPub) == 0 || len(in.NewDomainPub) == 0 {
		return nil, errors.New("migration: old_identity_pub and new_domain_pub are required")
	}
	if in.OldDomainKeyID == "" || len(in.OldDomainPriv) == 0 {
		return nil, errors.New("migration: old_domain_key_id and old_domain_priv are required")
	}
	if in.Record.OldDomainSignature == nil {
		return nil, errors.New("migration: cooperative record missing old_domain_signature slot")
	}
	if in.Record.OldDomainSignature.Value != "" {
		return nil, errors.New("migration: old_domain_signature already populated; not a fresh submission")
	}

	if err := in.Record.Validate(); err != nil {
		return nil, fmt.Errorf("migration: record validate: %w", err)
	}

	// §3.4 / §7.1 step 6 migrated_at bound check.
	if err := CheckMigratedAtBound(in.Record, in.OldIdentityCreated, in.Now); err != nil {
		return nil, fmt.Errorf("migration: migrated_at bound: %w", err)
	}

	// Notice window policy: bound-check is built into
	// MigrationRecord.Validate, but the operator may impose
	// stricter rules (for example, declining > 365 days even
	// though the spec permits 730).
	if in.Record.NoticeWindowUntil == nil {
		return nil, errors.New("migration: cooperative record requires notice_window_until")
	}
	window := in.Record.NoticeWindowUntil.Sub(in.Record.MigratedAt)
	if in.NoticePolicy != nil {
		if err := in.NoticePolicy(window); err != nil {
			return nil, fmt.Errorf("migration: notice policy: %w", err)
		}
	}

	// Verify the three submitted signatures using the partial
	// verification helper.
	if err := verifyOldIdentitySignature(in.Suite.Signer(), in.OldIdentityPub, in.Record); err != nil {
		return nil, fmt.Errorf("migration: verify old_identity_signature: %w", err)
	}
	// new_identity_pub for the canonical-bytes verification - extract
	// from the record body (it embeds new_identity_public_key).
	newIdentityPub, err := decodeNewIdentityPublicKey(in.Record)
	if err != nil {
		return nil, fmt.Errorf("migration: decode new_identity_public_key: %w", err)
	}
	if err := verifyNewIdentitySignature(in.Suite.Signer(), newIdentityPub, in.Record); err != nil {
		return nil, fmt.Errorf("migration: verify new_identity_signature: %w", err)
	}
	if err := verifyNewDomainSignature(in.Suite.Signer(), in.NewDomainPub, in.Record); err != nil {
		return nil, fmt.Errorf("migration: verify new_domain_signature: %w", err)
	}

	// Reserve the lockout BEFORE countersigning so a duplicate
	// concurrent submission for the same old address fails with
	// the typed error. Per §4.2 the old provider "MUST NOT
	// countersign a second migration record for the same old
	// address while a prior record is in its notice window".
	if in.Reservations != nil {
		localpart, err := localpartOf(in.Record.OldAddress)
		if err != nil {
			return nil, fmt.Errorf("migration: parse old_address: %w", err)
		}
		if err := in.Reservations.Reserve(ctx, localpart, *in.Record.NoticeWindowUntil, in.Record.RecordID); err != nil {
			return nil, fmt.Errorf("migration: reserve lockout: %w", err)
		}
	}

	// Verify the new provider populated the old_domain slot's KeyID
	// to match this old domain's fingerprint. The new provider
	// SHOULD have looked this up from the old provider's discovery
	// configuration before submitting; a mismatch here indicates
	// the new provider used a stale or wrong fingerprint.
	if in.Record.OldDomainSignature.KeyID != in.OldDomainKeyID {
		return nil, fmt.Errorf("migration: submitted old_domain_signature.key_id %q does not match old provider's fingerprint %q",
			in.Record.OldDomainSignature.KeyID, in.OldDomainKeyID)
	}

	// Countersign with the old domain key. SignOldDomain populates
	// only the .Value field; the slot's Algorithm and KeyID were
	// pre-populated by the new provider's BuildSubmission step so
	// the chained-signature canonical bytes are stable.
	if err := SignOldDomain(in.Suite.Signer(), in.OldDomainPriv, in.OldDomainKeyID, in.Record); err != nil {
		return nil, fmt.Errorf("migration: SignOldDomain: %w", err)
	}
	return in.Record, nil
}

// verifyOldIdentitySignature checks the old_identity_signature
// slot using the same canonical-bytes routine the verifier walks.
// Implemented inline to avoid coupling AcceptSubmission to the
// full four-pass VerifyMigrationRecord (which requires every
// signature to be populated, which the cooperative submission
// flow does not satisfy yet).
func verifyOldIdentitySignature(signer crypto.Signer, pub []byte, r *MigrationRecord) error {
	return verifyPass(signer, pub, r, 0, "old_identity_signature")
}
func verifyNewIdentitySignature(signer crypto.Signer, pub []byte, r *MigrationRecord) error {
	return verifyPass(signer, pub, r, 1, "new_identity_signature")
}
func verifyNewDomainSignature(signer crypto.Signer, pub []byte, r *MigrationRecord) error {
	return verifyPass(signer, pub, r, 2, "new_domain_signature")
}

// decodeNewIdentityPublicKey extracts the base64-decoded bytes of
// the new identity public key embedded in r.
func decodeNewIdentityPublicKey(r *MigrationRecord) ([]byte, error) {
	if r.NewIdentityPublicKey == "" {
		return nil, errors.New("migration: record missing new_identity_public_key")
	}
	return base64.StdEncoding.DecodeString(r.NewIdentityPublicKey)
}

// localpartOf returns the local part of an address (everything
// before "@"). Used for §6.1 lockout keying. Returns an error if
// the address has no "@".
func localpartOf(addr string) (string, error) {
	for i := 0; i < len(addr); i++ {
		if addr[i] == '@' {
			return addr[:i], nil
		}
	}
	return "", fmt.Errorf("migration: address %q has no local-part separator", addr)
}

// newRecordID returns a 26-character ULID-shaped identifier used
// for record_id when the caller does not supply one. Inlined to
// avoid pulling in an external ULID library.
func newRecordID() (string, error) {
	var bits [16]byte
	ms := uint64(time.Now().UnixMilli())
	bits[0] = byte(ms >> 40)
	bits[1] = byte(ms >> 32)
	bits[2] = byte(ms >> 24)
	bits[3] = byte(ms >> 16)
	bits[4] = byte(ms >> 8)
	bits[5] = byte(ms)
	if _, err := rand.Read(bits[6:]); err != nil {
		return "", err
	}
	const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	u := binary.BigEndian.Uint64(bits[:8])
	u2 := binary.BigEndian.Uint64(bits[8:16])
	out := make([]byte, 26)
	for i := 25; i >= 13; i-- {
		out[i] = alphabet[u2&31]
		u2 >>= 5
	}
	for i := 12; i >= 0; i-- {
		out[i] = alphabet[u&31]
		u >>= 5
	}
	return string(out), nil
}

// CheckMigratedAtBound is exposed in sign.go; AcceptSubmission
// invokes it via the helper below. The helper exists because
// AcceptSubmission's Now and OldIdentityCreated names are nicer
// than passing the raw signature.
//
// (Defined inline so godoc places it next to AcceptSubmission.
// The actual implementation in sign.go applies clockskew.Default
// for the future-skew check.)

// ErrNoticeWindowRefused is the conventional sentinel an
// operator's NoticePolicy returns when the requested window
// is outside their per-deployment policy.
var ErrNoticeWindowRefused = errors.New("migration: operator policy refused this notice window")
