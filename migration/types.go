// Package migration implements SEMP_MIGRATION record types and the
// sequential four-signature signing pattern from MIGRATION.md §3.
//
// The migration record carries a chain of four signatures (old
// identity, new identity, new domain, old domain) that each commit
// to the prior signatures, so a verifier walking them in order
// detects any after-the-fact tampering with an earlier signing
// party's commitment.
package migration

import (
	"time"

	"github.com/semp-dev/semp-go/extensions"
)

// Wire-level constants per MIGRATION.md §3.1.
const (
	RecordType    = "SEMP_MIGRATION"
	RecordVersion = "1.0.0"
)

// Mode names the migration mode per MIGRATION.md §2.
type Mode string

// Migration modes.
const (
	// ModeCooperative: the old provider participates and signs the
	// record. During the notice window the old provider returns
	// policy_forbidden with a migration_notice body for envelopes
	// addressed to the old address and includes a migration_to field
	// on key fetches. The old provider does not forward envelopes;
	// any user-initiated forwarding by a still-authenticated client
	// uses the ordinary forwarding primitive in ENVELOPE.md §6.6.
	ModeCooperative Mode = "cooperative"

	// ModeUnilateral: the user migrates without the old provider's
	// participation. old_domain_signature MAY be absent.
	ModeUnilateral Mode = "unilateral"
)

// Notice window bounds per MIGRATION.md §5.1. The library exposes
// the spec's MUST-NOT bounds; operators MAY accept any window in
// the open interval (MinNoticeWindow, MaxNoticeWindow] depending on
// policy.
const (
	// MinNoticeWindow is the spec's hard lower bound. Conformant old
	// providers MUST NOT accept windows below this.
	MinNoticeWindow = 30 * 24 * time.Hour

	// RecommendedNoticeWindow is the §5.1 recommended default.
	RecommendedNoticeWindow = 180 * 24 * time.Hour

	// MaxNoticeWindow is the spec's upper bound. Old providers MAY
	// decline windows above this.
	MaxNoticeWindow = 730 * 24 * time.Hour
)

// Signature is the reusable signature block shared by all four
// signature slots in a MigrationRecord.
type Signature struct {
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"key_id"`
	Value     string `json:"value"`
}

// MigrationRecord is a SEMP_MIGRATION record per MIGRATION.md §3.1.
//
// NoticeWindowUntil is a *time.Time so the JSON form can carry an
// explicit null when no notice window is offered (typical for
// unilateral mode where the old provider is non-cooperative). A
// zero time.Time would marshal as "0001-01-01T00:00:00Z" rather
// than null, which the spec's "Yes / nullable" type does not
// permit.
//
// OldDomainSignature is also a pointer so it can be omitted in
// unilateral mode where the old provider does not participate. The
// spec marks it required only when mode == cooperative.
type MigrationRecord struct {
	Type                 string     `json:"type"`
	Version              string     `json:"version"`
	RecordID             string     `json:"record_id"`
	OldAddress           string     `json:"old_address"`
	NewAddress           string     `json:"new_address"`
	OldIdentityKeyID     string     `json:"old_identity_key_id"`
	NewIdentityKeyID     string     `json:"new_identity_key_id"`
	NewIdentityPublicKey string     `json:"new_identity_public_key"` // base64
	MigratedAt           time.Time  `json:"migrated_at"`
	NoticeWindowUntil    *time.Time `json:"notice_window_until"`
	Mode                 Mode       `json:"mode"`

	OldIdentitySignature Signature  `json:"old_identity_signature"`
	NewIdentitySignature Signature  `json:"new_identity_signature"`
	NewDomainSignature   Signature  `json:"new_domain_signature"`
	OldDomainSignature   *Signature `json:"old_domain_signature,omitempty"`

	// Extensions carries optional extension entries per
	// EXTENSIONS.md §2.1 / MIGRATION.md §3.1. Every signature in the
	// §3.3 chain covers Extensions, so any content captured here is
	// attested by all four signers.
	Extensions extensions.Map `json:"extensions,omitempty"`
}
