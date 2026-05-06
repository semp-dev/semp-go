// Package migration implements SEMP_MIGRATION record types and the
// sequential four-signature signing pattern from MIGRATION.md §3.
//
// The migration record carries a chain of four signatures (old
// identity, new identity, new domain, old domain) that each commit
// to the prior signatures, so a verifier walking them in order
// detects any after-the-fact tampering with an earlier signing
// party's commitment.
package migration

import "time"

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
	// record. Forwarding is offered for the duration of
	// forwarding_window_until per §5.
	ModeCooperative Mode = "cooperative"

	// ModeUnilateral: the user migrates without the old provider's
	// participation. old_domain_signature MAY be absent.
	ModeUnilateral Mode = "unilateral"
)

// Forwarding window bounds per MIGRATION.md §5.1. The library
// exposes the spec's MUST-NOT bounds; operators MAY accept any
// window in the open interval (MinForwardingWindow,
// MaxForwardingWindow] depending on policy.
const (
	// MinForwardingWindow is the spec's hard lower bound.
	// Conformant old providers MUST NOT accept windows below this.
	MinForwardingWindow = 30 * 24 * time.Hour

	// RecommendedForwardingWindow is the §5.1 recommended default.
	RecommendedForwardingWindow = 180 * 24 * time.Hour

	// MaxForwardingWindow is the spec's upper bound. Old providers
	// MAY decline windows above this.
	MaxForwardingWindow = 730 * 24 * time.Hour
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
// ForwardingWindowUntil is a *time.Time so the JSON form can carry
// an explicit null when no forwarding is offered (typical for
// unilateral mode where the old provider is non-cooperative). A
// zero time.Time would marshal as "0001-01-01T00:00:00Z" rather
// than null, which the spec's "Yes / nullable" type does not
// permit.
//
// OldDomainSignature is also a pointer so it can be omitted in
// unilateral mode where the old provider does not participate. The
// spec marks it required only when mode == cooperative.
type MigrationRecord struct {
	Type                   string     `json:"type"`
	Version                string     `json:"version"`
	RecordID               string     `json:"record_id"`
	OldAddress             string     `json:"old_address"`
	NewAddress             string     `json:"new_address"`
	OldIdentityKeyID       string     `json:"old_identity_key_id"`
	NewIdentityKeyID       string     `json:"new_identity_key_id"`
	NewIdentityPublicKey   string     `json:"new_identity_public_key"` // base64
	MigratedAt             time.Time  `json:"migrated_at"`
	ForwardingWindowUntil  *time.Time `json:"forwarding_window_until"`
	Mode                   Mode       `json:"mode"`

	OldIdentitySignature Signature  `json:"old_identity_signature"`
	NewIdentitySignature Signature  `json:"new_identity_signature"`
	NewDomainSignature   Signature  `json:"new_domain_signature"`
	OldDomainSignature   *Signature `json:"old_domain_signature,omitempty"`
}
