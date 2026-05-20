package migration

import (
	"errors"
	"strings"
)

// MigrationNotice is the §5.3 body field attached to a
// policy_forbidden rejection emitted by the old provider during
// the migration notice window. It tells the sender's client where
// the recipient migrated to so the user can update their
// correspondent record and compose a fresh envelope to the new
// address.
//
// After the notice window elapses the old provider stops attaching
// the notice and handles envelopes to the old address the same way
// it handles envelopes to non-existent addresses.
//
// Per §5.3 the sending client MUST surface the notice to the user
// and MUST NOT automatically redirect correspondence without user
// confirmation per draft-gokce-semp-client §8.4.
type MigrationNotice struct {
	NewAddress         string `json:"new_address"`
	MigrationRecordID  string `json:"migration_record_id"`
	MigrationRecordURL string `json:"migration_record_url,omitempty"`
}

// BuildMigrationNotice returns a §5.3 notice from the published
// migration record. urlPattern is an optional URL template the
// operator uses to expose published records (typically
// "https://<old-domain>/.well-known/semp/migration/<record_id>"
// per §5.3 example). When urlPattern contains the literal
// "<record_id>" placeholder, BuildMigrationNotice substitutes the
// record's ID into the pattern; otherwise the pattern is used
// verbatim.
//
// Pass urlPattern as the empty string to omit MigrationRecordURL.
func BuildMigrationNotice(record *MigrationRecord, urlPattern string) (MigrationNotice, error) {
	if record == nil {
		return MigrationNotice{}, errors.New("migration: nil record")
	}
	if record.NewAddress == "" || record.RecordID == "" {
		return MigrationNotice{}, errors.New("migration: record missing new_address or record_id")
	}
	notice := MigrationNotice{
		NewAddress:        record.NewAddress,
		MigrationRecordID: record.RecordID,
	}
	if urlPattern != "" {
		notice.MigrationRecordURL = strings.ReplaceAll(urlPattern, "<record_id>", record.RecordID)
	}
	return notice, nil
}

// MigrationNoticeRejection is the §5.3 envelope-rejection wire
// shape emitted when the old provider receives an envelope during
// the migration notice window. It is a thin wrapper around the
// standard envelope rejection with a typed migration_notice body.
// The home server's HTTP layer marshals this to the SEMP_ENVELOPE
// step=rejected response.
type MigrationNoticeRejection struct {
	Type            string          `json:"type"`
	Step            string          `json:"step"`
	Version         string          `json:"version"`
	ReasonCode      string          `json:"reason_code"`
	Reason          string          `json:"reason"`
	MigrationNotice MigrationNotice `json:"migration_notice"`
}

// NewMigrationNoticeRejection returns the §5.3 rejection wrapping
// notice. The reason is a human-readable description; the spec
// example uses "Recipient has migrated."
func NewMigrationNoticeRejection(notice MigrationNotice, reason string) MigrationNoticeRejection {
	if reason == "" {
		reason = "Recipient has migrated."
	}
	return MigrationNoticeRejection{
		Type:            "SEMP_ENVELOPE",
		Step:            "rejected",
		Version:         "1.0.0",
		ReasonCode:      "policy_forbidden",
		Reason:          reason,
		MigrationNotice: notice,
	}
}
