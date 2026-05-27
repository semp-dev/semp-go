package migration

import (
	"context"
	"errors"
	"fmt"

	"github.com/semp-dev/semp-go/crypto"
)

// ThirdPartyHook is one of the §7 policy hooks a third-party
// domain runs after verifying a migration record. Each hook is
// SHOULD/MAY at the spec level - operators decide whether to
// preserve known-correspondent status, carry over reputation, or
// migrate block-list entries. A nil hook is silently skipped.
type ThirdPartyHook func(ctx context.Context, record *MigrationRecord) error

// ThirdPartyPolicy bundles the §7 SHOULD/MAY hooks. Each hook is
// invoked in spec order after a successful record verification:
//
//   - UpdateKnownCorrespondents (§7.2): preserve known-correspondent
//     status from old to new address, conditional on the migrated
//     identity key.
//   - CarryReputation (§7.3): per-domain reputation carry-over
//     (operator-discretion; see §7.3 "MAY carry over").
//   - MigrateBlockListEntries (§7.4): migrate block-list entries
//     targeting the old address to also target the new address;
//     migrated entries record the migration event in their
//     extensions for audit per §7.4.
//
// Any non-nil hook that errors causes ApplyThirdPartyPolicy to
// surface the first error; subsequent hooks still run so the
// operator's logging captures every failure.
type ThirdPartyPolicy struct {
	UpdateKnownCorrespondents ThirdPartyHook
	CarryReputation           ThirdPartyHook
	MigrateBlockListEntries   ThirdPartyHook
}

// ThirdPartyVerifyInput bundles the inputs the §7.1 verification
// path needs.
type ThirdPartyVerifyInput struct {
	Suite crypto.Suite

	// Record is the migration record to verify.
	Record *MigrationRecord

	// OldIdentityPub is the bytes of the OLD identity public key
	// at the time of migration (looked up from the user's
	// historical key state for OldIdentityKeyID).
	OldIdentityPub []byte

	// NewDomainPub is the new provider's CURRENT domain signing
	// key.
	NewDomainPub []byte

	// OldDomainPub is the old provider's CURRENT domain signing
	// key. Required only for cooperative records; for unilateral
	// records the field is ignored.
	OldDomainPub []byte
}

// VerifyThirdParty implements §7.1 third-party verification:
//
//   1. (Skipped: record fetch is the caller's concern.)
//   2. Verify old_identity_signature.
//   3. Verify new_identity_signature against new_identity_public_key.
//   4. Verify new_domain_signature.
//   5. For mode=cooperative, verify old_domain_signature.
//   6. (Caller supplies the migrated_at bound check via
//      CheckMigratedAtBound; not duplicated here.)
//
// Returns nil when every required signature verifies. On any
// failure the record MUST be treated as unverified per §7.1
// "If any verification fails, the domain MUST treat the record as
// unverified and MUST NOT apply any carry-over policy based on it."
func VerifyThirdParty(in ThirdPartyVerifyInput) error {
	if in.Suite == nil {
		return errors.New("migration: nil suite")
	}
	if in.Record == nil {
		return errors.New("migration: nil record")
	}
	if err := in.Record.Validate(); err != nil {
		return fmt.Errorf("migration: validate: %w", err)
	}
	newIdentityPub, err := decodeNewIdentityPublicKey(in.Record)
	if err != nil {
		return err
	}
	switch in.Record.Mode {
	case ModeCooperative:
		if len(in.OldDomainPub) == 0 {
			return errors.New("migration: cooperative third-party verification requires old_domain_pub")
		}
		return VerifyMigrationRecord(in.Suite.Signer(), in.Record,
			in.OldIdentityPub, newIdentityPub, in.NewDomainPub, in.OldDomainPub)
	case ModeUnilateral:
		// Verify the three present signatures by walking the same
		// passes VerifyMigrationRecord uses, minus the absent old
		// domain pass.
		if err := verifyOldIdentitySignature(in.Suite.Signer(), in.OldIdentityPub, in.Record); err != nil {
			return fmt.Errorf("migration: verify old_identity_signature: %w", err)
		}
		if err := verifyNewIdentitySignature(in.Suite.Signer(), newIdentityPub, in.Record); err != nil {
			return fmt.Errorf("migration: verify new_identity_signature: %w", err)
		}
		if err := verifyNewDomainSignature(in.Suite.Signer(), in.NewDomainPub, in.Record); err != nil {
			return fmt.Errorf("migration: verify new_domain_signature: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("migration: unknown mode %q", in.Record.Mode)
	}
}

// ApplyThirdPartyPolicy invokes each non-nil hook in the §7 order
// against the supplied (already-verified) record.
//
// The caller is responsible for verifying the record via
// VerifyThirdParty FIRST; ApplyThirdPartyPolicy does not re-verify.
// This separation lets operators cache verified records and apply
// policy hooks lazily (for example, on the next inbound envelope
// from the new address rather than at fetch time).
//
// Returns the FIRST hook error; subsequent hooks still run so the
// operator's logging captures every failure. The aggregate error
// list lives at *ThirdPartyPolicyErrors.Steps for callers that
// want to inspect every failure via errors.As.
func ApplyThirdPartyPolicy(ctx context.Context, record *MigrationRecord, policy ThirdPartyPolicy) error {
	if record == nil {
		return errors.New("migration: nil record")
	}
	steps := []struct {
		name string
		fn   ThirdPartyHook
	}{
		{"UpdateKnownCorrespondents", policy.UpdateKnownCorrespondents},
		{"CarryReputation", policy.CarryReputation},
		{"MigrateBlockListEntries", policy.MigrateBlockListEntries},
	}
	var errMap map[string]error
	for _, step := range steps {
		if step.fn == nil {
			continue
		}
		if err := step.fn(ctx, record); err != nil {
			if errMap == nil {
				errMap = make(map[string]error, 1)
			}
			errMap[step.name] = err
		}
	}
	if errMap == nil {
		return nil
	}
	return &ThirdPartyPolicyErrors{
		RecordID: record.RecordID,
		Steps:    errMap,
	}
}

// ThirdPartyPolicyErrors aggregates per-hook errors from a single
// ApplyThirdPartyPolicy run.
type ThirdPartyPolicyErrors struct {
	RecordID string
	Steps    map[string]error
}

// Error implements error.
func (e *ThirdPartyPolicyErrors) Error() string {
	if e == nil || len(e.Steps) == 0 {
		return "migration: no third-party policy errors"
	}
	return fmt.Sprintf("migration: third-party policy errors for record %s: %d failed hook(s)",
		e.RecordID, len(e.Steps))
}

// Unwrap surfaces the first error so errors.Is matching still
// works for callers that want to detect a specific failure mode.
func (e *ThirdPartyPolicyErrors) Unwrap() error {
	if e == nil {
		return nil
	}
	for _, name := range []string{"UpdateKnownCorrespondents", "CarryReputation", "MigrateBlockListEntries"} {
		if err, ok := e.Steps[name]; ok {
			return err
		}
	}
	return nil
}
