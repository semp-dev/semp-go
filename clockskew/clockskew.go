// Package clockskew implements the tiered clock-skew tolerance rules
// from CONFORMANCE.md section 9.3 (spec commit 2b4762d).
//
// SEMP timestamps appear in many places: postmark.expires, PoW
// challenge expires, session expires_at, block list sync timestamps,
// queue state records, backup bundle created_at, migration
// migrated_at, forwarder attestations, and delegated certificate
// lifetimes. Every validator MUST enforce a consistent tolerance.
//
// The spec's MUST/SHOULD tiers:
//
//   - Future-dated: MUST reject if T > now + 15 minutes; SHOULD reject
//     if T > now + 5 minutes; MUST accept T within 0 to 5 minutes of
//     now.
//   - Expired:       MUST reject when now > T + 15 minutes; SHOULD
//     reject at now > T; MAY grace 5 minutes.
//
// Senders MUST NOT rely on grace windows. Senders MUST set expiry
// values far enough in the future that a well-behaved verifier can
// accept them without grace.
//
// This package exposes two helpers, CheckFutureTimestamp and
// CheckExpiry, configured through a Tolerance struct. The default
// tolerance matches the MUST bounds. Operators who want to be stricter
// (SHOULD-enforcement) can pass a shorter grace.
package clockskew

import (
	"errors"
	"fmt"
	"time"
)

// Tolerance is the clock-skew tolerance bound applied on one side.
// Forward is the maximum amount a timestamp may be in the future
// relative to the verifier's clock; Grace is the maximum amount a
// timestamp's expiry may be in the past before the verifier MUST
// reject.
//
// The zero Tolerance rejects any deviation; callers typically use
// Default or a custom tightness.
type Tolerance struct {
	// Forward is the maximum T - now accepted for a future-dated
	// timestamp. A timestamp more than Forward in the future MUST be
	// rejected as implausible.
	Forward time.Duration

	// Grace is the maximum now - T accepted for an expired timestamp.
	// A timestamp whose expiry is more than Grace in the past MUST be
	// rejected.
	Grace time.Duration
}

// Default returns the MUST-level tolerance: 15 minutes on either side,
// matching CONFORMANCE.md section 9.3.1.
func Default() Tolerance {
	return Tolerance{
		Forward: 15 * time.Minute,
		Grace:   15 * time.Minute,
	}
}

// Strict returns the SHOULD-level tolerance: 5 minutes future, no
// grace on expiry. Verifiers that want the tighter SHOULD interpretation
// use this.
func Strict() Tolerance {
	return Tolerance{
		Forward: 5 * time.Minute,
		Grace:   0,
	}
}

// CheckFutureTimestamp returns an error if t is more than tol.Forward
// in the future relative to now. A timestamp at or before now is
// always accepted (past timestamps are the expiry path).
//
// Use CheckFutureTimestamp for fields that carry "this record was
// produced at T" where T is expected to be at or near now: block list
// sync timestamps, observation timestamps, delivery receipt
// accepted_at, migration migrated_at.
func CheckFutureTimestamp(t time.Time, now time.Time, tol Tolerance) error {
	if t.IsZero() {
		return errors.New("clockskew: zero timestamp")
	}
	if t.After(now.Add(tol.Forward)) {
		return fmt.Errorf("clockskew: timestamp %s is more than %s in the future of %s",
			t.UTC().Format(time.RFC3339), tol.Forward, now.UTC().Format(time.RFC3339))
	}
	return nil
}

// CheckExpiry returns an error if expiresAt has passed by more than
// tol.Grace relative to now. A future expiry is always accepted (this
// is the expiry path, not the future-dated path).
//
// Use CheckExpiry for fields that declare "valid until T": postmark
// expires, PoW challenge expires, session expires_at, delegated
// certificate expires_at.
func CheckExpiry(expiresAt time.Time, now time.Time, tol Tolerance) error {
	if expiresAt.IsZero() {
		return errors.New("clockskew: zero expiry")
	}
	if now.After(expiresAt.Add(tol.Grace)) {
		return fmt.Errorf("clockskew: expiry %s is more than %s in the past of %s",
			expiresAt.UTC().Format(time.RFC3339), tol.Grace, now.UTC().Format(time.RFC3339))
	}
	return nil
}
