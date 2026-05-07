package closure

import (
	"context"
	"time"

	semp "semp.dev/semp-go"
	"semp.dev/semp-go/brief"
)

// RecipientPolicyFunc is the per-recipient gate signature the
// closure driver returns from RecipientPolicy. It matches
// delivery.RecipientPolicyFunc so callers can plug it directly
// into delivery.Pipeline.RecipientPolicy.
type recipientPolicyFunc func(ctx context.Context, recipient brief.Address) (semp.Acknowledgment, semp.ReasonCode, string)

// RecipientPolicy returns a closure-aware per-recipient policy
// adapter for delivery.Pipeline. The returned function rejects
// envelopes addressed to closed accounts with
// `policy_forbidden` per CLOSURE.md §5.1, preserving existence
// indistinguishability per DESIGN.md §2.7 and DELIVERY.md §6.4
// (the `policy_forbidden` reason is the same one a non-existent
// address receives).
//
// Per CLOSURE.md §5.1 the home server MAY alternatively respond
// with a `silent` acknowledgment (DELIVERY.md §1.3); to use that
// posture pass UseSilentAcknowledgment in the policy options.
//
// The retention window is the Driver's configured
// RetainFinalizedFor. Outside the window the policy returns
// ("", "", "") so the envelope falls through to the standard
// block-list / inbox path (the local-part may have been
// reassigned per §6.2).
type RecipientPolicyOptions struct {
	// UseSilentAcknowledgment, when true, returns AckSilent
	// instead of AckRejected for closed accounts. Both preserve
	// existence indistinguishability per CLOSURE.md §5.1; the
	// choice is operator policy.
	UseSilentAcknowledgment bool

	// NowFn supplies the wall-clock for retention-window
	// comparisons. Defaults to time.Now().UTC.
	NowFn func() time.Time
}

// RecipientPolicy returns the adapter described in
// RecipientPolicyOptions. The returned function has signature
// compatible with delivery.RecipientPolicyFunc — operators wire it
// as `pipeline.RecipientPolicy = closureDriver.RecipientPolicy(opts)`.
func (d *Driver) RecipientPolicy(opts RecipientPolicyOptions) recipientPolicyFunc {
	now := opts.NowFn
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return func(ctx context.Context, recipient brief.Address) (semp.Acknowledgment, semp.ReasonCode, string) {
		closed, err := d.IsAccountClosed(ctx, string(recipient), now())
		if err != nil {
			// Fail open per CLOSURE.md §5.1: a transient store
			// error MUST NOT silently drop deliveries to active
			// accounts. Operators that want fail-closed wire their
			// own policy.
			return "", "", ""
		}
		if !closed {
			return "", "", ""
		}
		if opts.UseSilentAcknowledgment {
			return semp.AckSilent, "", ""
		}
		return semp.AckRejected, semp.ReasonPolicyForbidden, "recipient policy"
	}
}
