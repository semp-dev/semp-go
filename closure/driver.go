package closure

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// FinalizationEffectFunc is the per-step hook the Driver invokes
// during §4.2 finalization. Each step receives the user_id of the
// account being closed; implementations carry out the side effect
// in their own subsystem and return an error on failure. A nil
// FinalizationEffectFunc is treated as a no-op for that step.
type FinalizationEffectFunc func(ctx context.Context, userID string) error

// FinalizationEffects bundles the nine §4.2 steps the Driver runs
// at finalization time. Operators wire their own subsystems into
// each hook; the library does not impose a particular
// implementation. Any nil hook is skipped silently — operators that
// do not implement a particular step (for example, an installation
// without a recovery bundle store) leave that hook nil.
//
// The hooks fire in §4.2 spec order; the Driver does not
// short-circuit on per-step errors. All non-nil hooks run on every
// finalization pass, and any errors are collected into a
// *FinalizationErrors error returned at the end.
//
// The spec's "atomically (from the perspective of subsequent
// operations)" wording is satisfied at the operator's persistence
// layer — the Driver runs the effects in deterministic order; the
// operator's database / coordination layer enforces visibility
// transactionality if required. Library-level Driver does not
// attempt cross-subsystem transactions.
type FinalizationEffects struct {
	// RevokeIdentityKey corresponds to §4.2.1: revoke the account's
	// identity key with reason `superseded` per KEY.md §8.
	RevokeIdentityKey FinalizationEffectFunc

	// RevokeEncryptionKeys corresponds to §4.2.2: revoke all active
	// encryption keys with reason `superseded`.
	RevokeEncryptionKeys FinalizationEffectFunc

	// RevokeDeviceCertificates corresponds to §4.2.3: revoke every
	// scoped device certificate per KEY.md §10.3.7 with reason
	// `delegated_role_ended`.
	RevokeDeviceCertificates FinalizationEffectFunc

	// TerminateSessions corresponds to §4.2.4: terminate all
	// active sessions belonging to any device of the account.
	TerminateSessions FinalizationEffectFunc

	// DrainOutboundQueue corresponds to §4.2.5: every non-terminal
	// queue state record for this account MUST transition to
	// `expired` per DELIVERY.md §2.6. The operator supplies the
	// user→envelopes lookup since the queue store API is
	// envelope/recipient-keyed; closure driver does not impose a
	// per-user index.
	DrainOutboundQueue FinalizationEffectFunc

	// DeleteRecoveryBundle corresponds to §4.2.6: delete the
	// recovery bundle per RECOVERY.md §4.2. A recovery.BundleStore
	// adapter is offered as DeleteRecoveryBundleFor (see below).
	DeleteRecoveryBundle FinalizationEffectFunc

	// CancelInflightMigrations corresponds to §4.2.7: mark any
	// in-flight migration records targeting this account as
	// canceled. Records originating from this account are
	// preserved as historical artifacts (the operator's
	// implementation MUST distinguish by direction).
	CancelInflightMigrations FinalizationEffectFunc

	// RetainBlockList corresponds to §4.2.8: retain the block list
	// per operator policy. The block list MUST NOT be transmitted
	// externally; the hook typically captures local state for
	// post-closure auditing.
	RetainBlockList FinalizationEffectFunc

	// CeaseServing corresponds to §4.2.9: cease serving SEMP
	// operations on behalf of the account. The operator's
	// session/auth layer MUST refuse new operations after this
	// hook returns.
	CeaseServing FinalizationEffectFunc
}

// FinalizationErrors aggregates per-step errors from a single
// finalization pass. The Driver returns this when any of the
// FinalizationEffects hooks errored; callers branch on individual
// step failures via errors.As.
type FinalizationErrors struct {
	UserID string
	// Steps maps the step name (e.g., "RevokeIdentityKey") to the
	// error returned by that hook. Successful steps do not appear.
	Steps map[string]error
}

// Error implements error.
func (e *FinalizationErrors) Error() string {
	if e == nil || len(e.Steps) == 0 {
		return "closure: no finalization errors"
	}
	names := make([]string, 0, len(e.Steps))
	for k := range e.Steps {
		names = append(names, k)
	}
	sort.Strings(names)
	parts := make([]string, 0, len(names))
	for _, n := range names {
		parts = append(parts, fmt.Sprintf("%s: %v", n, e.Steps[n]))
	}
	return fmt.Sprintf("closure: finalization errors for %s: %s", e.UserID, strings.Join(parts, "; "))
}

// Unwrap returns the first error so errors.Is can match against a
// specific step's failure when convenient. Tests typically inspect
// the Steps map directly via errors.As.
func (e *FinalizationErrors) Unwrap() error {
	if e == nil {
		return nil
	}
	for _, name := range orderedStepNames {
		if err, ok := e.Steps[name]; ok {
			return err
		}
	}
	return nil
}

// orderedStepNames is the canonical §4.2 step order used by both
// the runner and the error string.
var orderedStepNames = []string{
	"RevokeIdentityKey",
	"RevokeEncryptionKeys",
	"RevokeDeviceCertificates",
	"TerminateSessions",
	"DrainOutboundQueue",
	"DeleteRecoveryBundle",
	"CancelInflightMigrations",
	"RetainBlockList",
	"CeaseServing",
}

// Driver tracks pending closure requests and runs the §4.2 atomic
// effects when each reaches its FinalizationAt timestamp.
//
// Submit records an accepted request; Cancel removes a pending
// request (idempotent). Tick walks pending requests and finalizes
// any whose grace deadline has passed.
//
// Driver is concurrency-safe; multiple goroutines may call any
// method.
type Driver struct {
	mu      sync.Mutex
	pending map[string]*Record // keyed by user_id

	effects FinalizationEffects
	nowFn   func() time.Time
}

// DriverConfig bundles Driver inputs.
type DriverConfig struct {
	Effects FinalizationEffects
	NowFn   func() time.Time
}

// NewDriver returns a Driver with the supplied effect hooks.
// NowFn defaults to time.Now().UTC.
func NewDriver(cfg DriverConfig) *Driver {
	now := cfg.NowFn
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &Driver{
		pending: make(map[string]*Record),
		effects: cfg.Effects,
		nowFn:   now,
	}
}

// Submit records r as the active closure request for r.UserID.
// Returns ErrAlreadyPending if a request is already pending for
// the same user; the operator's submission handler enforces the
// "at most one active closure" rule per CLOSURE.md §2.4 and is
// expected to surface this error to the user.
//
// Submit does NOT verify r's signature; callers MUST run
// VerifyRecord against the issuing device's public key before
// calling.
func (d *Driver) Submit(_ context.Context, r *Record) error {
	if r == nil {
		return errors.New("closure: nil record")
	}
	if r.Step != StepRequest {
		return fmt.Errorf("closure: Submit requires step=%s, got %s", StepRequest, r.Step)
	}
	if err := r.Validate(); err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, exists := d.pending[r.UserID]; exists {
		return fmt.Errorf("%w: %s", ErrAlreadyPending, r.UserID)
	}
	cp := *r
	d.pending[r.UserID] = &cp
	return nil
}

// Cancel drops the pending request for userID. Returns (true, nil)
// if a request was pending and is now removed; (false, nil) if no
// request was pending (idempotent per §2.7.4-style semantics; a
// late cancel of a non-existent request does not surface an
// error).
//
// Per §3.2 cancellation is itself a SEMP_ACCOUNT_CLOSURE record
// with step=cancel. Callers verify that record before invoking
// Cancel here; the Driver tracks only the userID.
func (d *Driver) Cancel(_ context.Context, userID string) (bool, error) {
	if userID == "" {
		return false, errors.New("closure: cancel empty user_id")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, exists := d.pending[userID]; !exists {
		return false, nil
	}
	delete(d.pending, userID)
	return true, nil
}

// Pending returns a defensive copy of the request currently
// pending for userID, or nil if none.
func (d *Driver) Pending(userID string) *Record {
	d.mu.Lock()
	defer d.mu.Unlock()
	r, ok := d.pending[userID]
	if !ok {
		return nil
	}
	cp := *r
	return &cp
}

// PendingCount returns the number of pending requests, useful for
// operator monitoring.
func (d *Driver) PendingCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.pending)
}

// Tick processes every pending request whose FinalizationAt has
// passed. For each it runs the FinalizationEffects in §4.2 order
// and removes the request from the pending set on completion.
//
// Returns the number of users finalized and the first
// *FinalizationErrors observed (subsequent users' errors are
// surfaced via the operator's error logging; callers that need to
// observe every per-user error should pass each user through the
// driver individually).
//
// Per §4.1, finalization MUST NOT occur before the FinalizationAt
// timestamp; Tick respects this strictly.
func (d *Driver) Tick(ctx context.Context) (int, error) {
	now := d.nowFn()

	// Snapshot due requests under the lock so the run-effects loop
	// does not hold the mutex during operator-supplied calls.
	d.mu.Lock()
	type job struct {
		userID string
		record *Record
	}
	var due []job
	for uid, r := range d.pending {
		if !now.Before(r.FinalizationAt()) {
			cp := *r
			due = append(due, job{userID: uid, record: &cp})
		}
	}
	d.mu.Unlock()
	sort.Slice(due, func(i, j int) bool { return due[i].userID < due[j].userID })

	finalized := 0
	var firstErr *FinalizationErrors
	for _, j := range due {
		if err := ctx.Err(); err != nil {
			return finalized, err
		}
		errs := d.runEffects(ctx, j.userID)
		// Remove the pending entry whether or not effects succeeded
		// — the spec's intent is that finalization is irreversible
		// once the grace deadline passes. Operator-supplied effect
		// errors are surfaced via the returned *FinalizationErrors
		// and the operator's retry / escalation policy applies.
		d.mu.Lock()
		delete(d.pending, j.userID)
		d.mu.Unlock()
		finalized++
		if errs != nil && firstErr == nil {
			firstErr = errs
		}
	}
	if firstErr != nil {
		return finalized, firstErr
	}
	return finalized, nil
}

// runEffects fires the nine FinalizationEffects hooks in spec
// order. Returns a non-nil *FinalizationErrors if any hook errored.
func (d *Driver) runEffects(ctx context.Context, userID string) *FinalizationErrors {
	steps := []struct {
		name string
		fn   FinalizationEffectFunc
	}{
		{"RevokeIdentityKey", d.effects.RevokeIdentityKey},
		{"RevokeEncryptionKeys", d.effects.RevokeEncryptionKeys},
		{"RevokeDeviceCertificates", d.effects.RevokeDeviceCertificates},
		{"TerminateSessions", d.effects.TerminateSessions},
		{"DrainOutboundQueue", d.effects.DrainOutboundQueue},
		{"DeleteRecoveryBundle", d.effects.DeleteRecoveryBundle},
		{"CancelInflightMigrations", d.effects.CancelInflightMigrations},
		{"RetainBlockList", d.effects.RetainBlockList},
		{"CeaseServing", d.effects.CeaseServing},
	}
	var errMap map[string]error
	for _, step := range steps {
		if step.fn == nil {
			continue
		}
		if err := step.fn(ctx, userID); err != nil {
			if errMap == nil {
				errMap = make(map[string]error, 1)
			}
			errMap[step.name] = err
		}
	}
	if errMap == nil {
		return nil
	}
	return &FinalizationErrors{UserID: userID, Steps: errMap}
}

// ErrAlreadyPending is returned by Submit when a request is
// already pending for the user.
var ErrAlreadyPending = errors.New("closure: a closure request is already pending for this user")
