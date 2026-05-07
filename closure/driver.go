package closure

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
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
// effects when each reaches its FinalizationAt timestamp. After
// finalization the user_id is recorded in the §6.1 retention window
// for IsAccountClosed queries (used by §5 ingress and §6 reassignment
// checks).
//
// Submit records an accepted request; Cancel removes a pending
// request (idempotent). Tick walks pending requests and finalizes
// any whose grace deadline has passed.
//
// Driver is concurrency-safe; multiple goroutines may call any
// method. Persistence delegates to a Store; the default in-memory
// Store covers tests and demos, production deployments plug in a
// durable backend.
type Driver struct {
	store   Store
	effects FinalizationEffects
	nowFn   func() time.Time

	// retainFinalizedFor is the §6.1 retention window. Defaults to
	// RecommendedRetention; sub-floor values are clamped up by
	// PruneFinalized when called.
	retainFinalizedFor time.Duration
}

// DriverConfig bundles Driver inputs.
type DriverConfig struct {
	Effects FinalizationEffects

	// Store persists pending and finalized state. Optional;
	// defaults to NewInMemoryStore() when nil.
	Store Store

	// RetainFinalizedFor is the §6.1 retention window applied by
	// IsAccountClosed and PruneFinalized. Optional; defaults to
	// RecommendedRetention (365 days). Sub-floor values clamp to
	// MinRetention (180 days) at use time.
	RetainFinalizedFor time.Duration

	NowFn func() time.Time
}

// NewDriver returns a Driver with the supplied configuration.
// NowFn defaults to time.Now().UTC; Store defaults to a fresh
// in-memory store; RetainFinalizedFor defaults to RecommendedRetention.
func NewDriver(cfg DriverConfig) *Driver {
	now := cfg.NowFn
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	store := cfg.Store
	if store == nil {
		store = NewInMemoryStore()
	}
	retainFor := cfg.RetainFinalizedFor
	if retainFor <= 0 {
		retainFor = RecommendedRetention
	}
	return &Driver{
		store:              store,
		effects:            cfg.Effects,
		nowFn:              now,
		retainFinalizedFor: retainFor,
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
func (d *Driver) Submit(ctx context.Context, r *Record) error {
	if r == nil {
		return errors.New("closure: nil record")
	}
	if r.Step != StepRequest {
		return fmt.Errorf("closure: Submit requires step=%s, got %s", StepRequest, r.Step)
	}
	if err := r.Validate(); err != nil {
		return err
	}
	return d.store.PutPending(ctx, r)
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
func (d *Driver) Cancel(ctx context.Context, userID string) (bool, error) {
	if userID == "" {
		return false, errors.New("closure: cancel empty user_id")
	}
	existing, err := d.store.GetPending(ctx, userID)
	if err != nil {
		return false, fmt.Errorf("closure: cancel get: %w", err)
	}
	if existing == nil {
		return false, nil
	}
	if err := d.store.DeletePending(ctx, userID); err != nil {
		return false, fmt.Errorf("closure: cancel delete: %w", err)
	}
	return true, nil
}

// Pending returns a defensive copy of the request currently
// pending for userID, or nil if none. Reads through the Store; a
// transient Store error returns nil and is silently swallowed —
// callers that need the error path use the context-aware
// PendingCtx variant.
func (d *Driver) Pending(userID string) *Record {
	r, _ := d.store.GetPending(context.Background(), userID)
	return r
}

// PendingCtx is the ctx-aware variant of Pending; returns the
// Store's error directly.
func (d *Driver) PendingCtx(ctx context.Context, userID string) (*Record, error) {
	return d.store.GetPending(ctx, userID)
}

// Tick processes every pending request whose FinalizationAt has
// passed. For each it runs the FinalizationEffects in §4.2 order,
// records the finalization timestamp in the §6.1 retention store,
// and removes the request from the pending set on completion.
//
// Returns the number of users finalized and the first
// *FinalizationErrors observed (subsequent users' errors are
// surfaced via the operator's error logging; callers that need to
// observe every per-user error should pass each user through the
// driver individually).
//
// Per §4.1, finalization MUST NOT occur before the FinalizationAt
// timestamp; Tick respects this strictly. Per §4.2 finalization is
// irreversible once the grace deadline passes — the pending entry
// is removed and the finalized timestamp recorded regardless of
// per-step effect errors.
func (d *Driver) Tick(ctx context.Context) (int, error) {
	now := d.nowFn()
	due, err := d.store.DuePending(ctx, now)
	if err != nil {
		return 0, fmt.Errorf("closure: due pending: %w", err)
	}

	finalized := 0
	var firstErr *FinalizationErrors
	for _, r := range due {
		if err := ctx.Err(); err != nil {
			return finalized, err
		}
		errs := d.runEffects(ctx, r.UserID)
		// §4.2: finalization is irreversible once the grace
		// deadline passes. Record the finalized timestamp + delete
		// the pending entry whether or not effects succeeded;
		// operator's retry / escalation handles partial-failure
		// remediation via the returned *FinalizationErrors.
		if perr := d.store.PutFinalized(ctx, r.UserID, now); perr != nil && firstErr == nil {
			// Capture the persistence failure as a step error so the
			// operator sees it.
			if errs == nil {
				errs = &FinalizationErrors{UserID: r.UserID, Steps: map[string]error{}}
			}
			errs.Steps["PersistFinalized"] = perr
		}
		if derr := d.store.DeletePending(ctx, r.UserID); derr != nil && errs == nil {
			errs = &FinalizationErrors{
				UserID: r.UserID,
				Steps:  map[string]error{"DeletePending": derr},
			}
		}
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

// IsAccountClosed reports whether userID is in the §6.1 post-
// finalization retention window at now. Returns (false, nil) when
// no finalization is recorded for userID, or when the recorded
// timestamp is older than the configured retention window.
//
// Used by §5 ingress (envelope arriving for a closed account
// returns policy_forbidden during the retention window) and §6
// reassignment (the local-part MUST NOT be reassigned during the
// window).
func (d *Driver) IsAccountClosed(ctx context.Context, userID string, now time.Time) (bool, error) {
	if userID == "" {
		return false, errors.New("closure: empty user_id")
	}
	finalizedAt, found, err := d.store.GetFinalized(ctx, userID)
	if err != nil {
		return false, fmt.Errorf("closure: get finalized: %w", err)
	}
	if !found {
		return false, nil
	}
	retainFor := d.retainFinalizedFor
	if retainFor < MinRetention {
		retainFor = MinRetention
	}
	return finalizedAt.Add(retainFor).After(now), nil
}

// PruneFinalized evicts finalized entries older than the
// configured retention window. Operators call this on a janitor
// cadence to bound the finalized-state store. retainFor is clamped
// to MinRetention internally.
func (d *Driver) PruneFinalized(ctx context.Context) (int, error) {
	return d.store.PruneFinalized(ctx, d.retainFinalizedFor)
}

// PendingCount returns the number of pending closure requests.
// Useful for operator monitoring. Reads through the Store.
func (d *Driver) PendingCount() int {
	n, _ := d.store.CountPending(context.Background())
	return n
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
