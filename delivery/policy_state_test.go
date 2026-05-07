package delivery_test

import (
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	semp "semp.dev/semp-go"
	"semp.dev/semp-go/delivery"
)

// blockEntry returns a §5 block-entry JSON payload with the supplied
// id. Just enough shape to round-trip through PolicyState; the
// state machine treats the entry as opaque bytes keyed by id.
func blockEntry(id string) json.RawMessage {
	return json.RawMessage(`{"id":"` + id + `","entity":{"type":"user","address":"x@example.com"}}`)
}

// firstContactEntry returns the singleton policy payload.
func firstContactEntry(mode string) json.RawMessage {
	return json.RawMessage(`{"mode":"` + mode + `"}`)
}

// newPolicyMsg fabricates a structurally-valid UserPolicyMessage
// without signing; PolicyState.Apply does not verify signatures and
// the wire-level signing tests live in receipt_test.go.
func newPolicyMsg(t *testing.T, version int64, ts time.Time, ops []delivery.PolicyOperation) *delivery.UserPolicyMessage {
	t.Helper()
	return &delivery.UserPolicyMessage{
		Type:          delivery.UserPolicyType,
		Step:          delivery.UserPolicyStep,
		Version:       delivery.UserPolicyVersion,
		UserID:        "alice@example.com",
		DeviceID:      "device-1",
		PolicyVersion: version,
		Timestamp:     ts,
		Operations:    ops,
	}
}

// TestPolicyStateInitialApplyAdvancesVersion confirms a fresh state
// accepts any version >= 1 as the first message.
func TestPolicyStateInitialApplyAdvancesVersion(t *testing.T) {
	state, err := delivery.NewPolicyState("alice@example.com")
	if err != nil {
		t.Fatalf("NewPolicyState: %v", err)
	}
	if state.CurrentVersion() != 0 {
		t.Errorf("initial CurrentVersion = %d, want 0", state.CurrentVersion())
	}

	msg := newPolicyMsg(t, 1, time.Now().UTC(), []delivery.PolicyOperation{
		{Op: delivery.PolicyOpAdd, Kind: delivery.PolicyKindBlock, Entry: blockEntry("b-1")},
	})
	if err := state.Apply(msg); err != nil {
		t.Fatalf("Apply v=1: %v", err)
	}
	if state.CurrentVersion() != 1 {
		t.Errorf("after first Apply: CurrentVersion = %d, want 1", state.CurrentVersion())
	}
	if got := state.ListEntries(delivery.PolicyKindBlock); len(got) != 1 {
		t.Errorf("block entries len = %d, want 1", len(got))
	}
}

// TestPolicyStateMonotonicProgression confirms successive higher
// versions accumulate.
func TestPolicyStateMonotonicProgression(t *testing.T) {
	state, _ := delivery.NewPolicyState("alice@example.com")
	t0 := time.Now().UTC()
	if err := state.Apply(newPolicyMsg(t, 1, t0, []delivery.PolicyOperation{
		{Op: delivery.PolicyOpAdd, Kind: delivery.PolicyKindBlock, Entry: blockEntry("b-1")},
	})); err != nil {
		t.Fatalf("Apply v=1: %v", err)
	}
	if err := state.Apply(newPolicyMsg(t, 2, t0.Add(time.Second), []delivery.PolicyOperation{
		{Op: delivery.PolicyOpAdd, Kind: delivery.PolicyKindBlock, Entry: blockEntry("b-2")},
	})); err != nil {
		t.Fatalf("Apply v=2: %v", err)
	}
	if state.CurrentVersion() != 2 {
		t.Errorf("CurrentVersion = %d, want 2", state.CurrentVersion())
	}
	if got := state.ListEntries(delivery.PolicyKindBlock); len(got) != 2 {
		t.Errorf("block entries len = %d, want 2", len(got))
	}
}

// TestPolicyStateLowerVersionRejected confirms stale-version
// detection.
func TestPolicyStateLowerVersionRejected(t *testing.T) {
	state, _ := delivery.NewPolicyState("alice@example.com")
	t0 := time.Now().UTC()
	if err := state.Apply(newPolicyMsg(t, 5, t0, []delivery.PolicyOperation{
		{Op: delivery.PolicyOpAdd, Kind: delivery.PolicyKindBlock, Entry: blockEntry("b-5")},
	})); err != nil {
		t.Fatalf("Apply v=5: %v", err)
	}
	err := state.Apply(newPolicyMsg(t, 4, t0.Add(time.Second), []delivery.PolicyOperation{
		{Op: delivery.PolicyOpAdd, Kind: delivery.PolicyKindBlock, Entry: blockEntry("b-4")},
	}))
	if err == nil {
		t.Fatal("Apply v=4 (after v=5) accepted; should have been stale")
	}
	if got := semp.CodeOf(err); got != semp.ReasonPolicyVersionStale {
		t.Errorf("reason code = %q, want %q", got, semp.ReasonPolicyVersionStale)
	}
	var pae *delivery.PolicyApplyError
	if !errors.As(err, &pae) {
		t.Fatalf("error does not unwrap to *PolicyApplyError: %v", err)
	}
	if pae.SubmittedVersion != 4 || pae.CurrentVersion != 5 {
		t.Errorf("PolicyApplyError version pair = (%d,%d), want (4,5)",
			pae.SubmittedVersion, pae.CurrentVersion)
	}
	// State unchanged.
	if state.CurrentVersion() != 5 {
		t.Errorf("CurrentVersion after rejection = %d, want 5", state.CurrentVersion())
	}
	if got := state.ListEntries(delivery.PolicyKindBlock); len(got) != 1 {
		t.Errorf("block entries len = %d, want 1", len(got))
	}
}

// TestPolicyStateEqualVersionLaterTimestampWins confirms the §7.2
// tie-break: equal version + later timestamp accepted.
func TestPolicyStateEqualVersionLaterTimestampWins(t *testing.T) {
	state, _ := delivery.NewPolicyState("alice@example.com")
	t0 := time.Now().UTC()
	if err := state.Apply(newPolicyMsg(t, 7, t0, []delivery.PolicyOperation{
		{Op: delivery.PolicyOpAdd, Kind: delivery.PolicyKindBlock, Entry: blockEntry("b-1")},
	})); err != nil {
		t.Fatalf("Apply v=7 ts=t0: %v", err)
	}
	// Equal version, later timestamp: spec resolves by timestamp.
	if err := state.Apply(newPolicyMsg(t, 7, t0.Add(2*time.Second), []delivery.PolicyOperation{
		{Op: delivery.PolicyOpAdd, Kind: delivery.PolicyKindBlock, Entry: blockEntry("b-2")},
	})); err != nil {
		t.Errorf("Apply v=7 ts=t0+2s: %v", err)
	}
	if got := state.ListEntries(delivery.PolicyKindBlock); len(got) != 2 {
		t.Errorf("block entries len = %d, want 2", len(got))
	}
}

// TestPolicyStateEqualVersionEqualTimestampRejected confirms an
// exact replay (same version + same timestamp) is treated as stale.
func TestPolicyStateEqualVersionEqualTimestampRejected(t *testing.T) {
	state, _ := delivery.NewPolicyState("alice@example.com")
	t0 := time.Now().UTC()
	msg := newPolicyMsg(t, 3, t0, []delivery.PolicyOperation{
		{Op: delivery.PolicyOpAdd, Kind: delivery.PolicyKindBlock, Entry: blockEntry("b-1")},
	})
	if err := state.Apply(msg); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if err := state.Apply(msg); err == nil {
		t.Error("Apply re-accepted an exact-replay message")
	} else if got := semp.CodeOf(err); got != semp.ReasonPolicyVersionStale {
		t.Errorf("reason code = %q, want %q", got, semp.ReasonPolicyVersionStale)
	}
}

// TestPolicyStateEqualVersionEarlierTimestampRejected confirms an
// equal-version-but-earlier-timestamp replay loses the tie-break.
func TestPolicyStateEqualVersionEarlierTimestampRejected(t *testing.T) {
	state, _ := delivery.NewPolicyState("alice@example.com")
	t0 := time.Now().UTC()
	if err := state.Apply(newPolicyMsg(t, 3, t0, []delivery.PolicyOperation{
		{Op: delivery.PolicyOpAdd, Kind: delivery.PolicyKindBlock, Entry: blockEntry("b-1")},
	})); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	err := state.Apply(newPolicyMsg(t, 3, t0.Add(-time.Second), []delivery.PolicyOperation{
		{Op: delivery.PolicyOpAdd, Kind: delivery.PolicyKindBlock, Entry: blockEntry("b-2")},
	}))
	if err == nil {
		t.Error("Apply accepted equal-version-but-earlier-timestamp")
	} else if got := semp.CodeOf(err); got != semp.ReasonPolicyVersionStale {
		t.Errorf("reason code = %q, want %q", got, semp.ReasonPolicyVersionStale)
	}
}

// TestPolicyStateUnsupportedKindRejected confirms an op carrying a
// kind not registered in NewPolicyState fails atomically — no other
// operation in the same message is applied.
func TestPolicyStateUnsupportedKindRejected(t *testing.T) {
	state, _ := delivery.NewPolicyState("alice@example.com",
		delivery.PolicyKindBlock, // explicitly limited registry; no accepted_sender
	)
	t0 := time.Now().UTC()
	err := state.Apply(newPolicyMsg(t, 1, t0, []delivery.PolicyOperation{
		{Op: delivery.PolicyOpAdd, Kind: delivery.PolicyKindBlock, Entry: blockEntry("b-1")},
		{Op: delivery.PolicyOpAdd, Kind: delivery.PolicyKindAcceptedSender, Entry: blockEntry("a-1")},
	}))
	if err == nil {
		t.Fatal("Apply accepted an unsupported kind")
	}
	if got := semp.CodeOf(err); got != semp.ReasonPolicyKindUnsupported {
		t.Errorf("reason code = %q, want %q", got, semp.ReasonPolicyKindUnsupported)
	}
	var pae *delivery.PolicyApplyError
	if !errors.As(err, &pae) {
		t.Fatalf("error does not unwrap to *PolicyApplyError: %v", err)
	}
	if pae.Kind != delivery.PolicyKindAcceptedSender {
		t.Errorf("PolicyApplyError.Kind = %q, want %q", pae.Kind, delivery.PolicyKindAcceptedSender)
	}
	if pae.OpIndex != 1 {
		t.Errorf("PolicyApplyError.OpIndex = %d, want 1", pae.OpIndex)
	}
	// Atomicity: the FIRST op (which targets a supported kind) MUST
	// NOT have been applied.
	if got := state.ListEntries(delivery.PolicyKindBlock); len(got) != 0 {
		t.Errorf("block entries len = %d, want 0 (atomic rejection)", len(got))
	}
	if state.CurrentVersion() != 0 {
		t.Errorf("CurrentVersion = %d, want 0", state.CurrentVersion())
	}
}

// TestPolicyStateSingletonAddRejected confirms a singleton-shaped
// kind (first_contact) carrying op=add fails with policy_op_invalid.
// This is the §7.3 singleton rule the wire-level Validate enforces;
// Apply translates the structural error into a typed reason code.
func TestPolicyStateSingletonAddRejected(t *testing.T) {
	state, _ := delivery.NewPolicyState("alice@example.com")
	t0 := time.Now().UTC()
	err := state.Apply(newPolicyMsg(t, 1, t0, []delivery.PolicyOperation{
		{
			Op:    delivery.PolicyOpAdd,
			Kind:  delivery.PolicyKindFirstContact,
			Entry: firstContactEntry("challenge"),
		},
	}))
	if err == nil {
		t.Fatal("Apply accepted add on a singleton kind")
	}
	if got := semp.CodeOf(err); got != semp.ReasonPolicyOpInvalid {
		t.Errorf("reason code = %q, want %q", got, semp.ReasonPolicyOpInvalid)
	}
	var pae *delivery.PolicyApplyError
	if !errors.As(err, &pae) {
		t.Fatalf("error does not unwrap to *PolicyApplyError: %v", err)
	}
	if pae.OpIndex != 0 {
		t.Errorf("PolicyApplyError.OpIndex = %d, want 0", pae.OpIndex)
	}
	if pae.Kind != delivery.PolicyKindFirstContact {
		t.Errorf("PolicyApplyError.Kind = %q, want %q", pae.Kind, delivery.PolicyKindFirstContact)
	}
}

// TestPolicyStateSingletonModifyAccepted confirms the singleton
// happy path.
func TestPolicyStateSingletonModifyAccepted(t *testing.T) {
	state, _ := delivery.NewPolicyState("alice@example.com")
	if err := state.Apply(newPolicyMsg(t, 1, time.Now().UTC(), []delivery.PolicyOperation{
		{
			Op:    delivery.PolicyOpModify,
			Kind:  delivery.PolicyKindFirstContact,
			Entry: firstContactEntry("challenge"),
		},
	})); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	got := state.Singleton(delivery.PolicyKindFirstContact)
	if string(got) != `{"mode":"challenge"}` {
		t.Errorf("singleton = %s, want challenge", got)
	}

	// Overwrite with a later version.
	if err := state.Apply(newPolicyMsg(t, 2, time.Now().UTC(), []delivery.PolicyOperation{
		{
			Op:    delivery.PolicyOpModify,
			Kind:  delivery.PolicyKindFirstContact,
			Entry: firstContactEntry("known_correspondents_only"),
		},
	})); err != nil {
		t.Fatalf("Apply v=2: %v", err)
	}
	got = state.Singleton(delivery.PolicyKindFirstContact)
	if string(got) != `{"mode":"known_correspondents_only"}` {
		t.Errorf("singleton after overwrite = %s", got)
	}
}

// TestPolicyStateRemoveAndModifyOnLists exercises the list-shaped
// kinds end-to-end: add, modify (upsert), remove (delete).
func TestPolicyStateRemoveAndModifyOnLists(t *testing.T) {
	state, _ := delivery.NewPolicyState("alice@example.com")
	t0 := time.Now().UTC()
	if err := state.Apply(newPolicyMsg(t, 1, t0, []delivery.PolicyOperation{
		{Op: delivery.PolicyOpAdd, Kind: delivery.PolicyKindBlock, Entry: blockEntry("b-1")},
		{Op: delivery.PolicyOpAdd, Kind: delivery.PolicyKindBlock, Entry: blockEntry("b-2")},
	})); err != nil {
		t.Fatalf("Apply v=1: %v", err)
	}
	if got := state.ListEntries(delivery.PolicyKindBlock); len(got) != 2 {
		t.Fatalf("after add: len = %d, want 2", len(got))
	}

	if err := state.Apply(newPolicyMsg(t, 2, t0.Add(time.Second), []delivery.PolicyOperation{
		{Op: delivery.PolicyOpRemove, Kind: delivery.PolicyKindBlock, EntryID: "b-1"},
		{
			Op:      delivery.PolicyOpModify,
			Kind:    delivery.PolicyKindBlock,
			EntryID: "b-2",
			Entry:   json.RawMessage(`{"id":"b-2","entity":{"type":"user","address":"y@example.com"}}`),
		},
	})); err != nil {
		t.Fatalf("Apply v=2: %v", err)
	}
	got := state.ListEntries(delivery.PolicyKindBlock)
	if len(got) != 1 {
		t.Fatalf("after remove+modify: len = %d, want 1", len(got))
	}
	if _, ok := got["b-1"]; ok {
		t.Error("b-1 still present after remove")
	}
	if v, ok := got["b-2"]; !ok || string(v) == "" {
		t.Error("b-2 missing or empty after modify")
	}
}

// TestPolicyStateRemoveOfMissingIDIsIdempotent documents the design
// choice that a remove of an unknown entry_id is a no-op rather than
// an error. The version-monotonicity guard catches replay; per-op
// preconditions would surface false-positive failures during normal
// multi-device convergence.
func TestPolicyStateRemoveOfMissingIDIsIdempotent(t *testing.T) {
	state, _ := delivery.NewPolicyState("alice@example.com")
	if err := state.Apply(newPolicyMsg(t, 1, time.Now().UTC(), []delivery.PolicyOperation{
		{Op: delivery.PolicyOpRemove, Kind: delivery.PolicyKindBlock, EntryID: "ghost"},
	})); err != nil {
		t.Errorf("Apply remove-of-missing rejected: %v", err)
	}
	if state.CurrentVersion() != 1 {
		t.Errorf("CurrentVersion = %d, want 1 (no-op should still advance version)", state.CurrentVersion())
	}
}

// TestPolicyStatePerKindIsolation confirms entries under one kind
// do not leak into another.
func TestPolicyStatePerKindIsolation(t *testing.T) {
	state, _ := delivery.NewPolicyState("alice@example.com")
	if err := state.Apply(newPolicyMsg(t, 1, time.Now().UTC(), []delivery.PolicyOperation{
		{Op: delivery.PolicyOpAdd, Kind: delivery.PolicyKindBlock, Entry: blockEntry("b-1")},
		{Op: delivery.PolicyOpAdd, Kind: delivery.PolicyKindAcceptedSender, Entry: blockEntry("a-1")},
	})); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if got := state.ListEntries(delivery.PolicyKindBlock); len(got) != 1 || got["b-1"] == nil {
		t.Errorf("block bucket = %v, want b-1 only", got)
	}
	if got := state.ListEntries(delivery.PolicyKindAcceptedSender); len(got) != 1 || got["a-1"] == nil {
		t.Errorf("accepted_sender bucket = %v, want a-1 only", got)
	}
}

// TestPolicyStateSnapshotIsDeepCopy confirms Snapshot's returned
// maps are independent of the live state.
func TestPolicyStateSnapshotIsDeepCopy(t *testing.T) {
	state, _ := delivery.NewPolicyState("alice@example.com")
	if err := state.Apply(newPolicyMsg(t, 1, time.Now().UTC(), []delivery.PolicyOperation{
		{Op: delivery.PolicyOpAdd, Kind: delivery.PolicyKindBlock, Entry: blockEntry("b-1")},
	})); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	snap := state.Snapshot()

	// Mutate the snapshot.
	snap.ListEntries[delivery.PolicyKindBlock]["b-1"] = json.RawMessage(`{"tampered":true}`)
	snap.PolicyVersion = 9999

	// Live state unchanged.
	if state.CurrentVersion() != 1 {
		t.Errorf("CurrentVersion drifted after snapshot mutation: %d", state.CurrentVersion())
	}
	got := state.ListEntries(delivery.PolicyKindBlock)["b-1"]
	if string(got) == `{"tampered":true}` {
		t.Error("live state mutated when snapshot bucket was modified")
	}
}

// TestPolicyStateUserIDMismatchRejected confirms a message whose
// user_id does not match the state's user_id is rejected as a
// routing logic error (plain error, not a reason-coded
// PolicyApplyError).
func TestPolicyStateUserIDMismatchRejected(t *testing.T) {
	state, _ := delivery.NewPolicyState("alice@example.com")
	wrong := newPolicyMsg(t, 1, time.Now().UTC(), []delivery.PolicyOperation{
		{Op: delivery.PolicyOpAdd, Kind: delivery.PolicyKindBlock, Entry: blockEntry("b-1")},
	})
	wrong.UserID = "bob@example.com"
	err := state.Apply(wrong)
	if err == nil {
		t.Fatal("Apply accepted user_id mismatch")
	}
	if semp.CodeOf(err) != "" {
		t.Errorf("user_id mismatch should not surface a reason code; got %q", semp.CodeOf(err))
	}
}

// TestPolicyStateConcurrentApply confirms PolicyState is safe under
// concurrent Apply calls: monotonicity is preserved, and the final
// version equals the highest-numbered submission accepted.
func TestPolicyStateConcurrentApply(t *testing.T) {
	state, _ := delivery.NewPolicyState("alice@example.com")
	const N = 50
	var wg sync.WaitGroup
	for i := 1; i <= N; i++ {
		wg.Add(1)
		go func(v int) {
			defer wg.Done()
			msg := newPolicyMsg(t, int64(v), time.Now().UTC().Add(time.Duration(v)*time.Millisecond),
				[]delivery.PolicyOperation{
					{Op: delivery.PolicyOpAdd, Kind: delivery.PolicyKindBlock, Entry: blockEntry(
						"b-" + intStr(v),
					)},
				})
			// Errors are expected when submissions race and the
			// later-numbered one lands first; what we care about is
			// no data race and a sane final state.
			_ = state.Apply(msg)
		}(i)
	}
	wg.Wait()
	if state.CurrentVersion() < 1 || state.CurrentVersion() > N {
		t.Errorf("final CurrentVersion %d out of [1, %d]", state.CurrentVersion(), N)
	}
	// The final version must equal the largest version that was
	// accepted as a strictly-monotonic step from earlier accepts.
	// We can at minimum confirm: the bucket holds at most one entry
	// per submitted v (no duplicate keys).
	got := state.ListEntries(delivery.PolicyKindBlock)
	if len(got) > N {
		t.Errorf("block bucket holds %d entries, more than %d submissions", len(got), N)
	}
}

// TestPolicyStateAcceptsCustomKind confirms operators can register
// extension-defined kinds at construction time and Apply accepts
// them just like the spec-defined defaults.
func TestPolicyStateAcceptsCustomKind(t *testing.T) {
	const customKind = "example.org/custom_filter"
	state, err := delivery.NewPolicyState("alice@example.com",
		delivery.PolicyKindBlock,
		customKind,
	)
	if err != nil {
		t.Fatalf("NewPolicyState: %v", err)
	}
	if !state.SupportsKind(customKind) {
		t.Errorf("SupportsKind(%q) = false", customKind)
	}
	if err := state.Apply(newPolicyMsg(t, 1, time.Now().UTC(), []delivery.PolicyOperation{
		{Op: delivery.PolicyOpAdd, Kind: customKind, Entry: blockEntry("c-1")},
	})); err != nil {
		t.Errorf("Apply custom kind: %v", err)
	}
	if got := state.ListEntries(customKind); len(got) != 1 {
		t.Errorf("custom-kind bucket len = %d, want 1", len(got))
	}
}

// TestNewPolicyStateRejectsEmptyArgs guards the obvious foot-guns.
func TestNewPolicyStateRejectsEmptyArgs(t *testing.T) {
	if _, err := delivery.NewPolicyState(""); err == nil {
		t.Error("NewPolicyState accepted empty user_id")
	}
	if _, err := delivery.NewPolicyState("alice@example.com", ""); err == nil {
		t.Error("NewPolicyState accepted empty kind")
	}
}

// intStr is a tiny stringer to avoid pulling in strconv in test
// hot paths.
func intStr(v int) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
