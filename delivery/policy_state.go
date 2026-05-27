package delivery

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	semp "github.com/semp-dev/semp-go"
)

// PolicyApplyError carries the structured details of a policy
// rejection. Returned wrapped inside a *semp.Error so callers can
// match either by ReasonCode (semp.CodeOf) or by inspecting the
// per-reason fields here via errors.As.
//
// Field meaning depends on Code:
//
//   - ReasonPolicyKindUnsupported: Kind names the offending kind;
//     OpIndex is the 0-based index of the operation that carried it.
//   - ReasonPolicyOpInvalid: OpIndex is the offending operation;
//     Detail describes the specific violation.
//   - ReasonPolicyVersionStale: SubmittedVersion is what the client
//     sent; CurrentVersion is the server's current value.
type PolicyApplyError struct {
	Code             semp.ReasonCode
	Kind             string
	OpIndex          int
	SubmittedVersion int64
	CurrentVersion   int64
	Detail           string
}

// Error implements error.
func (e *PolicyApplyError) Error() string {
	switch e.Code {
	case semp.ReasonPolicyKindUnsupported:
		return fmt.Sprintf("delivery: policy operation[%d] kind %q is not supported", e.OpIndex, e.Kind)
	case semp.ReasonPolicyOpInvalid:
		if e.Detail != "" {
			return fmt.Sprintf("delivery: policy operation[%d] is invalid: %s", e.OpIndex, e.Detail)
		}
		return fmt.Sprintf("delivery: policy operation[%d] is invalid", e.OpIndex)
	case semp.ReasonPolicyVersionStale:
		return fmt.Sprintf("delivery: submitted policy_version %d is not greater than current %d",
			e.SubmittedVersion, e.CurrentVersion)
	default:
		return fmt.Sprintf("delivery: policy apply error: %s", e.Code)
	}
}

// asSEMPError wraps e in a *semp.Error so callers can use the
// codebase-wide errors.As(err, &semp.Error{}) pattern.
func (e *PolicyApplyError) asSEMPError() *semp.Error {
	return semp.WrapErr(e.Code, e, "user-policy update rejected")
}

// DefaultPolicyKinds returns the rule kinds DELIVERY.md §7.3 defines
// for v1.0.0: semp.dev/block, semp.dev/accepted_sender,
// semp.dev/first_contact. Operators with extension-defined kinds
// pass them as the additional NewPolicyState arguments.
func DefaultPolicyKinds() []string {
	return []string{
		PolicyKindBlock,
		PolicyKindAcceptedSender,
		PolicyKindFirstContact,
	}
}

// PolicyState is the per-user authoritative policy view that a home
// server maintains per DELIVERY.md §7.2. Apply takes a verified
// SEMP_USER_POLICY message and either applies every operation
// atomically (advancing policy_version) or rejects the whole message
// without mutating state.
//
// PolicyState is concurrency-safe; multiple goroutines may call
// Apply or any of the read methods.
//
// PolicyState does NOT enforce DELIVERY.md §7.5 encrypted-at-rest
// storage. The structure holds in-memory state in plain bytes; a
// production server wraps the state behind a persistence layer that
// performs the encryption when state is written to disk.
type PolicyState struct {
	mu sync.Mutex

	userID         string
	supportedKinds map[string]struct{}

	policyVersion int64
	lastTimestamp time.Time

	listEntries map[string]map[string]json.RawMessage
	singletons  map[string]json.RawMessage
}

// NewPolicyState returns a state for userID supporting the passed
// rule kinds. With no kinds passed, DefaultPolicyKinds() is used.
//
// Operators register extension kinds here so the home server accepts
// them; an unregistered kind triggers ReasonPolicyKindUnsupported on
// Apply per §7.2.
func NewPolicyState(userID string, kinds ...string) (*PolicyState, error) {
	if userID == "" {
		return nil, errors.New("delivery: policy state requires user_id")
	}
	if len(kinds) == 0 {
		kinds = DefaultPolicyKinds()
	}
	s := &PolicyState{
		userID:         userID,
		supportedKinds: make(map[string]struct{}, len(kinds)),
		listEntries:    make(map[string]map[string]json.RawMessage),
		singletons:     make(map[string]json.RawMessage),
	}
	for _, k := range kinds {
		if k == "" {
			return nil, errors.New("delivery: policy state cannot register empty kind")
		}
		s.supportedKinds[k] = struct{}{}
	}
	return s, nil
}

// UserID returns the user_id this state belongs to.
func (s *PolicyState) UserID() string { return s.userID }

// CurrentVersion returns the current policy_version per §7.2. Zero
// before any message has been applied; advances monotonically.
func (s *PolicyState) CurrentVersion() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.policyVersion
}

// LastTimestamp returns the timestamp of the most recently applied
// message. Zero before any message has been applied.
func (s *PolicyState) LastTimestamp() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastTimestamp
}

// SupportsKind reports whether kind is registered for this state.
func (s *PolicyState) SupportsKind(kind string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.supportedKinds[kind]
	return ok
}

// SupportedKinds returns the registered kinds in lexical order. The
// returned slice is owned by the caller.
func (s *PolicyState) SupportedKinds() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.supportedKinds))
	for k := range s.supportedKinds {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Apply applies m atomically per DELIVERY.md §7.2. On success the
// state's policy_version advances to m.PolicyVersion and the
// per-kind stores reflect every operation. On any per-message
// failure the state is unchanged and the returned error wraps a
// *PolicyApplyError carrying the structured rejection details.
//
// Apply does NOT verify the signature on m; callers MUST run
// VerifyUserPolicyMessage against the originating device's public
// key before calling Apply. Apply does run m.Validate() as a
// belt-and-suspenders check; structural failures from Validate
// surface as plain wrapped errors, while the three §5 ERRORS.md
// reason codes (kind_unsupported, op_invalid, version_stale) come
// back as *semp.Error wrapping *PolicyApplyError.
//
// User_id is checked against the state's user_id; a mismatch is a
// routing logic error and surfaces as a plain error rather than a
// reason code.
func (s *PolicyState) Apply(m *UserPolicyMessage) error {
	if m == nil {
		return errors.New("delivery: nil user policy message")
	}
	// Validate is the structural gate (type discriminators, op-kind
	// rules, required-field presence). The §7.3 op-kind rules are
	// where policy_op_invalid lives, so we capture Validate's per-op
	// error and translate.
	if err := m.Validate(); err != nil {
		// Translate the specific §7.3 violations into typed
		// PolicyApplyError so the home server returns the right
		// reason code; structural failures fall through.
		if idx, kind, detail, ok := classifyOpInvalid(err, m); ok {
			pae := &PolicyApplyError{
				Code:    semp.ReasonPolicyOpInvalid,
				Kind:    kind,
				OpIndex: idx,
				Detail:  detail,
			}
			return pae.asSEMPError()
		}
		return fmt.Errorf("delivery: policy validate: %w", err)
	}
	if m.UserID != s.userID {
		return fmt.Errorf("delivery: policy message user_id %q does not match state user_id %q",
			m.UserID, s.userID)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// §7.2 ordering rule: monotonic policy_version with later-
	// timestamp tie-break for equal versions. A submission whose
	// (version, timestamp) is not strictly after the current state
	// is stale.
	if m.PolicyVersion < s.policyVersion ||
		(m.PolicyVersion == s.policyVersion && !m.Timestamp.After(s.lastTimestamp)) {
		pae := &PolicyApplyError{
			Code:             semp.ReasonPolicyVersionStale,
			SubmittedVersion: m.PolicyVersion,
			CurrentVersion:   s.policyVersion,
		}
		return pae.asSEMPError()
	}

	// Pre-flight every op for unsupported-kind before mutating.
	// §7.2 atomicity: a single unrecognized kind rejects the whole
	// message; unrelated operations in the same message MUST NOT be
	// applied.
	for i, op := range m.Operations {
		if _, ok := s.supportedKinds[op.Kind]; !ok {
			pae := &PolicyApplyError{
				Code:    semp.ReasonPolicyKindUnsupported,
				Kind:    op.Kind,
				OpIndex: i,
			}
			return pae.asSEMPError()
		}
	}

	// Apply.
	for _, op := range m.Operations {
		s.applyOp(op)
	}
	s.policyVersion = m.PolicyVersion
	s.lastTimestamp = m.Timestamp
	return nil
}

// applyOp mutates the per-kind store for one operation. The caller
// holds s.mu and has pre-validated the op's kind.
//
// Singleton kinds (first_contact): modify is upsert; add/remove are
// rejected upstream by Validate per §7.3.
//
// List-shaped kinds: add and modify both upsert by id (CRDT-style:
// the verb distinction is preserved on the wire so consumers can
// reason about author intent, but the convergent state on the server
// is the same regardless of which verb was used). remove deletes by
// entry_id; missing-id remove is a no-op. This idempotent shape
// avoids surfacing precondition failures at the op level on top of
// the version-monotonicity guard, which already rejects replays at
// the message level.
func (s *PolicyState) applyOp(op PolicyOperation) {
	if op.Kind == PolicyKindFirstContact {
		s.singletons[op.Kind] = append(json.RawMessage(nil), op.Entry...)
		return
	}
	bucket, ok := s.listEntries[op.Kind]
	if !ok {
		bucket = make(map[string]json.RawMessage)
		s.listEntries[op.Kind] = bucket
	}
	switch op.Op {
	case PolicyOpAdd, PolicyOpModify:
		id := s.entryID(op)
		if id == "" {
			// Upstream Validate enforces presence rules per verb;
			// reaching here without an id means the entry's own id
			// field is also missing. Skip silently rather than
			// inserting under "" so callers see the no-op rather
			// than a corrupted bucket.
			return
		}
		bucket[id] = append(json.RawMessage(nil), op.Entry...)
	case PolicyOpRemove:
		delete(bucket, op.EntryID)
	}
}

// entryID returns the id this op targets. For remove/modify the
// op's own EntryID field is authoritative. For add the spec puts
// the id inside the entry payload (id field, ULID RECOMMENDED per
// §7.3); we extract it here.
func (s *PolicyState) entryID(op PolicyOperation) string {
	if op.EntryID != "" {
		return op.EntryID
	}
	var probe struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(op.Entry, &probe)
	return probe.ID
}

// ListEntries returns a deep copy of the entries currently held for
// kind, keyed by entry id. Empty for unregistered or empty kinds.
func (s *PolicyState) ListEntries(kind string) map[string]json.RawMessage {
	s.mu.Lock()
	defer s.mu.Unlock()
	src := s.listEntries[kind]
	out := make(map[string]json.RawMessage, len(src))
	for k, v := range src {
		out[k] = append(json.RawMessage(nil), v...)
	}
	return out
}

// Singleton returns a copy of the current singleton entry for kind,
// or nil if none has been set. Useful for the first_contact policy
// kind.
func (s *PolicyState) Singleton(kind string) json.RawMessage {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.singletons[kind]
	if !ok {
		return nil
	}
	return append(json.RawMessage(nil), v...)
}

// PolicySnapshot is a deep copy of a PolicyState's contents at one
// point in time. Used for propagation to other devices on next
// connection per §7.2 and for persistence checkpointing.
type PolicySnapshot struct {
	UserID        string
	PolicyVersion int64
	LastTimestamp time.Time
	ListEntries   map[string]map[string]json.RawMessage
	Singletons    map[string]json.RawMessage
}

// Snapshot returns a deep copy of s's contents. Safe to mutate
// without affecting the live state.
func (s *PolicyState) Snapshot() *PolicySnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	snap := &PolicySnapshot{
		UserID:        s.userID,
		PolicyVersion: s.policyVersion,
		LastTimestamp: s.lastTimestamp,
		ListEntries:   make(map[string]map[string]json.RawMessage, len(s.listEntries)),
		Singletons:    make(map[string]json.RawMessage, len(s.singletons)),
	}
	for kind, src := range s.listEntries {
		dst := make(map[string]json.RawMessage, len(src))
		for id, v := range src {
			dst[id] = append(json.RawMessage(nil), v...)
		}
		snap.ListEntries[kind] = dst
	}
	for kind, v := range s.singletons {
		snap.Singletons[kind] = append(json.RawMessage(nil), v...)
	}
	return snap
}

// classifyOpInvalid heuristically maps a Validate() error to the
// triple (op_index, kind, detail) when the error originates from
// PolicyOperation.validate(). Returns ok=false for structural
// errors that are not specific op-kind violations.
//
// The mapping leans on Validate's stable error-string format
// ("operations[N]: ...") because reaching the inner op error any
// other way would require restructuring user_policy.go to surface a
// typed sentinel. This function is the only place the format is
// load-bearing; if user_policy.go ever switches to a typed inner
// error, swap this for an errors.As check.
func classifyOpInvalid(err error, m *UserPolicyMessage) (idx int, kind, detail string, ok bool) {
	const prefix = "delivery: user policy operations["
	msg := err.Error()
	if !startsWith(msg, prefix) {
		return 0, "", "", false
	}
	rest := msg[len(prefix):]
	end := -1
	for i, c := range rest {
		if c == ']' {
			end = i
			break
		}
	}
	if end < 1 {
		return 0, "", "", false
	}
	if _, e := fmt.Sscanf(rest[:end], "%d", &idx); e != nil {
		return 0, "", "", false
	}
	if idx < 0 || idx >= len(m.Operations) {
		return 0, "", "", false
	}
	tail := rest[end+1:]
	// tail looks like ": <inner detail>".
	if startsWith(tail, ": ") {
		detail = tail[2:]
	} else {
		detail = tail
	}
	return idx, m.Operations[idx].Kind, detail, true
}

func startsWith(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}
