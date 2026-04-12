package session

import (
	"time"

	"semp.dev/semp-go/crypto"
)

// Session is the in-memory state for a single SEMP session, mirroring the
// fields enumerated in SESSION.md §2.3 (server side) and §2.6.1 (client
// side). The struct is intentionally not safe for JSON marshaling: there is
// no MarshalJSON shim and the key fields are unexported, because session
// state MUST NOT be written to disk, replicated, or included in backups
// (SESSION.md §2.3, §2.6.2).
type Session struct {
	// ID is the server-generated session identifier (ULID recommended).
	ID string

	// Role is RoleClient or RoleFederation.
	Role Role

	// State is the current lifecycle phase.
	State State

	// EstablishedAt is the wall-clock time at which the session was
	// accepted (the moment the responder sent step "accepted"). Per
	// SESSION.md §3.4, this timestamp is inherited across rekeys.
	EstablishedAt time.Time

	// TTL is the session lifetime in seconds, taken from the responder's
	// session_ttl field.
	TTL time.Duration

	// ExpiresAt is the locally computed EstablishedAt + TTL (reset to
	// now + TTL on every successful rekey per SESSION.md §3.4).
	ExpiresAt time.Time

	// PeerIdentity is the authenticated peer identifier: a user address for
	// client sessions, a domain for federation sessions.
	PeerIdentity string

	// RekeyCount is the number of successful rekey events this session
	// has seen. SESSION.md §3.5 caps this at MaxRekeysPerSession (10);
	// an 11th rekey MUST be rejected with reason_code rate_limited.
	RekeyCount int

	// LastRekeyAt is the wall-clock time of the most recent successful
	// rekey (zero if none yet). SESSION.md §3.5 requires at least one
	// minute between rekey attempts.
	LastRekeyAt time.Time

	// PreviousID is the session's prior ID during the brief transition
	// window after a rekey (SESSION.md §3.4). Envelopes whose postmark
	// references PreviousID are still accepted until PreviousIDExpiresAt.
	// Empty outside of that window.
	PreviousID string

	// PreviousIDExpiresAt is the deadline after which PreviousID is no
	// longer accepted. Zero when PreviousID is empty.
	PreviousIDExpiresAt time.Time

	// keys holds the five derived session keys. Unexported so callers go
	// through MAC and AEAD accessors that operate on the bytes without
	// ever returning them to the caller — this prevents accidental
	// serialization or logging of secret material.
	keys *crypto.SessionKeys
}

// New constructs a Session with State StateInitial. Other fields are filled
// in by the handshake state machine as it progresses.
func New(role Role) *Session {
	return &Session{
		Role:  role,
		State: StateInitial,
	}
}

// SetKeys installs the derived session keys. Called by the handshake state
// machine after the shared secret is derived. The keys are owned by the
// session from this point on; the handshake MUST NOT retain a copy.
func (s *Session) SetKeys(k *crypto.SessionKeys) {
	if s == nil {
		return
	}
	s.keys = k
}

// Active reports whether the session is currently usable for sending
// envelopes (State == StateActive and now < ExpiresAt).
func (s *Session) Active(now time.Time) bool {
	if s == nil || s.State != StateActive {
		return false
	}
	return now.Before(s.ExpiresAt)
}

// Erase zeroes the session key material and transitions the session to
// StateErased. After Erase, all subsequent operations are no-ops. Callers
// MUST invoke Erase as part of teardown (SESSION.md §2.4, §2.6.2).
func (s *Session) Erase() {
	if s == nil {
		return
	}
	if s.keys != nil {
		s.keys.Erase()
		s.keys = nil
	}
	s.State = StateErased
}

// EnvMAC returns the K_env_mac bytes for use in seal.session_mac
// computation. Returns nil if the session has been erased.
//
// This is the only public accessor for raw key material in the API. Callers
// MUST NOT log, persist, or transmit the returned bytes; they exist for the
// seal Signer to feed into the MAC primitive.
//
// TODO(SESSION.md §5.3): consider replacing this accessor with a MAC method
// that performs the computation in-place, avoiding any exposure of the key
// bytes outside this package.
func (s *Session) EnvMAC() []byte {
	if s == nil || s.keys == nil {
		return nil
	}
	return s.keys.EnvMAC
}

// EncC2S / EncS2C / MACC2S / MACS2C expose the four directional session
// keys. They are used by the rekey driver to encrypt/MAC the rekey-init
// and rekey-accepted messages over the existing session channel. Like
// EnvMAC, they are raw key bytes and callers MUST NOT log, persist, or
// transmit them.
func (s *Session) EncC2S() []byte { return s.rawKey(func(k *crypto.SessionKeys) []byte { return k.EncC2S }) }
func (s *Session) EncS2C() []byte { return s.rawKey(func(k *crypto.SessionKeys) []byte { return k.EncS2C }) }
func (s *Session) MACC2S() []byte { return s.rawKey(func(k *crypto.SessionKeys) []byte { return k.MACC2S }) }
func (s *Session) MACS2C() []byte { return s.rawKey(func(k *crypto.SessionKeys) []byte { return k.MACS2C }) }

func (s *Session) rawKey(pick func(*crypto.SessionKeys) []byte) []byte {
	if s == nil || s.keys == nil {
		return nil
	}
	return pick(s.keys)
}

// TransitionWindow is the duration during which both the old and the
// new session_id are accepted after a successful rekey (SESSION.md §3.4).
const TransitionWindow = 5 * time.Second

// CanRekey reports whether s may be rekeyed at wall-clock time `now`
// under SESSION.md §3.5: the session must be active, at least
// MinRekeyInterval must have elapsed since the last rekey, and the
// session must not have exceeded MaxRekeysPerSession events.
//
// Returns (ok, reasonCode, reason). The reasonCode is one of
// "session_expired", "rate_limited", or empty on success.
func (s *Session) CanRekey(now time.Time) (bool, string, string) {
	if s == nil {
		return false, "session_expired", "nil session"
	}
	if s.State != StateActive {
		return false, "session_expired", "session not active"
	}
	if !now.Before(s.ExpiresAt) {
		return false, "session_expired", "session TTL elapsed"
	}
	if s.RekeyCount >= MaxRekeysPerSession {
		return false, "rate_limited", "max rekey events per session reached"
	}
	if !s.LastRekeyAt.IsZero() && now.Sub(s.LastRekeyAt) < MinRekeyInterval {
		return false, "rate_limited", "rekey rate limit"
	}
	return true, "", ""
}

// ApplyRekey swaps in the new session keys produced by a successful
// rekey exchange. It also:
//
//   - retires the current ID into PreviousID (with a TransitionWindow
//     grace period during which the old ID still matches per §3.4),
//   - sets the current ID to newID,
//   - resets ExpiresAt to now + original TTL (§3.4),
//   - increments RekeyCount and sets LastRekeyAt.
//
// The caller is responsible for erasing the PRIOR keys before passing
// the new ones in — SetKeys does not erase the previous value because
// different callers have different erase policies (e.g. tests prefer
// to inspect both sets).
func (s *Session) ApplyRekey(newID string, newKeys *crypto.SessionKeys, now time.Time) {
	if s == nil {
		return
	}
	s.PreviousID = s.ID
	s.PreviousIDExpiresAt = now.Add(TransitionWindow)
	s.ID = newID
	if s.keys != nil {
		s.keys.Erase()
	}
	s.keys = newKeys
	s.ExpiresAt = now.Add(s.TTL)
	s.RekeyCount++
	s.LastRekeyAt = now
}

// AcceptsID reports whether sessionID matches the session's current or
// transition-window previous ID at the given wall-clock time. Used by
// inbound envelope processing during the brief transition window after
// a rekey (SESSION.md §3.4).
func (s *Session) AcceptsID(sessionID string, now time.Time) bool {
	if s == nil {
		return false
	}
	if s.ID == sessionID {
		return true
	}
	if s.PreviousID == sessionID && now.Before(s.PreviousIDExpiresAt) {
		return true
	}
	return false
}
