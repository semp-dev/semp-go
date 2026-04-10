package session

import (
	"time"

	"github.com/semp-dev/semp-go/crypto"
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
	// accepted (the moment the responder sent step "accepted").
	EstablishedAt time.Time

	// TTL is the session lifetime in seconds, taken from the responder's
	// session_ttl field.
	TTL time.Duration

	// ExpiresAt is the locally computed EstablishedAt + TTL.
	ExpiresAt time.Time

	// PeerIdentity is the authenticated peer identifier: a user address for
	// client sessions, a domain for federation sessions.
	PeerIdentity string

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
