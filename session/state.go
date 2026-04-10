package session

// State represents a SEMP session's current lifecycle phase.
type State int

// Lifecycle states.
const (
	// StateInitial — created but not yet established.
	StateInitial State = iota

	// StateHandshaking — handshake in progress.
	StateHandshaking

	// StateActive — handshake complete, accepting envelopes.
	StateActive

	// StateRekeying — in-session rekey exchange in progress.
	StateRekeying

	// StateExpired — TTL elapsed; key material still in memory until Erase.
	StateExpired

	// StateInvalidated — explicitly invalidated by the server (block, key
	// revocation, security event).
	StateInvalidated

	// StateErased — Erase has been called; the session struct is now inert.
	StateErased
)

// String satisfies fmt.Stringer.
func (s State) String() string {
	switch s {
	case StateInitial:
		return "initial"
	case StateHandshaking:
		return "handshaking"
	case StateActive:
		return "active"
	case StateRekeying:
		return "rekeying"
	case StateExpired:
		return "expired"
	case StateInvalidated:
		return "invalidated"
	case StateErased:
		return "erased"
	default:
		return "unknown"
	}
}

// Role identifies whether this session represents a client connection to a
// home server or a federation connection to a peer domain.
type Role int

// Session roles.
const (
	// RoleClient — a user client to its home server.
	RoleClient Role = iota

	// RoleFederation — a server-to-server federation connection.
	RoleFederation
)
