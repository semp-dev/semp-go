package reputation

import "time"

// Challenge is the proof-of-work challenge issued by a server during a
// handshake when the originating domain has insufficient reputation
// (REPUTATION.md §8.3).
//
// The handshake message that carries this struct is defined in
// handshake.PoWRequired; this type holds the same fields in a form
// convenient for policy code that issues challenges.
type Challenge struct {
	ID         string    // ULID recommended
	Algorithm  string    // always "sha256"
	Prefix     []byte    // minimum 16 bytes of entropy
	Difficulty int       // leading zero bits required in the solution hash
	Expires    time.Time // single-use deadline
}

// Difficulty returns the difficulty (leading zero bits) recommended for the
// given new-domain age in days. This is one possible policy curve;
// operators may substitute their own.
//
// Reference: REPUTATION.md §8.3.2.
//
// TODO(REPUTATION.md §8.3.2): implement a real curve. The skeleton returns
// a constant value.
func DifficultyForAge(ageDays int) int {
	return 20
}

// IssueChallenge constructs a fresh Challenge for a sender at the given
// difficulty.
//
// TODO(REPUTATION.md §8.3.1): implement using crypto/rand for prefix entropy
// and ULID for the ID.
func IssueChallenge(difficulty int, ttl time.Duration) (*Challenge, error) {
	_, _ = difficulty, ttl
	return nil, nil
}
