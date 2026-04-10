package transport

// Profile is the bitmask of communication patterns a transport satisfies
// (TRANSPORT.md §3).
type Profile uint8

// Profile bits.
const (
	// ProfileSynchronous covers handshake, discovery, key exchange, and
	// rekey: low-latency request-response or multi-message sequential
	// exchanges.
	ProfileSynchronous Profile = 1 << iota

	// ProfileAsynchronous covers envelope submission, envelope relay, and
	// delivery event notifications: latency-tolerant operations.
	ProfileAsynchronous
)

// ProfileBoth is a convenience constant for transports that satisfy both
// profiles. The three core transports (ws, h2, quic) all use this value.
const ProfileBoth = ProfileSynchronous | ProfileAsynchronous

// Has reports whether p includes the given profile bits.
func (p Profile) Has(q Profile) bool { return p&q == q }
