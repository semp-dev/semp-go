package reputation

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Challenge is the proof-of-work challenge issued by a server during a
// handshake when the originating domain has insufficient reputation
// (REPUTATION.md §8.3).
//
// The handshake message that carries this struct is defined in
// handshake.PoWRequired; this type holds the same fields in a form
// convenient for policy code that issues challenges without pulling in
// the handshake package.
type Challenge struct {
	ID         string    // ULID recommended
	Algorithm  string    // always "sha256"
	Prefix     []byte    // minimum 16 bytes of entropy
	Difficulty int       // leading zero bits required in the solution hash
	Expires    time.Time // single-use deadline
}

// Constants mirrored from handshake for direct use in the reputation
// layer without importing handshake (which would cause a cycle — the
// handshake package already imports the reputation abstractions).
const (
	// DefaultPoWAlgorithm is the only supported PoW hash algorithm.
	DefaultPoWAlgorithm = "sha256"

	// MinPrefixBytes is the minimum entropy a challenge's prefix must
	// carry (REPUTATION.md §8.3.1).
	MinPrefixBytes = 16

	// DefaultChallengeTTL is the time-to-live applied to a new
	// challenge when the caller passes zero. Five minutes is the
	// clock-skew buffer RECOMMENDED by §8.3.4.
	DefaultChallengeTTL = 5 * time.Minute
)

// Difficulty presets from REPUTATION.md §8.3.2.
const (
	// DifficultyBaseline is the default for zero-reputation senders
	// per §8.3.2 ("Servers SHOULD use difficulty 20 as the default for
	// zero-reputation senders").
	DifficultyBaseline = 20

	// DifficultyRelaxed is the relaxed level for zero-reputation but
	// established-age domains (§8.3.2 table: "Zero reputation, domain
	// age > threshold → 16").
	DifficultyRelaxed = 16

	// DifficultySuspicious is the lower end of the "established domain
	// exhibiting suspicious patterns" range (§8.3.2 table: 20–24).
	DifficultySuspicious = 22

	// DifficultyHostile is the lower end of the "hostile assessment"
	// range (§8.3.2 table: 24–28). Setting this above 24 adds noticeable
	// latency for legitimate senders; operators should reserve it.
	DifficultyHostile = 26

	// DomainAgeGateDays is the "new domain" window from REPUTATION.md
	// §2.1 — domains younger than this get more aggressive scrutiny.
	DomainAgeGateDays = 30
)

// DifficultyForAge returns the recommended difficulty for a new-domain
// that is ageDays old according to the curve in REPUTATION.md §8.3.2:
//
//   - age < DomainAgeGateDays → DifficultyBaseline (20)
//   - age ≥ DomainAgeGateDays → DifficultyRelaxed  (16)
//
// Operators with stricter or looser policies should skip this helper
// and pass their own difficulty to IssueChallenge.
func DifficultyForAge(ageDays int) int {
	if ageDays < DomainAgeGateDays {
		return DifficultyBaseline
	}
	return DifficultyRelaxed
}

// DifficultyForAssessment returns the recommended PoW difficulty for a
// domain whose reputation has been summarized as the given assessment.
// Zero-reputation domains are handled by DifficultyForAge; this helper
// is for domains that already have an established observation record.
//
//   - AssessmentTrusted / AssessmentNeutral → 0 (no PoW required)
//   - AssessmentSuspicious                  → DifficultySuspicious (22)
//   - AssessmentHostile                     → DifficultyHostile (26)
//
// A return value of zero MUST be interpreted as "no challenge".
func DifficultyForAssessment(a Assessment) int {
	switch a {
	case AssessmentTrusted, AssessmentNeutral, "":
		return 0
	case AssessmentSuspicious:
		return DifficultySuspicious
	case AssessmentHostile:
		return DifficultyHostile
	default:
		return 0
	}
}

// IssueChallenge constructs a fresh Challenge at the given difficulty.
// The prefix is filled with MinPrefixBytes of cryptographically secure
// random bytes. The ID is a ULID-shaped 26-character Crockford base32
// string derived from the current wall-clock time plus 10 bytes of
// entropy.
//
// A zero ttl is replaced with DefaultChallengeTTL. A negative ttl is
// rejected as a programming error.
//
// Reference: REPUTATION.md §8.3.1.
func IssueChallenge(difficulty int, ttl time.Duration) (*Challenge, error) {
	if difficulty < 0 {
		return nil, errors.New("reputation: negative PoW difficulty")
	}
	if difficulty > 256 {
		return nil, errors.New("reputation: PoW difficulty exceeds SHA-256 output size")
	}
	if ttl < 0 {
		return nil, errors.New("reputation: negative PoW TTL")
	}
	if ttl == 0 {
		ttl = DefaultChallengeTTL
	}
	prefix := make([]byte, MinPrefixBytes)
	if _, err := rand.Read(prefix); err != nil {
		return nil, fmt.Errorf("reputation: challenge prefix entropy: %w", err)
	}
	id, err := newChallengeID()
	if err != nil {
		return nil, err
	}
	return &Challenge{
		ID:         id,
		Algorithm:  DefaultPoWAlgorithm,
		Prefix:     prefix,
		Difficulty: difficulty,
		Expires:    time.Now().UTC().Add(ttl),
	}, nil
}

// PrefixBase64 returns the challenge prefix encoded with standard
// base64 — the wire format the handshake layer and VECTORS.md §4.3
// use for the preimage.
func (c *Challenge) PrefixBase64() string {
	if c == nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(c.Prefix)
}

// -----------------------------------------------------------------------------
// Challenge ledger
// -----------------------------------------------------------------------------

// ChallengeLedger tracks which challenges have been issued, which have
// been redeemed (preventing replay per REPUTATION.md §8.3.4 — "Each
// challenge MUST be single-use"), and prunes expired entries so memory
// does not grow without bound.
//
// A ChallengeLedger is safe for concurrent use by multiple goroutines.
// The zero value is not usable; call NewChallengeLedger.
type ChallengeLedger struct {
	mu sync.Mutex
	// entries keyed by challenge ID. The value is the full challenge
	// plus a redeemed flag; redeemed entries are retained until their
	// expiry so replay attempts against an expired-but-still-in-memory
	// challenge return "already used" rather than "unknown".
	entries map[string]*ledgerEntry

	// lastSweep is the wall-clock time of the most recent prune. The
	// ledger runs at most one sweep per sweepInterval.
	lastSweep     time.Time
	sweepInterval time.Duration
}

type ledgerEntry struct {
	challenge *Challenge
	redeemed  bool
}

// NewChallengeLedger returns an empty ledger. sweepInterval bounds how
// often the ledger walks its map to prune expired entries. A zero
// interval picks a sensible default (1 minute).
func NewChallengeLedger(sweepInterval time.Duration) *ChallengeLedger {
	if sweepInterval <= 0 {
		sweepInterval = time.Minute
	}
	return &ChallengeLedger{
		entries:       map[string]*ledgerEntry{},
		sweepInterval: sweepInterval,
	}
}

// Record adds ch to the ledger. Returns an error if a challenge with
// the same ID has already been recorded — IDs are expected to be
// globally unique per the ULID recommendation in §8.3.1.
func (l *ChallengeLedger) Record(ch *Challenge) error {
	if l == nil || ch == nil {
		return errors.New("reputation: nil ledger or challenge")
	}
	if ch.ID == "" {
		return errors.New("reputation: challenge has empty ID")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.maybeSweepLocked()
	if _, exists := l.entries[ch.ID]; exists {
		return fmt.Errorf("reputation: duplicate challenge ID %s", ch.ID)
	}
	l.entries[ch.ID] = &ledgerEntry{challenge: ch}
	return nil
}

// Redeem marks the challenge with the given ID as redeemed. Returns:
//
//   - (*Challenge, nil) on the first successful redemption.
//   - (nil, ErrChallengeUnknown) if the challenge is not in the ledger.
//   - (nil, ErrChallengeExpired) if the challenge has passed its expiry.
//   - (nil, ErrChallengeReplayed) if the challenge has already been
//     successfully redeemed.
//
// Redeem does not itself verify the PoW solution — the caller is
// expected to pair Redeem with a solution verification step (e.g. the
// handshake package's VerifySolution). Redeem is responsible for the
// ledger bookkeeping that wraps the cryptographic check.
func (l *ChallengeLedger) Redeem(challengeID string) (*Challenge, error) {
	if l == nil {
		return nil, errors.New("reputation: nil ledger")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.maybeSweepLocked()
	entry, ok := l.entries[challengeID]
	if !ok {
		return nil, ErrChallengeUnknown
	}
	if entry.redeemed {
		return nil, ErrChallengeReplayed
	}
	if !entry.challenge.Expires.IsZero() && !time.Now().Before(entry.challenge.Expires) {
		return nil, ErrChallengeExpired
	}
	entry.redeemed = true
	return entry.challenge, nil
}

// Active reports the number of non-expired, non-redeemed challenges
// currently in the ledger. Useful for metrics.
func (l *ChallengeLedger) Active() int {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	count := 0
	for _, e := range l.entries {
		if e.redeemed {
			continue
		}
		if !e.challenge.Expires.IsZero() && !now.Before(e.challenge.Expires) {
			continue
		}
		count++
	}
	return count
}

// Sweep removes all entries whose challenge has expired AND (if
// redeemed) whose expiry has passed by at least the sweep grace
// window. Callers that want deterministic pruning can invoke Sweep
// directly; otherwise the ledger sweeps lazily on Record and Redeem.
func (l *ChallengeLedger) Sweep() {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sweepLocked(time.Now())
}

// maybeSweepLocked runs a sweep if enough time has elapsed since the
// last one. Caller must hold l.mu.
func (l *ChallengeLedger) maybeSweepLocked() {
	now := time.Now()
	if now.Sub(l.lastSweep) < l.sweepInterval {
		return
	}
	l.sweepLocked(now)
}

// sweepLocked drops expired entries. Caller must hold l.mu.
func (l *ChallengeLedger) sweepLocked(now time.Time) {
	// Keep redeemed expired entries until they pass their expiry by a
	// clock-skew grace of 5 minutes, per REPUTATION.md §8.3.4:
	// "Challenge IDs MAY be pruned after their expiry time plus a
	// reasonable clock-skew buffer (RECOMMENDED: 5 minutes)."
	const grace = 5 * time.Minute
	for id, e := range l.entries {
		if e.challenge.Expires.IsZero() {
			continue
		}
		pruneAt := e.challenge.Expires.Add(grace)
		if now.After(pruneAt) {
			delete(l.entries, id)
		}
	}
	l.lastSweep = now
}

// Ledger error values.
var (
	// ErrChallengeUnknown is returned by Redeem when the challenge ID
	// has never been recorded.
	ErrChallengeUnknown = errors.New("reputation: unknown challenge")

	// ErrChallengeExpired is returned by Redeem when the challenge has
	// passed its expiry timestamp.
	ErrChallengeExpired = errors.New("reputation: challenge expired")

	// ErrChallengeReplayed is returned by Redeem when the challenge
	// has already been successfully redeemed once.
	ErrChallengeReplayed = errors.New("reputation: challenge already redeemed")
)

// -----------------------------------------------------------------------------
// ID generation
// -----------------------------------------------------------------------------

// crockfordAlphabet is the Crockford base32 alphabet used by ULIDs.
// We don't need bit-for-bit ULID compliance — just a collision-free
// 26-character identifier.
const crockfordAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

var crockfordEncoding = base32.NewEncoding(crockfordAlphabet).WithPadding(base32.NoPadding)

// newChallengeID returns a ULID-shaped 26-character identifier with a
// 48-bit millisecond timestamp prefix and 80 bits of randomness. This
// mirrors the pattern used by transport/h2's session id generator,
// inlined here to avoid a cross-package dependency.
func newChallengeID() (string, error) {
	var raw [16]byte
	now := uint64(time.Now().UnixMilli())
	binary.BigEndian.PutUint64(raw[:8], now<<16)
	if _, err := rand.Read(raw[6:]); err != nil {
		return "", fmt.Errorf("reputation: challenge id entropy: %w", err)
	}
	enc := crockfordEncoding.EncodeToString(raw[:])
	if len(enc) > 26 {
		enc = enc[:26]
	}
	return enc, nil
}
