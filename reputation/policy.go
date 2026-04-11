package reputation

import (
	"encoding/base64"
	"sync"
	"time"
)

// PoWPolicy turns an ObservationStore + ChallengeLedger into the
// decision "should this handshake be PoW-gated, and if so, at what
// difficulty?". Operators plug it into the handshake layer via the
// HandshakeAdapter below, which implements handshake.Policy (through
// duck-typing — we avoid importing handshake here to prevent a
// dependency cycle).
//
// The decision curve matches REPUTATION.md §8.3.2:
//
//   - Unknown / neutral domains → DifficultyForAge(ageDays)
//   - Trusted domains           → no PoW (returns zero-value
//     challenge)
//   - Suspicious domains        → DifficultySuspicious (22)
//   - Hostile domains           → DifficultyHostile (26)
//
// Callers that want a stricter or looser curve should implement their
// own policy that reads Score directly; PoWPolicy is the sensible
// default.
type PoWPolicy struct {
	// Store is the reputation signal source. Required.
	Store *ObservationStore

	// Ledger tracks issued and redeemed challenges. Required — without
	// a ledger the server cannot enforce the single-use rule from
	// REPUTATION.md §8.3.4.
	Ledger *ChallengeLedger

	// TTL is the lifetime applied to every issued challenge. Zero
	// picks DefaultChallengeTTL.
	TTL time.Duration

	// AgeDaysFor returns the best-effort age in days for the given
	// domain. Optional: nil returns ageDays=0 (i.e. "treat as new
	// domain") which maps to DifficultyBaseline. Operators with a
	// WHOIS lookup or a registration database plug in here.
	AgeDaysFor func(domain string) int

	// MinDifficulty floors every issued challenge to at least this
	// level, regardless of assessment. Zero disables the floor. Useful
	// for operators that want a baseline friction on every inbound
	// handshake from a zero-reputation sender.
	MinDifficulty int

	// Clock is a time hook for tests. Zero means time.Now.
	Clock func() time.Time
}

// Decide returns a challenge when the policy requires PoW for the
// given origin domain, or (nil, nil) when no challenge is required.
// The returned challenge has already been recorded in the ledger.
// A non-nil error means the caller should fail the handshake with
// a transport-level error rather than a pow_failed rejection.
func (p *PoWPolicy) Decide(domain string) (*Challenge, error) {
	if p == nil {
		return nil, nil
	}
	difficulty := p.difficultyFor(domain)
	if difficulty <= 0 {
		return nil, nil
	}
	ch, err := IssueChallenge(difficulty, p.TTL)
	if err != nil {
		return nil, err
	}
	if p.Ledger != nil {
		if err := p.Ledger.Record(ch); err != nil {
			return nil, err
		}
	}
	return ch, nil
}

// difficultyFor combines age and assessment into a single difficulty
// value. Returns 0 when no PoW is required.
func (p *PoWPolicy) difficultyFor(domain string) int {
	score := p.score(domain)
	assessmentDiff := DifficultyForAssessment(score.Assessment)

	var ageDays int
	if p.AgeDaysFor != nil {
		ageDays = p.AgeDaysFor(domain)
	} else if score.AgeDays >= 0 {
		ageDays = score.AgeDays
	}
	ageDiff := DifficultyForAge(ageDays)

	// Use the HIGHER of the two signals — a trusted-but-very-new
	// domain still gets the age friction; a suspicious-but-old domain
	// still gets the assessment friction.
	d := assessmentDiff
	if ageDiff > d && score.Assessment != AssessmentTrusted {
		d = ageDiff
	}
	// Trusted domains are exempt: §8.3.2 says "Servers SHOULD use
	// difficulty 20 as the default for zero-reputation senders".
	// Once a domain earns trusted we stop issuing PoW regardless of
	// its age.
	if score.Assessment == AssessmentTrusted {
		return 0
	}
	if p.MinDifficulty > d {
		d = p.MinDifficulty
	}
	return d
}

// score queries the ObservationStore or returns a zero Score if no
// store is configured.
func (p *PoWPolicy) score(domain string) Score {
	if p == nil || p.Store == nil {
		return Score{Domain: domain, Assessment: AssessmentNeutral, AgeDays: -1}
	}
	return p.Store.Score(domain)
}

// RedeemAndVerify looks up the challenge by ID, runs the ledger
// single-use check, and then calls verify to confirm the solution. It
// wraps the two-step (ledger + cryptographic) check into one safe
// call. verify is passed the original challenge prefix and difficulty
// so the caller's cryptographic verification (e.g. handshake's
// VerifySolution) does not need to know about the ledger.
//
// On success the challenge is marked redeemed and (nil) is returned.
// On any failure the ledger is NOT touched so the caller can attempt
// verification with a fresh solution if the client retries — unless
// the failure is the ledger's own single-use rejection, in which case
// the challenge stays marked redeemed (which is correct).
func (p *PoWPolicy) RedeemAndVerify(challengeID string, verify func(prefix []byte, difficulty int) error) error {
	if p == nil || p.Ledger == nil {
		return ErrChallengeUnknown
	}
	ch, err := p.Ledger.Redeem(challengeID)
	if err != nil {
		return err
	}
	return verify(ch.Prefix, ch.Difficulty)
}

// -----------------------------------------------------------------------------
// HandshakeAdapter
// -----------------------------------------------------------------------------

// HandshakeAdapter wraps a PoWPolicy so it satisfies the handshake
// package's Policy interface without this package having to import
// handshake (and thereby creating a cycle — handshake already depends
// on reputation-shaped concepts). The adapter embeds a DelegatePolicy
// for the non-PoW decisions (block lists, session TTL, permissions)
// and delegates to it for everything other than RequirePoW.
//
// Usage from a server:
//
//	policy := &reputation.HandshakeAdapter{
//	    PoW:       powPolicy,
//	    Delegate:  myBlocklistAndPermissionsPolicy,
//	    Transport: "ws",
//	}
//	handshake.NewServer(handshake.ServerConfig{ Policy: policy, ... })
//
// The Delegate is required — it owns the fields PoWPolicy does not.
type HandshakeAdapter struct {
	PoW      *PoWPolicy
	Delegate DelegatePolicy

	// OriginFrom maps a handshake init nonce+transport pair to the
	// sender's domain. The handshake layer does not give us the
	// sender's domain at the PoW decision point (the encrypted
	// identity proof is not yet opened), so we rely on the operator
	// to plumb per-connection domain hints — typically by remembering
	// the TLS SNI or the HTTP request's Host header when they accept
	// the transport connection.
	//
	// When OriginFrom is nil or returns an empty string, the adapter
	// treats the origin as unknown and issues DifficultyBaseline.
	OriginFrom func(initNonce, transport string) string

	// Clock is a clock hook for tests.
	Clock func() time.Time

	// outstanding remembers the challenge issued for a given init so
	// the caller can look it up after the handshake continues and
	// Record the outcome in the ObservationStore.
	mu          sync.Mutex
	outstanding map[string]*Challenge
}

// DelegatePolicy is the subset of handshake.Policy that the
// HandshakeAdapter does not handle itself. An operator's existing
// policy implementation satisfies this interface trivially: the
// adapter calls BlockedDomain, SessionTTL, and Permissions verbatim.
type DelegatePolicy interface {
	BlockedDomain(domain string) bool
	SessionTTL(identity string) int
	Permissions(identity string) []string
}

// PoWRequirement is the struct the adapter returns from its
// RequirePoW equivalent. It mirrors handshake.PoWRequired's wire
// fields but is declared here so reputation can stay
// handshake-independent. Callers that use the adapter with
// handshake.Server wrap it once in a small shim that copies the
// fields into handshake.PoWRequired; see the tests for an example.
type PoWRequirement struct {
	ChallengeID string
	Algorithm   string
	PrefixB64   string
	Difficulty  int
	Expires     time.Time
}

// RequirePoW is the adapter's decision hook. Call it from the shim
// that implements handshake.Policy.RequirePoW:
//
//	func (s *shim) RequirePoW(initNonce, transport string) *handshake.PoWRequired {
//	    req := s.adapter.RequirePoW(initNonce, transport)
//	    if req == nil {
//	        return nil
//	    }
//	    return &handshake.PoWRequired{
//	        Type:        handshake.MessageType,
//	        Step:        handshake.StepPoWRequired,
//	        Party:       handshake.PartyServer,
//	        Version:     semp.ProtocolVersion,
//	        ChallengeID: req.ChallengeID,
//	        Algorithm:   req.Algorithm,
//	        Prefix:      req.PrefixB64,
//	        Difficulty:  req.Difficulty,
//	        Expires:     req.Expires,
//	    }
//	}
//
// Returns nil when no PoW is required (trusted or no-policy case).
func (a *HandshakeAdapter) RequirePoW(initNonce, transport string) *PoWRequirement {
	if a == nil || a.PoW == nil {
		return nil
	}
	domain := ""
	if a.OriginFrom != nil {
		domain = a.OriginFrom(initNonce, transport)
	}
	ch, err := a.PoW.Decide(domain)
	if err != nil || ch == nil {
		return nil
	}
	a.remember(initNonce, ch)
	return &PoWRequirement{
		ChallengeID: ch.ID,
		Algorithm:   ch.Algorithm,
		PrefixB64:   base64.StdEncoding.EncodeToString(ch.Prefix),
		Difficulty:  ch.Difficulty,
		Expires:     ch.Expires,
	}
}

// BlockedDomain delegates to the wrapped DelegatePolicy.
func (a *HandshakeAdapter) BlockedDomain(domain string) bool {
	if a == nil || a.Delegate == nil {
		return false
	}
	return a.Delegate.BlockedDomain(domain)
}

// SessionTTL delegates to the wrapped DelegatePolicy.
func (a *HandshakeAdapter) SessionTTL(identity string) int {
	if a == nil || a.Delegate == nil {
		return 0
	}
	return a.Delegate.SessionTTL(identity)
}

// Permissions delegates to the wrapped DelegatePolicy.
func (a *HandshakeAdapter) Permissions(identity string) []string {
	if a == nil || a.Delegate == nil {
		return nil
	}
	return a.Delegate.Permissions(identity)
}

// remember stashes a challenge keyed by the client's init nonce so
// the outcome of the subsequent pow_solution exchange can be
// attributed back to a domain for observation recording.
func (a *HandshakeAdapter) remember(initNonce string, ch *Challenge) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.outstanding == nil {
		a.outstanding = map[string]*Challenge{}
	}
	a.outstanding[initNonce] = ch
}

// Forget removes the outstanding challenge for initNonce. Call this
// from the shim after the handshake either completes or fails, so
// the adapter's scratch map does not leak memory.
func (a *HandshakeAdapter) Forget(initNonce string) *Challenge {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	ch := a.outstanding[initNonce]
	delete(a.outstanding, initNonce)
	return ch
}

// Outstanding reports the number of issued-but-not-yet-resolved
// challenges in the adapter's scratch map. Useful for metrics.
func (a *HandshakeAdapter) Outstanding() int {
	if a == nil {
		return 0
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.outstanding)
}
