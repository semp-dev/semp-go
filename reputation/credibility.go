package reputation

import "sync"

// Consumer-side observation weighting per REPUTATION.md §5.5.4 /
// draft-gokce-semp-delivery §11.8. A consumer aggregating
// observations from multiple peers SHOULD weight each observation
// by its locally-computed credibility for the publishing observer.
//
// Inputs to local credibility are implementation-defined and
// include:
//
//   - Evidence-hash verification rate (proportion of fetched
//     evidence whose digest matched the observation's
//     evidence_hash).
//   - Alignment with the consumer's own direct experience.
//   - Schema conformance history.
//   - Observer domain-stability signals (age, key rotation
//     hygiene, etc.).
//
// Per §5.5.4 consumer credibility is per-consumer local state. A
// consumer MUST NOT publish or share credibility scores about
// other observers as part of trust gossip or any other SEMP wire
// artifact. Shared scores would introduce transitive trust, which
// is incompatible with the no-transitive-trust principle.

// CredibilityScore is a consumer-side weight in [0, 1] for one
// observer. 0 means the consumer fully discounts the observer's
// observations; 1 means full weight. The default for an unknown
// observer is DefaultCredibility.
type CredibilityScore float64

// DefaultCredibility is the starting weight applied to an observer
// the consumer has no prior signals for. Conservative middle value.
const DefaultCredibility CredibilityScore = 0.5

// CredibilityLedger is the per-consumer local store of observer
// credibility. Safe for concurrent use.
//
// The ledger is INTENTIONALLY in-memory and unexported on the wire.
// Callers MUST NOT serialize or publish its contents. A
// MarshalJSON method is deliberately omitted so an accidental
// json.Marshal returns the empty object.
type CredibilityLedger struct {
	mu     sync.RWMutex
	scores map[string]CredibilityScore
}

// NewCredibilityLedger returns an empty ledger.
func NewCredibilityLedger() *CredibilityLedger {
	return &CredibilityLedger{scores: make(map[string]CredibilityScore)}
}

// Set records a credibility score for observer. Clamps s into
// [0, 1].
func (l *CredibilityLedger) Set(observer string, s CredibilityScore) {
	if l == nil || observer == "" {
		return
	}
	if s < 0 {
		s = 0
	}
	if s > 1 {
		s = 1
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.scores[observer] = s
}

// Get returns the recorded credibility for observer, or
// DefaultCredibility when the consumer has not yet seen this
// observer.
func (l *CredibilityLedger) Get(observer string) CredibilityScore {
	if l == nil || observer == "" {
		return DefaultCredibility
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	if s, ok := l.scores[observer]; ok {
		return s
	}
	return DefaultCredibility
}

// WeightedAggregate folds a slice of observations into a single
// summary value, weighted by per-observer credibility. metric is
// a caller-supplied projection that extracts the scalar to
// aggregate from one observation (typical: abuse_rate,
// reject_rate, suspicious-assessment-count).
//
// Returns the weighted mean. Returns 0 when observations is empty
// or when every observation has zero credibility.
func (l *CredibilityLedger) WeightedAggregate(
	observations []Observation,
	metric func(Observation) float64,
) float64 {
	if l == nil || len(observations) == 0 || metric == nil {
		return 0
	}
	var weighted, total float64
	for _, o := range observations {
		w := float64(l.Get(o.Observer))
		if w == 0 {
			continue
		}
		weighted += metric(o) * w
		total += w
	}
	if total == 0 {
		return 0
	}
	return weighted / total
}
