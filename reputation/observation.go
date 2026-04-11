package reputation

import (
	"strings"
	"sync"
	"time"

	"github.com/semp-dev/semp-go/keys"
)

// Observation is a single observation record published by one operator
// about another domain. Observations are signed by the publisher and
// form the input data behind the trust gossip hash.
//
// Reference: REPUTATION.md §4.
type Observation struct {
	// SubjectDomain is the domain being observed.
	SubjectDomain string `json:"subject_domain"`

	// PublisherDomain is the operator that published this observation.
	PublisherDomain string `json:"publisher_domain"`

	// PeriodStart is the start of the observation window.
	PeriodStart time.Time `json:"period_start"`

	// PeriodEnd is the end of the observation window.
	PeriodEnd time.Time `json:"period_end"`

	// Metrics is the full set of quantitative signals recorded during
	// the window (REPUTATION.md §4.5).
	Metrics Metrics `json:"metrics"`

	// Assessment is the summary classification (REPUTATION.md §4.6).
	Assessment Assessment `json:"assessment"`

	// Signature is the publisher's signature over the canonical form
	// of this observation (with Signature itself elided).
	Signature keys.PublicationSignature `json:"signature"`
}

// Metrics is the quantitative payload of an Observation. The field
// names and semantics follow REPUTATION.md §4.5.
type Metrics struct {
	EnvelopesReceived     int64 `json:"envelopes_received"`
	EnvelopesRejected     int64 `json:"envelopes_rejected"`
	AbuseReports          int64 `json:"abuse_reports"`
	UniqueSendersObserved int64 `json:"unique_senders_observed,omitempty"`
	HandshakesCompleted   int64 `json:"handshakes_completed,omitempty"`
	HandshakesRejected    int64 `json:"handshakes_rejected,omitempty"`
}

// Assessment is the qualitative summary attached to an Observation
// (REPUTATION.md §4.6).
type Assessment string

// Assessment values.
const (
	AssessmentTrusted    Assessment = "trusted"
	AssessmentNeutral    Assessment = "neutral"
	AssessmentSuspicious Assessment = "suspicious"
	AssessmentHostile    Assessment = "hostile"
)

// GossipHash is the trust gossip hash representation defined in
// REPUTATION.md §5: a publishable, hashed summary of a domain's
// observation history that other servers can compare against their
// own.
type GossipHash struct {
	Domain    string    `json:"domain"`
	Hash      string    `json:"hash"`
	Algorithm string    `json:"algorithm"`
	AsOf      time.Time `json:"as_of"`
}

// -----------------------------------------------------------------------------
// ObservationStore
// -----------------------------------------------------------------------------

// ObservationStore is the in-memory counterpart of a server's
// per-domain signal ledger (REPUTATION.md §4.1: "Each server maintains
// an internal ledger of its interactions with other domains. From
// this ledger, it may produce observation records.").
//
// The store records the raw counters as they happen (one call per
// handshake completed, one per handshake rejected, one per envelope
// accepted or rejected, one per abuse report) and exposes a Score
// query that turns the counters into a Score + Assessment + the
// derived "this domain is currently suspicious" verdict operators
// plug into their PoW policy hook.
//
// ObservationStore is safe for concurrent use. It is NOT a persistent
// store — production deployments should wrap a durable backend that
// persists counters across restarts and supports sliding-window
// pruning.
type ObservationStore struct {
	mu      sync.Mutex
	domains map[string]*domainCounters
	// firstSeen records the first time a signal was recorded for each
	// domain. The Score query uses this as a cheap proxy for domain
	// registration age: operators that plug in a WHOIS-backed lookup
	// (whois.go) can override with a real registration date.
	firstSeen map[string]time.Time
	// nowFunc is a clock hook for tests; defaults to time.Now.
	nowFunc func() time.Time
}

// domainCounters is the raw signal counter block per observed
// subject domain.
type domainCounters struct {
	HandshakesCompleted int64
	HandshakesRejected  int64
	EnvelopesAccepted   int64
	EnvelopesRejected   int64
	AbuseReports        int64
}

// NewObservationStore returns an empty ObservationStore. Pass a
// non-nil now hook to override the wall clock in tests.
func NewObservationStore(now func() time.Time) *ObservationStore {
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &ObservationStore{
		domains:   map[string]*domainCounters{},
		firstSeen: map[string]time.Time{},
		nowFunc:   now,
	}
}

// RecordHandshake records the outcome of one handshake attempt with
// the given subject domain. ok=true increments HandshakesCompleted;
// ok=false increments HandshakesRejected.
func (s *ObservationStore) RecordHandshake(domain string, ok bool) {
	if s == nil {
		return
	}
	c := s.touchDomain(domain)
	if ok {
		c.HandshakesCompleted++
	} else {
		c.HandshakesRejected++
	}
}

// RecordEnvelope records the outcome of one envelope delivery attempt
// from the given subject domain. accepted=true increments
// EnvelopesAccepted; accepted=false increments EnvelopesRejected.
func (s *ObservationStore) RecordEnvelope(domain string, accepted bool) {
	if s == nil {
		return
	}
	c := s.touchDomain(domain)
	if accepted {
		c.EnvelopesAccepted++
	} else {
		c.EnvelopesRejected++
	}
}

// RecordAbuseReport records one abuse report filed against the given
// subject domain. The caller is expected to have verified the report's
// signature and authorization before calling; the store does not
// filter.
func (s *ObservationStore) RecordAbuseReport(domain string) {
	if s == nil {
		return
	}
	c := s.touchDomain(domain)
	c.AbuseReports++
}

// Metrics returns a snapshot of the current counters for the given
// domain as a reputation.Metrics struct, suitable for inclusion in a
// published Observation. Returns a zero-value Metrics for unknown
// domains.
func (s *ObservationStore) Metrics(domain string) Metrics {
	if s == nil {
		return Metrics{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.domains[normalize(domain)]
	if c == nil {
		return Metrics{}
	}
	return Metrics{
		EnvelopesReceived:   c.EnvelopesAccepted + c.EnvelopesRejected,
		EnvelopesRejected:   c.EnvelopesRejected,
		AbuseReports:        c.AbuseReports,
		HandshakesCompleted: c.HandshakesCompleted,
		HandshakesRejected:  c.HandshakesRejected,
	}
}

// Score is the derived reputation verdict for a domain. It combines
// the raw counters and a simple age proxy into a rate-of-abuse value
// and an Assessment.
type Score struct {
	// Domain is the subject this score describes.
	Domain string

	// TotalEnvelopes is EnvelopesAccepted + EnvelopesRejected.
	TotalEnvelopes int64

	// AbuseRate is AbuseReports / TotalEnvelopes in the range [0, 1].
	// Zero when TotalEnvelopes is zero.
	AbuseRate float64

	// RejectRate is EnvelopesRejected / TotalEnvelopes in [0, 1].
	// Zero when TotalEnvelopes is zero.
	RejectRate float64

	// HandshakeRejectRate is HandshakesRejected / (HandshakesCompleted + HandshakesRejected).
	// Zero when no handshakes have been observed.
	HandshakeRejectRate float64

	// FirstSeen is the first time any signal was recorded for this
	// domain. Zero if the domain has not been observed.
	FirstSeen time.Time

	// AgeDays is the whole-day difference between now and FirstSeen,
	// or -1 if FirstSeen is zero.
	AgeDays int

	// Assessment is the summary classification derived from the
	// counters per REPUTATION.md §4.6.
	Assessment Assessment
}

// Score computes the current Score for the given subject domain.
// Unknown domains return a zero-value Score with Assessment set to
// AssessmentNeutral (the "insufficient data" outcome per §4.6).
//
// The scoring curve is intentionally simple — operators with richer
// policies should treat Score as raw input and run their own
// classifier. The defaults are:
//
//   - AbuseRate ≥ 0.05 OR RejectRate ≥ 0.50 → AssessmentHostile
//   - AbuseRate ≥ 0.01 OR RejectRate ≥ 0.20 → AssessmentSuspicious
//   - AbuseRate == 0 AND RejectRate < 0.05 AND TotalEnvelopes ≥ 100 → AssessmentTrusted
//   - Otherwise → AssessmentNeutral
func (s *ObservationStore) Score(domain string) Score {
	if s == nil {
		return Score{Domain: domain, Assessment: AssessmentNeutral, AgeDays: -1}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	d := normalize(domain)
	c := s.domains[d]
	firstSeen := s.firstSeen[d]
	score := Score{Domain: domain, FirstSeen: firstSeen, AgeDays: -1}
	if !firstSeen.IsZero() {
		score.AgeDays = int(s.nowFunc().Sub(firstSeen).Hours() / 24)
	}
	if c == nil {
		score.Assessment = AssessmentNeutral
		return score
	}
	total := c.EnvelopesAccepted + c.EnvelopesRejected
	score.TotalEnvelopes = total
	if total > 0 {
		score.AbuseRate = float64(c.AbuseReports) / float64(total)
		score.RejectRate = float64(c.EnvelopesRejected) / float64(total)
	}
	if hs := c.HandshakesCompleted + c.HandshakesRejected; hs > 0 {
		score.HandshakeRejectRate = float64(c.HandshakesRejected) / float64(hs)
	}
	score.Assessment = classify(score)
	return score
}

// classify is the default scoring curve. Extracted so tests can
// exercise it without going through the full ObservationStore.
func classify(s Score) Assessment {
	const (
		hostileAbuseRate      = 0.05
		hostileRejectRate     = 0.50
		suspiciousAbuseRate   = 0.01
		suspiciousRejectRate  = 0.20
		trustedMinEnvelopes   = 100
		trustedMaxRejectRate  = 0.05
	)
	if s.AbuseRate >= hostileAbuseRate || s.RejectRate >= hostileRejectRate {
		return AssessmentHostile
	}
	if s.AbuseRate >= suspiciousAbuseRate || s.RejectRate >= suspiciousRejectRate {
		return AssessmentSuspicious
	}
	if s.TotalEnvelopes >= trustedMinEnvelopes && s.AbuseRate == 0 && s.RejectRate < trustedMaxRejectRate {
		return AssessmentTrusted
	}
	return AssessmentNeutral
}

// Reset clears all counters for the given domain. Intended for tests
// and for operator-driven manual overrides.
func (s *ObservationStore) Reset(domain string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	d := normalize(domain)
	delete(s.domains, d)
	delete(s.firstSeen, d)
}

// Len returns the number of domains with at least one recorded signal.
func (s *ObservationStore) Len() int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.domains)
}

// touchDomain returns the per-domain counter block for domain,
// allocating it (and recording first-seen) on first access.
func (s *ObservationStore) touchDomain(domain string) *domainCounters {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := normalize(domain)
	c, ok := s.domains[d]
	if !ok {
		c = &domainCounters{}
		s.domains[d] = c
		s.firstSeen[d] = s.nowFunc()
	}
	return c
}

// normalize lowercases a domain name so counters don't split on case
// mismatches. Real DNS is case-insensitive; user input typically is
// not.
func normalize(domain string) string { return strings.ToLower(strings.TrimSpace(domain)) }

// ComputeGossipHash is retained as a stub for future §5 work. The
// full trust gossip publication format requires canonical observation
// records and publisher-domain signing, neither of which are in scope
// for this milestone.
//
// TODO(REPUTATION.md §5): implement once the observation record wire
// format has a canonicalizer.
func ComputeGossipHash(domain string, observations []Observation) (*GossipHash, error) {
	_, _ = domain, observations
	return nil, nil
}
