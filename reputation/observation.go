package reputation

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/semp-dev/semp-go/extensions"
	"github.com/semp-dev/semp-go/internal/canonical"
	"github.com/semp-dev/semp-go/keys"
)

// Wire-level type discriminators used in SEMP_TRUST_OBSERVATION and
// SEMP_TRUST_OBSERVATIONS messages.
const (
	// ObservationType is the wire-level `type` field of a single
	// signed observation record (REPUTATION.md §4.2).
	ObservationType = "SEMP_TRUST_OBSERVATION"

	// ObservationsType is the wire-level `type` field of the
	// publication envelope that carries a list of observations
	// (REPUTATION.md §5.1).
	ObservationsType = "SEMP_TRUST_OBSERVATIONS"

	// ObservationVersion is the SEMP protocol version this
	// implementation writes into observation records and publication
	// envelopes.
	ObservationVersion = "1.0.0"
)

// Observation is a single observation record published by one
// operator about another domain. Its JSON layout matches
// REPUTATION.md §4.2 exactly, so the Go struct can marshal/unmarshal
// through encoding/json without a custom shim and round-trip through
// the canonical serializer for signing.
type Observation struct {
	// Type is the wire discriminator. MUST be ObservationType.
	Type string `json:"type"`

	// Version is the SEMP protocol version.
	Version string `json:"version"`

	// ID is the unique observation identifier. ULID RECOMMENDED
	// (REPUTATION.md §4.3).
	ID string `json:"id"`

	// Observer is the domain of the server making the observation.
	Observer string `json:"observer"`

	// Subject is the domain being observed.
	Subject string `json:"subject"`

	// Window is the time window the observation covers.
	// REPUTATION.md §4.4 recommends windows of 30 days or less.
	Window Window `json:"window"`

	// Metrics is the quantitative payload per §4.5.
	Metrics Metrics `json:"metrics"`

	// Assessment is the summary classification per §4.6.
	Assessment Assessment `json:"assessment"`

	// EvidenceAvailable reports whether verifiable evidence is
	// available for this observation.
	EvidenceAvailable bool `json:"evidence_available"`

	// EvidenceURI is the URL where evidence can be fetched when
	// EvidenceAvailable is true.
	EvidenceURI string `json:"evidence_uri,omitempty"`

	// Timestamp is the ISO 8601 UTC time the observation was
	// published. Distinct from Window.End.
	Timestamp time.Time `json:"timestamp"`

	// Expires is the hard expiry of this observation record. Per
	// §4.4 an expired observation MUST be treated as absent.
	Expires time.Time `json:"expires"`

	// Signature is the publisher's signature over the canonical
	// form of this observation with signature.value elided.
	Signature keys.PublicationSignature `json:"signature"`

	// Extensions is the observer-defined extensions map. Always
	// emitted (even when empty) so the canonical bytes are stable.
	Extensions extensions.Map `json:"extensions"`
}

// Window is the nested time-window object from REPUTATION.md §4.2.
type Window struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// Metrics is the quantitative payload of an Observation per
// REPUTATION.md §4.5.
type Metrics struct {
	EnvelopesReceived     int64           `json:"envelopes_received"`
	EnvelopesRejected     int64           `json:"envelopes_rejected"`
	AbuseReports          int64           `json:"abuse_reports"`
	AbuseCategories       []AbuseCategory `json:"abuse_categories,omitempty"`
	UniqueSendersObserved int64           `json:"unique_senders_observed,omitempty"`
	HandshakesCompleted   int64           `json:"handshakes_completed,omitempty"`
	HandshakesRejected    int64           `json:"handshakes_rejected,omitempty"`
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

// GossipHash is the publishable hash summary of a domain's
// observation history from REPUTATION.md §5. It lets two servers
// compare their observation sets compactly without exchanging the
// full record body.
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
	// AbuseCategories records one entry per abuse report so the
	// published observation can carry the per-report category list
	// required by REPUTATION.md §4.5 ("abuse_categories: List of
	// abuse categories reported. May contain duplicates.").
	AbuseCategories []AbuseCategory
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
// subject domain with the stated category. The caller is expected to
// have verified the report's authenticity and any embedded
// disclosure authorization before calling; the store does not
// validate. category may be empty — an empty category is recorded as
// a count increment without a corresponding abuse_categories entry,
// which matches the spec allowance that abuse_categories is optional.
func (s *ObservationStore) RecordAbuseReport(domain string, category AbuseCategory) {
	if s == nil {
		return
	}
	c := s.touchDomain(domain)
	c.AbuseReports++
	if category != "" {
		c.AbuseCategories = append(c.AbuseCategories, category)
	}
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
	m := Metrics{
		EnvelopesReceived:   c.EnvelopesAccepted + c.EnvelopesRejected,
		EnvelopesRejected:   c.EnvelopesRejected,
		AbuseReports:        c.AbuseReports,
		HandshakesCompleted: c.HandshakesCompleted,
		HandshakesRejected:  c.HandshakesRejected,
	}
	if len(c.AbuseCategories) > 0 {
		// Copy the slice so the caller cannot mutate the store's
		// backing array.
		m.AbuseCategories = append([]AbuseCategory(nil), c.AbuseCategories...)
	}
	return m
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
		hostileAbuseRate     = 0.05
		hostileRejectRate    = 0.50
		suspiciousAbuseRate  = 0.01
		suspiciousRejectRate = 0.20
		trustedMinEnvelopes  = 100
		trustedMaxRejectRate = 0.05
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

// -----------------------------------------------------------------------------
// GossipHash
// -----------------------------------------------------------------------------

// ComputeGossipHash combines a list of observations into a single
// GossipHash suitable for publication per REPUTATION.md §5. The hash
// is SHA-256 over the canonical serialization of a small JSON wrapper
// that contains the subject domain plus the observation IDs and
// timestamps in canonical (sorted) order. Two servers with the same
// observation set produce byte-identical gossip hashes, so they can
// cheaply detect divergence.
//
// The hash covers only the observation IDs and their timestamps, not
// the full metrics body, so a comparison remains meaningful even when
// two observers report the same underlying events with slightly
// different metrics. An operator that wants a full-body comparison
// should walk observations themselves.
//
// Returns an error if domain is empty. An empty observations slice is
// allowed and produces a hash over just the domain — a legitimate
// "I have no observations for this subject" publication.
func ComputeGossipHash(domain string, observations []Observation) (*GossipHash, error) {
	if strings.TrimSpace(domain) == "" {
		return nil, errors.New("reputation: gossip hash requires a domain")
	}
	// Collect (id, timestamp) pairs in a stable order so two
	// observers who publish the same observation set produce the
	// same hash regardless of iteration order.
	type entry struct {
		ID        string    `json:"id"`
		Timestamp time.Time `json:"timestamp"`
	}
	entries := make([]entry, 0, len(observations))
	for _, o := range observations {
		entries = append(entries, entry{ID: o.ID, Timestamp: o.Timestamp.UTC()})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].ID != entries[j].ID {
			return entries[i].ID < entries[j].ID
		}
		return entries[i].Timestamp.Before(entries[j].Timestamp)
	})
	payload := struct {
		Domain  string  `json:"domain"`
		Entries []entry `json:"entries"`
	}{
		Domain:  normalize(domain),
		Entries: entries,
	}
	canon, err := canonical.Marshal(payload)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(canon)
	return &GossipHash{
		Domain:    normalize(domain),
		Hash:      hex.EncodeToString(sum[:]),
		Algorithm: "sha256",
		AsOf:      time.Now().UTC(),
	}, nil
}
