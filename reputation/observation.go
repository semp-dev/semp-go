package reputation

import (
	"time"

	"github.com/semp-dev/semp-go/keys"
)

// Observation is a single observation record published by one operator
// about another domain. Observations are signed by the publisher and form
// the input data behind the trust gossip hash.
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

	// MessagesAccepted, MessagesRejected, AbuseReports are the headline
	// metrics. Operators MUST NOT fabricate or inflate these values
	// (REPUTATION.md §4.5).
	MessagesAccepted int64 `json:"messages_accepted"`
	MessagesRejected int64 `json:"messages_rejected"`
	AbuseReports     int64 `json:"abuse_reports"`

	// Signature is the publisher's signature over the canonical form of
	// this observation (with Signature itself elided).
	Signature keys.PublicationSignature `json:"signature"`
}

// GossipHash is the trust gossip hash representation defined in
// REPUTATION.md §5: a publishable, hashed summary of a domain's
// observation history that other servers can compare against their own.
type GossipHash struct {
	// Domain is the domain being summarized.
	Domain string `json:"domain"`

	// Hash is the hex-encoded hash value.
	Hash string `json:"hash"`

	// Algorithm is the hash algorithm identifier (e.g. "sha256").
	Algorithm string `json:"algorithm"`

	// AsOf is the time at which this snapshot was computed.
	AsOf time.Time `json:"as_of"`
}

// ComputeGossipHash combines a list of observations into a single GossipHash
// suitable for publication.
//
// TODO(REPUTATION.md §5): implement.
func ComputeGossipHash(domain string, observations []Observation) (*GossipHash, error) {
	_, _ = domain, observations
	return nil, nil
}
