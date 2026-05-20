package reputation

// Publication eligibility per REPUTATION.md §4.6.2 /
// draft-gokce-semp-delivery §11.7. A server SHOULD NOT publish an
// observation about a subject domain unless it has directly
// observed enough interaction with the subject to back the
// metrics. The two thresholds:
//
//   - At least MinPublishVolumeEnvelopes envelopes (or equivalent
//     handshake attempts) observed during the window.
//   - At least one metrics field non-zero. Records with uniformly
//     zero metrics MUST NOT be published.
//
// These are publisher-side gates. A consumer that receives an
// observation that violates either rule SHOULD treat the
// publishing observer as a candidate for observation_record_abuse
// reporting per §3.4.

// MinPublishVolumeEnvelopes is the §4.6.2 RECOMMENDED minimum
// number of envelopes (or handshake attempts) the observer should
// have observed during the window before publishing an observation
// about a subject domain.
const MinPublishVolumeEnvelopes = 16

// MeetsPublishVolume reports whether the metrics carry at least
// MinPublishVolumeEnvelopes envelopes (post-bucketing). Observers
// applying the bucketing rule round up to the next power of two,
// so any non-zero metric above 0 will be at least 1; this check
// requires the post-bucketing total to clear the 16-envelope
// threshold.
//
// Counts considered in the volume total: EnvelopesReceived,
// HandshakesCompleted, HandshakesRejected. The spec treats
// handshake attempts as equivalent observation events.
func MeetsPublishVolume(m Metrics) bool {
	total := m.EnvelopesReceived + m.HandshakesCompleted + m.HandshakesRejected
	return total >= MinPublishVolumeEnvelopes
}

// AllMetricsZero reports whether every metric field is zero and
// the abuse_categories list is empty. The §4.6.2 rule says
// records with uniformly zero metrics MUST NOT be published.
func AllMetricsZero(m Metrics) bool {
	return m.EnvelopesReceived == 0 &&
		m.EnvelopesRejected == 0 &&
		m.AbuseReports == 0 &&
		m.UniqueSendersObserved == 0 &&
		m.HandshakesCompleted == 0 &&
		m.HandshakesRejected == 0 &&
		len(m.AbuseCategories) == 0
}

// EligibleForPublication is the convenience predicate: returns
// true when the metrics satisfy both the volume threshold and the
// non-all-zero rule. Publishers SHOULD gate every outgoing
// observation on this check.
func EligibleForPublication(m Metrics) bool {
	return MeetsPublishVolume(m) && !AllMetricsZero(m)
}
