// Package reputation implements SEMP's domain-based reputation system:
// observation records that operators publish about other domains, the
// trust gossip hash that summarizes a domain's history, the proof-of-work
// challenge issued during the handshake, abuse report categories, and the
// WHOIS-based domain age signal used for new-domain caution.
//
// Reputation is observable, transferable, and cryptographically verifiable
// — IP addresses are not part of the trust model. Operators decide how to
// weight signals through configurable policy.
//
// Specification reference: REPUTATION.md.
package reputation
