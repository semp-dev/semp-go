// Package discovery implements SEMP server and protocol discovery: DNS
// SRV/TXT lookup, well-known URI fallback, the SEMP_DISCOVERY lookup
// protocol, the MX-record fallback used to detect SMTP-only legacy
// recipients, partition resolution for large domains, and per-result
// caching with TTL enforcement.
//
// Discovery is always performed by the sender's server on behalf of the
// sending user. Clients never perform cross-domain discovery directly
// (DISCOVERY.md §1.1).
//
// Specification reference: DISCOVERY.md.
package discovery
