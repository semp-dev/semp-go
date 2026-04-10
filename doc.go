// Package semp is the root of the semp-go module. It defines the types and
// constants that are shared across every other package in the module: the
// protocol version, the machine-readable reason codes that govern handshake
// and envelope rejection, the acknowledgment outcomes returned at the
// delivery layer, the submission status values returned to clients, and the
// structured error type that all SEMP failures funnel through.
//
// This package intentionally has no internal dependencies. Every subpackage
// in semp-go imports it, which means it must remain free of imports from
// elsewhere in the module to avoid cycles.
//
// Specification references:
//
//   - ERRORS.md     — the authoritative registry of every code defined here.
//   - DELIVERY.md §1 — the three protocol-level acknowledgment outcomes.
//   - CLIENT.md §6.3 — submission status values returned by the home server.
//   - DISCOVERY.md §4.6 — discovery status values returned by lookups.
//   - DESIGN.md §11 — RFC 2119 normative language used throughout the suite.
package semp
