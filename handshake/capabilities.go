package handshake

import (
	"errors"

	"semp.dev/semp-go/crypto"
)

// NegotiateCapabilities returns the agreed session parameters from the
// client's offered capabilities and the server's accepted set, preferring
// the post-quantum hybrid suite when both peers support it (HANDSHAKE.md
// §6.4, SESSION.md §4.3).
//
// The returned Negotiated MUST be honored verbatim by both parties for the
// duration of the session.
//
// Selection rules:
//
//   - Encryption algorithm: walk crypto.Negotiate's preference order (PQ
//     hybrid first, then baseline). The strongest mutually supported and
//     implemented suite wins.
//   - Compression: walk a fixed preference order (zstd, gzip, none). If the
//     server has no compression preferences, "none" is selected.
//   - Features: the intersection of offered.Features and accepted.Features,
//     in the order they appear in offered.
//   - max_envelope_size / max_batch_size: the smaller of the two values when
//     both sides advertise one; the side that advertises it when only one
//     does; zero (omitted) when neither does.
//
// A negotiation failure (no mutually supported encryption suite) returns an
// error so the caller can respond with a `policy_violation` rejection.
func NegotiateCapabilities(offered, accepted Capabilities) (Negotiated, error) {
	suiteIDs := func(s []string) []crypto.SuiteID {
		out := make([]crypto.SuiteID, 0, len(s))
		for _, v := range s {
			out = append(out, crypto.SuiteID(v))
		}
		return out
	}
	chosen, err := crypto.Negotiate(suiteIDs(offered.EncryptionAlgorithms), suiteIDs(accepted.EncryptionAlgorithms))
	if err != nil {
		return Negotiated{}, err
	}

	compression := negotiateCompression(offered.Compression, accepted.Compression)
	features := intersectStrings(offered.Features, accepted.Features)

	maxSize := offered.MaxEnvelopeSize
	if accepted.MaxEnvelopeSize > 0 && (maxSize == 0 || accepted.MaxEnvelopeSize < maxSize) {
		maxSize = accepted.MaxEnvelopeSize
	}
	maxBatch := offered.MaxBatchSize
	if accepted.MaxBatchSize > 0 && (maxBatch == 0 || accepted.MaxBatchSize < maxBatch) {
		maxBatch = accepted.MaxBatchSize
	}

	return Negotiated{
		EncryptionAlgorithm: string(chosen),
		Compression:         compression,
		Features:            features,
		MaxEnvelopeSize:      maxSize,
		MaxBatchSize:        maxBatch,
	}, nil
}

// negotiateCompression picks the strongest mutually supported compression
// algorithm. Preference order: zstd > gzip > none. "none" is the universal
// fallback that every implementation MUST support; if the offered or accepted
// list does not include any algorithm at all we still return "none".
func negotiateCompression(offered, accepted []string) string {
	preference := []string{"zstd", "gzip", "none"}
	want := make(map[string]bool, len(accepted))
	for _, c := range accepted {
		want[c] = true
	}
	have := make(map[string]bool, len(offered))
	for _, c := range offered {
		have[c] = true
	}
	for _, p := range preference {
		if want[p] && have[p] {
			return p
		}
	}
	return "none"
}

// intersectStrings returns the elements of a that also appear in b, in the
// order they appear in a. Used for capability feature intersection.
func intersectStrings(a, b []string) []string {
	if len(a) == 0 || len(b) == 0 {
		return []string{}
	}
	set := make(map[string]bool, len(b))
	for _, v := range b {
		set[v] = true
	}
	out := make([]string, 0, len(a))
	for _, v := range a {
		if set[v] {
			out = append(out, v)
		}
	}
	return out
}

// DefaultClientCapabilities returns a Capabilities value that advertises
// the algorithms a baseline conformant client supports (ENVELOPE.md §7.3.2).
func DefaultClientCapabilities() Capabilities {
	return Capabilities{
		EncryptionAlgorithms: []string{
			string(crypto.SuiteIDPQKyber768X25519),
			string(crypto.SuiteIDX25519ChaCha20Poly1305),
		},
		Compression: []string{"none"},
		Features:    []string{},
	}
}

// DefaultServerCapabilities returns a Capabilities value that mirrors what a
// baseline conformant server accepts. Used by Server when constructing the
// negotiated parameters during OnInit.
func DefaultServerCapabilities() Capabilities {
	return Capabilities{
		EncryptionAlgorithms: []string{
			string(crypto.SuiteIDPQKyber768X25519),
			string(crypto.SuiteIDX25519ChaCha20Poly1305),
		},
		Compression: []string{"none"},
		Features:    []string{},
	}
}

// errNoMutualSuite is returned by NegotiateCapabilities when no encryption
// suite is mutually supported. Exported via errors.Is checks would require a
// sentinel; for now the underlying crypto.Negotiate error is sufficient.
var errNoMutualSuite = errors.New("handshake: no mutually supported encryption suite")
