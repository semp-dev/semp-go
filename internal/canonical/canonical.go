package canonical

// Marshal returns the canonical JSON serialization of v.
//
// Canonicalization rules (ENVELOPE.md §4.3):
//
//  1. UTF-8 encoded JSON.
//  2. Object keys sorted lexicographically by their UTF-16 code unit values
//     at every level of nesting.
//  3. No insignificant whitespace (no spaces between tokens, no trailing
//     newline).
//  4. Numbers serialized in their shortest unambiguous form (RFC 8785
//     conventions are the intended target).
//  5. Strings escaped per RFC 8259, using the shortest legal escape.
//
// Marshal does not perform field elision. Callers that need to zero out
// `seal.signature` / `seal.session_mac` or strip `postmark.hop_count` from
// the canonical form should pass an Elider to MarshalWithElision.
//
// TODO(ENVELOPE.md §4.3): implement deterministic JSON canonicalization.
// Reference implementation candidates:
//   - github.com/gowebpki/jcs (RFC 8785 JSON Canonicalization Scheme)
//   - hand-rolled tokenizer to keep dependencies minimal
//
// The skeleton returns an empty byte slice and a nil error so that downstream
// stubs can compile against the intended signature.
func Marshal(v any) ([]byte, error) {
	_ = v
	return nil, nil
}

// Elider is a callback that lets a caller mutate a value before it is
// canonicalized. Elider is invoked exactly once on a deep copy of the input,
// allowing safe in-place mutation.
//
// The seal signer uses an Elider to set seal.signature and seal.session_mac
// to the empty string and to remove postmark.hop_count from the value before
// canonicalization, per ENVELOPE.md §4.3.
type Elider func(value any) error

// MarshalWithElision applies elide to a deep copy of v, then returns the
// canonical serialization of the modified copy.
//
// TODO(ENVELOPE.md §4.3): implement deep copy + elision pipeline.
func MarshalWithElision(v any, elide Elider) ([]byte, error) {
	_ = v
	_ = elide
	return nil, nil
}

// Hash returns SHA-256(b). It is provided here as a convenience because
// nearly every caller of Marshal needs the hash of the canonical bytes
// (confirmation hash, seal session MAC input, discovery signature digest).
//
// TODO(VECTORS.md §3): replace with crypto/sha256.Sum256 once the canonical
// pipeline is real.
func Hash(b []byte) []byte {
	_ = b
	return nil
}
