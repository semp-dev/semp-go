package keys

// Fingerprint is the canonical key identifier used everywhere in SEMP.
// Per KEY.md §4.4, a fingerprint is computed as SHA-256 over the public key
// bytes and is exchanged as a base64 or hex-encoded string.
//
// Fingerprints are the only field used in seal.brief_recipients and
// seal.enclosure_recipients map keys, so they MUST be reproducible byte for
// byte across implementations.
type Fingerprint string

// String satisfies fmt.Stringer.
func (f Fingerprint) String() string { return string(f) }

// Compute returns the Fingerprint of the given public key bytes. The result
// is the lowercase hex encoding of SHA-256(publicKey).
//
// TODO(KEY.md §4.4): implement using crypto/sha256 and encoding/hex.
func Compute(publicKey []byte) Fingerprint {
	_ = publicKey
	return ""
}
