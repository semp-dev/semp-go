package keys

import (
	"crypto/sha256"
	"encoding/hex"
)

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
// is the lowercase hex encoding of SHA-256(publicKey), 64 characters.
//
// Hex was chosen over base64 because hex is unambiguous about case and
// padding, which simplifies map key comparison in seal.brief_recipients.
// Implementations that prefer base64 fingerprints can derive them from the
// raw SHA-256 by re-encoding.
func Compute(publicKey []byte) Fingerprint {
	if len(publicKey) == 0 {
		return ""
	}
	sum := sha256.Sum256(publicKey)
	return Fingerprint(hex.EncodeToString(sum[:]))
}
