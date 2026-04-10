package crypto

// AEAD is an authenticated encryption with associated data primitive. Both
// SEMP suites use ChaCha20-Poly1305 for envelope brief and enclosure
// encryption, handshake message encryption, and identity proof encryption.
//
// SEMP does not nest AEAD operations: a fresh symmetric key is generated for
// every envelope (K_brief and K_enclosure) and consumed exactly once.
type AEAD interface {
	// KeySize returns the key length in bytes (32 for ChaCha20-Poly1305).
	KeySize() int

	// NonceSize returns the nonce length in bytes (12 for ChaCha20-Poly1305).
	NonceSize() int

	// Overhead returns the byte expansion produced by encryption (16 for
	// the Poly1305 authentication tag).
	Overhead() int

	// Seal encrypts plaintext under key with the given nonce and additional
	// authenticated data, returning ciphertext appended with the auth tag.
	// nonce MUST be unique per (key, plaintext) pair; reuse is catastrophic
	// for ChaCha20-Poly1305.
	Seal(key, nonce, plaintext, additionalData []byte) ([]byte, error)

	// Open decrypts ciphertext, verifying the authentication tag against
	// additionalData. Returns an error if authentication fails.
	Open(key, nonce, ciphertext, additionalData []byte) ([]byte, error)
}

// FreshKey returns a cryptographically random AEAD key of the size required
// by aead.
//
// TODO(ENVELOPE.md §7.1 step 2): implement using crypto/rand.Read once the
// real AEAD primitive is wired in.
func FreshKey(aead AEAD) ([]byte, error) {
	_ = aead
	return nil, nil
}

// FreshNonce returns a cryptographically random nonce of the size required
// by aead. Callers SHOULD prefer counter-based nonces for high-volume use
// to avoid the small but non-zero probability of random collision; FreshNonce
// is intended for one-shot encryptions where each key is used exactly once.
//
// TODO(ENVELOPE.md §7.1): implement.
func FreshNonce(aead AEAD) ([]byte, error) {
	_ = aead
	return nil, nil
}
