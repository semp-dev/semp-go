package crypto

import (
	"crypto/rand"
	"errors"

	"golang.org/x/crypto/chacha20poly1305"
)

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

// aeadChaCha20Poly1305 is the IETF ChaCha20-Poly1305 AEAD used by both
// currently defined SEMP suites (ENVELOPE.md §7.3.1).
type aeadChaCha20Poly1305 struct{}

// NewAEADChaCha20Poly1305 returns the standard ChaCha20-Poly1305 AEAD. The
// returned value has no internal state and is safe for concurrent use; the
// per-call cipher.AEAD is constructed inside Seal/Open from the supplied key.
func NewAEADChaCha20Poly1305() AEAD { return aeadChaCha20Poly1305{} }

func (aeadChaCha20Poly1305) KeySize() int   { return chacha20poly1305.KeySize }
func (aeadChaCha20Poly1305) NonceSize() int { return chacha20poly1305.NonceSize }
func (aeadChaCha20Poly1305) Overhead() int  { return chacha20poly1305.Overhead }

// Seal implements AEAD. The dst buffer is allocated fresh; SEMP does not
// reuse output buffers, so the simpler API is appropriate.
func (a aeadChaCha20Poly1305) Seal(key, nonce, plaintext, ad []byte) ([]byte, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, errors.New("crypto: invalid ChaCha20-Poly1305 key size")
	}
	c, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != c.NonceSize() {
		return nil, errors.New("crypto: invalid ChaCha20-Poly1305 nonce size")
	}
	return c.Seal(nil, nonce, plaintext, ad), nil
}

// Open implements AEAD.
func (a aeadChaCha20Poly1305) Open(key, nonce, ciphertext, ad []byte) ([]byte, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, errors.New("crypto: invalid ChaCha20-Poly1305 key size")
	}
	c, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != c.NonceSize() {
		return nil, errors.New("crypto: invalid ChaCha20-Poly1305 nonce size")
	}
	return c.Open(nil, nonce, ciphertext, ad)
}

// FreshKey returns a cryptographically random AEAD key of the size required
// by aead. Used by senders to generate K_brief and K_enclosure on each
// envelope (ENVELOPE.md §7.1 step 2).
func FreshKey(aead AEAD) ([]byte, error) {
	if aead == nil {
		return nil, errors.New("crypto: nil AEAD")
	}
	k := make([]byte, aead.KeySize())
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	return k, nil
}

// FreshNonce returns a cryptographically random nonce of the size required
// by aead. SEMP uses fresh keys per envelope, so a random nonce is safe;
// callers that re-use a single key for many encryptions SHOULD prefer a
// counter-based scheme to avoid the (small but non-zero) probability of
// random collision.
func FreshNonce(aead AEAD) ([]byte, error) {
	if aead == nil {
		return nil, errors.New("crypto: nil AEAD")
	}
	n := make([]byte, aead.NonceSize())
	if _, err := rand.Read(n); err != nil {
		return nil, err
	}
	return n, nil
}
