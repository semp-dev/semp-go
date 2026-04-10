package crypto

import (
	"crypto/rand"
	"errors"

	"golang.org/x/crypto/curve25519"
)

// KEM is a key encapsulation mechanism. SEMP uses KEMs only for ephemeral
// key agreement during the handshake; long-term keys never participate in
// KEM operations directly.
//
// For the post-quantum hybrid suite, the KEM is implemented as a concat-KDF
// over Kyber768 and X25519 outputs:
//
//	IKM = K_kyber || K_x25519
//
// This concatenation order is fixed (SESSION.md §4.1) and MUST NOT vary
// between implementations.
type KEM interface {
	// GenerateKeyPair produces a fresh ephemeral key pair. The private key
	// MUST be erased immediately after the shared secret is derived
	// (SESSION.md §2.2).
	GenerateKeyPair() (publicKey, privateKey []byte, err error)

	// Encapsulate produces a fresh shared secret and a ciphertext that the
	// remote party can decapsulate using its private key. For X25519,
	// "ciphertext" is the initiator's ephemeral public key.
	Encapsulate(remotePublic []byte) (sharedSecret, ciphertext []byte, err error)

	// Decapsulate recovers the shared secret from a ciphertext using the
	// holder's private key. For X25519, "ciphertext" is the initiator's
	// ephemeral public key.
	Decapsulate(ciphertext, localPrivate []byte) (sharedSecret []byte, err error)

	// Agree performs a Diffie-Hellman style key agreement using the local
	// private key and the remote public key. Used directly for the X25519
	// component of the hybrid suite, and as the sole agreement mechanism
	// for the baseline suite.
	Agree(localPrivate, remotePublic []byte) (sharedSecret []byte, err error)
}

// kemX25519 is the X25519 ephemeral key agreement used by the baseline
// suite and as one half of the post-quantum hybrid.
type kemX25519 struct{}

// NewKEMX25519 returns the X25519 KEM. The returned value has no internal
// state and is safe for concurrent use.
func NewKEMX25519() KEM { return kemX25519{} }

// GenerateKeyPair returns a fresh X25519 key pair.
func (kemX25519) GenerateKeyPair() ([]byte, []byte, error) {
	priv := make([]byte, curve25519.ScalarSize)
	if _, err := rand.Read(priv); err != nil {
		return nil, nil, err
	}
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		Zeroize(priv)
		return nil, nil, err
	}
	return pub, priv, nil
}

// Agree performs a single X25519 scalar multiplication.
func (kemX25519) Agree(localPriv, remotePub []byte) ([]byte, error) {
	if len(localPriv) != curve25519.ScalarSize {
		return nil, errors.New("crypto: invalid X25519 private key size")
	}
	if len(remotePub) != curve25519.PointSize {
		return nil, errors.New("crypto: invalid X25519 public key size")
	}
	return curve25519.X25519(localPriv, remotePub)
}

// Encapsulate generates an ephemeral key pair, performs DH against the
// remote public key, and returns (sharedSecret, ephemeralPublic). The
// ephemeralPublic is the "ciphertext" that the remote party feeds into
// Decapsulate. The ephemeral private key is erased before return.
func (k kemX25519) Encapsulate(remotePub []byte) (sharedSecret, ciphertext []byte, err error) {
	ephPub, ephPriv, err := k.GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}
	defer Zeroize(ephPriv)
	secret, err := k.Agree(ephPriv, remotePub)
	if err != nil {
		return nil, nil, err
	}
	return secret, ephPub, nil
}

// Decapsulate is symmetric to Encapsulate: the local party uses its private
// key and the remote ephemeral public key (received as the "ciphertext") to
// recover the same shared secret.
func (k kemX25519) Decapsulate(ciphertext, localPriv []byte) ([]byte, error) {
	return k.Agree(localPriv, ciphertext)
}

// HybridIKM concatenates a Kyber-derived shared secret and an X25519-derived
// shared secret into the input keying material consumed by HKDF-Extract for
// the post-quantum hybrid suite.
//
// Order is fixed: K_kyber first, K_x25519 second (SESSION.md §4.1).
//
// HybridIKM is a pure concatenation; no hashing is performed here. The
// downstream HKDF-Extract is what binds the two halves into the session
// secret.
func HybridIKM(kyberSecret, x25519Secret []byte) []byte {
	out := make([]byte, 0, len(kyberSecret)+len(x25519Secret))
	out = append(out, kyberSecret...)
	out = append(out, x25519Secret...)
	return out
}
