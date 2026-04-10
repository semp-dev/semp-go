package crypto

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
	// remote party can decapsulate using its private key. Used by the
	// initiator side of the hybrid Kyber768 path.
	Encapsulate(remotePublic []byte) (sharedSecret, ciphertext []byte, err error)

	// Decapsulate recovers the shared secret from a ciphertext using the
	// holder's private key. Used by the responder side of the Kyber768 path.
	Decapsulate(ciphertext, localPrivate []byte) (sharedSecret []byte, err error)

	// Agree performs a Diffie-Hellman style key agreement using the local
	// private key and the remote public key. Used directly for the X25519
	// component of the hybrid suite, and as the sole agreement mechanism
	// for the baseline suite.
	Agree(localPrivate, remotePublic []byte) (sharedSecret []byte, err error)
}

// HybridIKM concatenates a Kyber-derived shared secret and an X25519-derived
// shared secret into the input keying material consumed by HKDF-Extract for
// the post-quantum hybrid suite.
//
// Order is fixed: K_kyber first, K_x25519 second (SESSION.md §4.1).
//
// TODO(SESSION.md §4.1): implement; the skeleton returns nil so callers can
// type-check the wiring.
func HybridIKM(kyberSecret, x25519Secret []byte) []byte {
	_, _ = kyberSecret, x25519Secret
	return nil
}
