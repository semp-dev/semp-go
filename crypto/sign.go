package crypto

// Signer is a digital signature primitive. Both currently defined SEMP
// suites use Ed25519 (ENVELOPE.md §7.3.1) for:
//
//   - seal.signature (envelope domain key signature)
//   - server_signature on every signed handshake message
//   - identity_signature inside the encrypted identity proof
//   - the signature field on signed key responses, discovery responses,
//     observation records, abuse reports, and revocation records
//
// Long-term keys MUST never be used as KEM private keys; the Signer
// abstraction is the only path to a long-term private key.
type Signer interface {
	// PublicKeySize returns the public key length in bytes (32 for Ed25519).
	PublicKeySize() int

	// SignatureSize returns the signature length in bytes (64 for Ed25519).
	SignatureSize() int

	// Sign produces a signature over message using privateKey.
	Sign(privateKey, message []byte) ([]byte, error)

	// Verify checks signature over message against publicKey. It MUST run
	// in constant time with respect to publicKey to avoid leaking key bits
	// through timing side channels.
	Verify(publicKey, message, signature []byte) error

	// GenerateKeyPair produces a fresh long-term key pair. Used during
	// domain key generation, identity key generation, and device key
	// generation. Callers are responsible for persisting the private key
	// per the storage rules in KEY.md §9.
	GenerateKeyPair() (publicKey, privateKey []byte, err error)
}
