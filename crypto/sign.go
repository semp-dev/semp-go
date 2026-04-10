package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
)

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

// signerEd25519 is the Ed25519 signature primitive used by both currently
// defined SEMP suites (ENVELOPE.md §7.3.1).
type signerEd25519 struct{}

// NewSignerEd25519 returns the standard Ed25519 signer. The returned value
// has no internal state and is safe for concurrent use.
func NewSignerEd25519() Signer { return signerEd25519{} }

func (signerEd25519) PublicKeySize() int { return ed25519.PublicKeySize }
func (signerEd25519) SignatureSize() int { return ed25519.SignatureSize }

// Sign produces an Ed25519 signature. privateKey MUST be ed25519.PrivateKey
// (64 bytes: seed || public). Sign returns an error if the key is the
// wrong length so that callers do not silently ship a malformed signature.
func (signerEd25519) Sign(privateKey, message []byte) ([]byte, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("crypto: invalid Ed25519 private key size")
	}
	return ed25519.Sign(ed25519.PrivateKey(privateKey), message), nil
}

// Verify checks an Ed25519 signature in constant time over publicKey.
func (signerEd25519) Verify(publicKey, message, signature []byte) error {
	if len(publicKey) != ed25519.PublicKeySize {
		return errors.New("crypto: invalid Ed25519 public key size")
	}
	if len(signature) != ed25519.SignatureSize {
		return errors.New("crypto: invalid Ed25519 signature size")
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKey), message, signature) {
		return errors.New("crypto: Ed25519 signature verification failed")
	}
	return nil
}

// GenerateKeyPair produces a fresh Ed25519 key pair using crypto/rand.
func (signerEd25519) GenerateKeyPair() ([]byte, []byte, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return []byte(pub), []byte(priv), nil
}
