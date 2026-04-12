package seal

import (
	"encoding/base64"
	"errors"
	"fmt"

	"semp.dev/semp-go/crypto"
	"semp.dev/semp-go/keys"
)

// Wrapper wraps and unwraps the per-envelope symmetric keys (K_brief and
// K_enclosure) under recipient public keys.
//
// Wire format (working interpretation; see WrapFormat below):
//
//	wrapped = base64( ephemeral_public_key || aead_ciphertext )
//
// where:
//
//   - ephemeral_public_key is a 32-byte X25519 public key generated fresh
//     for each Wrap call;
//   - aead_ciphertext is ChaCha20-Poly1305(wrap_key, zero_nonce, K, ad=recipient_pub),
//     yielding 32 + 16 = 48 bytes for a 32-byte symmetric key K;
//   - wrap_key = HKDF-SHA-512(ikm=ephemeral_dh_secret, salt=ephemeral_pub||recipient_pub,
//     info="SEMP-v1-wrap", length=32);
//   - ephemeral_dh_secret = X25519(ephemeral_priv, recipient_pub).
//
// Total size: 32 + 48 = 80 bytes; base64-encoded: 108 characters with
// padding.
//
// The construction is HPKE-Base style (RFC 9180 §6.1) with X25519, HKDF,
// and ChaCha20-Poly1305 as the underlying primitives. The zero nonce is
// safe because wrap_key is derived fresh for every call from a unique
// ephemeral key.
//
// TODO(ENVELOPE.md §7): the spec defines the encryption *flow* in §7.1
// but does not pin the exact wrap byte format. This implementation is
// the working interpretation. When the spec formalizes the format —
// likely as full RFC 9180 HPKE-Base with an explicit context string —
// this code will need to align. Cross-implementation interop is the
// gating criterion.
type Wrapper interface {
	// Wrap encrypts symmetricKey under recipientPublicKey and returns the
	// base64-encoded wrapped result.
	Wrap(recipientPublicKey, symmetricKey []byte) (string, error)

	// Unwrap decrypts the wrapped symmetric key using the recipient's
	// private key and returns the raw symmetric key bytes.
	Unwrap(recipientPrivateKey []byte, wrapped string) ([]byte, error)
}

// WrapInfo is the HKDF info context used by NewWrapper. It is exported so
// other implementations can derive interoperable wrap_keys.
const WrapInfo = "SEMP-v1-wrap"

// NewWrapper returns a Wrapper backed by X25519 + the given suite's KDF
// and AEAD. The wrap operation is always X25519-based regardless of
// the suite because long-term recipient encryption keys (the keys
// stored in the keys.Store and referenced by
// seal.brief_recipients / seal.enclosure_recipients) are X25519
// regardless of whether the current session runs under SuiteBaseline
// or the post-quantum hybrid SuitePQ. The Kyber768 component only
// protects ephemeral session key agreement during the handshake; per-
// recipient seal wrapping operates on stable published keys and stays
// X25519.
//
// The same wrapper instance is safe for concurrent use across
// goroutines because it carries no state — every Wrap/Unwrap call
// generates or consumes a fresh ephemeral key pair.
func NewWrapper(suite crypto.Suite) Wrapper {
	if suite == nil {
		return nil
	}
	return &wrapper{suite: suite}
}

type wrapper struct {
	suite crypto.Suite
}

// wrapKEM is the KEM used by the seal layer for per-recipient key
// wrapping. Always X25519, regardless of the session suite, because
// long-term recipient encryption keys are X25519 — see NewWrapper's
// doc comment for the rationale.
func (w *wrapper) wrapKEM() crypto.KEM {
	return crypto.NewKEMX25519()
}

// Wrap encrypts symmetricKey under recipientPublicKey using HPKE-Base style
// ephemeral X25519 + HKDF-SHA-512 + ChaCha20-Poly1305.
func (w *wrapper) Wrap(recipientPublicKey, symmetricKey []byte) (string, error) {
	if len(recipientPublicKey) == 0 {
		return "", errors.New("seal: empty recipient public key")
	}
	if len(symmetricKey) == 0 {
		return "", errors.New("seal: empty symmetric key")
	}
	kem := w.wrapKEM()

	// 1. Fresh ephemeral key pair.
	ephPub, ephPriv, err := kem.GenerateKeyPair()
	if err != nil {
		return "", fmt.Errorf("seal: ephemeral keypair: %w", err)
	}
	defer crypto.Zeroize(ephPriv)

	// 2. Diffie-Hellman against the recipient's public key.
	dh, err := kem.Agree(ephPriv, recipientPublicKey)
	if err != nil {
		return "", fmt.Errorf("seal: ephemeral DH: %w", err)
	}
	defer crypto.Zeroize(dh)

	// 3. Derive a wrap key from the DH secret. Salt binds the wrap to the
	//    specific (ephemeral_pub, recipient_pub) pair so that the wrap
	//    cannot be replayed against a different recipient.
	salt := make([]byte, 0, len(ephPub)+len(recipientPublicKey))
	salt = append(salt, ephPub...)
	salt = append(salt, recipientPublicKey...)

	kdf := w.suite.KDF()
	prk := kdf.Extract(salt, dh)
	defer crypto.Zeroize(prk)
	wrapKey := kdf.Expand(prk, []byte(WrapInfo), w.suite.AEAD().KeySize())
	defer crypto.Zeroize(wrapKey)

	// 4. AEAD-Seal the symmetric key under wrap_key with a zero nonce.
	//    The zero nonce is safe because wrap_key is unique per call.
	//    Bind the recipient's public key as additional authenticated data
	//    so that an attacker cannot strip the wrap and re-attach it to a
	//    different recipient.
	nonce := make([]byte, w.suite.AEAD().NonceSize())
	ct, err := w.suite.AEAD().Seal(wrapKey, nonce, symmetricKey, recipientPublicKey)
	if err != nil {
		return "", fmt.Errorf("seal: AEAD seal: %w", err)
	}

	// 5. Concatenate the ephemeral public key with the ciphertext and
	//    base64-encode for transport.
	wrapped := make([]byte, 0, len(ephPub)+len(ct))
	wrapped = append(wrapped, ephPub...)
	wrapped = append(wrapped, ct...)
	return base64.StdEncoding.EncodeToString(wrapped), nil
}

// Unwrap reverses Wrap. The recipient computes the same ephemeral DH secret,
// derives the same wrap_key, and decrypts the symmetric key.
//
// The recipient's own public key is recomputed from recipientPrivateKey for
// use as the AEAD additional data and as part of the salt. This means the
// caller does not need to pass the public key explicitly — the unwrap is
// fully determined by the wrapped blob and the recipient's private key.
func (w *wrapper) Unwrap(recipientPrivateKey []byte, wrapped string) ([]byte, error) {
	if len(recipientPrivateKey) == 0 {
		return nil, errors.New("seal: empty recipient private key")
	}
	raw, err := base64.StdEncoding.DecodeString(wrapped)
	if err != nil {
		return nil, fmt.Errorf("seal: wrapped key base64: %w", err)
	}

	kem := w.wrapKEM()

	// X25519 public keys are 32 bytes. Anything shorter is malformed.
	const x25519PubSize = 32
	if len(raw) < x25519PubSize+w.suite.AEAD().Overhead() {
		return nil, errors.New("seal: wrapped key truncated")
	}
	ephPub := raw[:x25519PubSize]
	ct := raw[x25519PubSize:]

	// 1. Recover the recipient's own public key by re-running the X25519
	//    base point derivation. This is the standard X25519 trick: the
	//    public key is X25519(priv, basepoint).
	recipientPub, err := kem.Agree(recipientPrivateKey, x25519Basepoint())
	if err != nil {
		return nil, fmt.Errorf("seal: derive recipient public: %w", err)
	}

	// 2. Diffie-Hellman against the ephemeral public key.
	dh, err := kem.Agree(recipientPrivateKey, ephPub)
	if err != nil {
		return nil, fmt.Errorf("seal: ephemeral DH: %w", err)
	}
	defer crypto.Zeroize(dh)

	// 3. Derive the same wrap key the sender used.
	salt := make([]byte, 0, len(ephPub)+len(recipientPub))
	salt = append(salt, ephPub...)
	salt = append(salt, recipientPub...)
	kdf := w.suite.KDF()
	prk := kdf.Extract(salt, dh)
	defer crypto.Zeroize(prk)
	wrapKey := kdf.Expand(prk, []byte(WrapInfo), w.suite.AEAD().KeySize())
	defer crypto.Zeroize(wrapKey)

	// 4. AEAD-Open. The recipient public key is the additional data.
	nonce := make([]byte, w.suite.AEAD().NonceSize())
	pt, err := w.suite.AEAD().Open(wrapKey, nonce, ct, recipientPub)
	if err != nil {
		return nil, fmt.Errorf("seal: AEAD open: %w", err)
	}
	return pt, nil
}

// x25519Basepoint returns the canonical X25519 base point (9 followed by
// 31 zero bytes), used to derive a public key from a private key via
// scalar multiplication.
func x25519Basepoint() []byte {
	bp := make([]byte, 32)
	bp[0] = 9
	return bp
}

// WrapForRecipients wraps symmetricKey under each recipient's public key in
// turn and returns the resulting RecipientMap. Used by the sending client
// to populate Seal.BriefRecipients and Seal.EnclosureRecipients.
//
// Reference: ENVELOPE.md §7.1 steps 5–8.
func WrapForRecipients(w Wrapper, symmetricKey []byte, recipients []RecipientKey) (RecipientMap, error) {
	if w == nil {
		return nil, errors.New("seal: nil wrapper")
	}
	if len(recipients) == 0 {
		return RecipientMap{}, nil
	}
	out := make(RecipientMap, len(recipients))
	for _, r := range recipients {
		wrapped, err := w.Wrap(r.PublicKey, symmetricKey)
		if err != nil {
			return nil, fmt.Errorf("seal: wrap for %s: %w", r.Fingerprint, err)
		}
		out[r.Fingerprint] = wrapped
	}
	return out, nil
}

// RecipientKey identifies a recipient public key by fingerprint and provides
// the raw key bytes needed for wrapping.
type RecipientKey struct {
	Fingerprint keys.Fingerprint
	PublicKey   []byte
}
