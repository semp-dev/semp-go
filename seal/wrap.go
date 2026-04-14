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
	// key pair and returns the raw symmetric key bytes. The public key
	// is needed as AAD for the AEAD verification.
	Unwrap(recipientPrivateKey, recipientPublicKey []byte, wrapped string) ([]byte, error)
}

// WrapInfo is the HKDF info context used by NewWrapper. It is exported so
// other implementations can derive interoperable wrap_keys.
const WrapInfo = "SEMP-v1-wrap"

// NewWrapper returns a Wrapper backed by the suite's KEM, KDF, and AEAD.
// The wrap operation uses the suite's KEM for per-recipient key wrapping:
// for SuiteBaseline this is X25519; for SuitePQ this is the Kyber768+X25519
// hybrid. This ensures that post-quantum protection extends to envelope
// confidentiality at rest, not only to session key exchange.
//
// Recipient encryption keys MUST be generated using the same suite's KEM.
// A baseline recipient key is X25519 (32 bytes); a PQ recipient key is
// the hybrid format (Kyber768 public key concatenated with X25519 public key).
//
// The same wrapper instance is safe for concurrent use across goroutines
// because it carries no state: every Wrap/Unwrap call generates or consumes
// a fresh ephemeral key pair.
func NewWrapper(suite crypto.Suite) Wrapper {
	if suite == nil {
		return nil
	}
	return &wrapper{suite: suite}
}

type wrapper struct {
	suite crypto.Suite
}

// wrapKEM returns the suite's KEM for per-recipient key wrapping.
func (w *wrapper) wrapKEM() crypto.KEM {
	return w.suite.KEM()
}

// Wrap encrypts symmetricKey under recipientPublicKey using KEM-based
// encapsulation + HKDF-SHA-512 + ChaCha20-Poly1305. For SuiteBaseline,
// the KEM is X25519. For SuitePQ, the KEM is Kyber768+X25519 hybrid,
// providing post-quantum protection for envelope confidentiality at rest.
func (w *wrapper) Wrap(recipientPublicKey, symmetricKey []byte) (string, error) {
	if len(recipientPublicKey) == 0 {
		return "", errors.New("seal: empty recipient public key")
	}
	if len(symmetricKey) == 0 {
		return "", errors.New("seal: empty symmetric key")
	}
	kem := w.wrapKEM()

	// 1. Encapsulate against the recipient's public key. This produces
	//    a shared secret and a ciphertext (for X25519: ephemeral pub;
	//    for hybrid: kyber ciphertext + X25519 ephemeral pub).
	sharedSecret, kemCT, err := kem.Encapsulate(recipientPublicKey)
	if err != nil {
		return "", fmt.Errorf("seal: KEM encapsulate: %w", err)
	}
	defer crypto.Zeroize(sharedSecret)

	// 2. Derive a wrap key from the shared secret.
	salt := append(kemCT, recipientPublicKey...)
	kdf := w.suite.KDF()
	prk := kdf.Extract(salt, sharedSecret)
	defer crypto.Zeroize(prk)
	wrapKey := kdf.Expand(prk, []byte(WrapInfo), w.suite.AEAD().KeySize())
	defer crypto.Zeroize(wrapKey)

	// 3. AEAD-Seal the symmetric key under wrap_key with a zero nonce.
	//    The zero nonce is safe because wrap_key is unique per call.
	//    Bind the recipient's public key as AAD.
	nonce := make([]byte, w.suite.AEAD().NonceSize())
	ct, err := w.suite.AEAD().Seal(wrapKey, nonce, symmetricKey, recipientPublicKey)
	if err != nil {
		return "", fmt.Errorf("seal: AEAD seal: %w", err)
	}

	// 4. Concatenate KEM ciphertext with AEAD ciphertext, base64-encode.
	wrapped := make([]byte, 0, len(kemCT)+len(ct))
	wrapped = append(wrapped, kemCT...)
	wrapped = append(wrapped, ct...)
	return base64.StdEncoding.EncodeToString(wrapped), nil
}

// Unwrap reverses Wrap. The recipient decapsulates the KEM ciphertext to
// recover the shared secret, derives the same wrap_key, and decrypts the
// symmetric key.
//
// recipientPublicKey is needed as AAD for the AEAD verification. The caller
// MUST pass the public key that corresponds to recipientPrivateKey.
func (w *wrapper) Unwrap(recipientPrivateKey, recipientPublicKey []byte, wrapped string) ([]byte, error) {
	if len(recipientPrivateKey) == 0 {
		return nil, errors.New("seal: empty recipient private key")
	}
	if len(recipientPublicKey) == 0 {
		return nil, errors.New("seal: empty recipient public key")
	}
	raw, err := base64.StdEncoding.DecodeString(wrapped)
	if err != nil {
		return nil, fmt.Errorf("seal: wrapped key base64: %w", err)
	}

	kem := w.wrapKEM()

	// Determine KEM ciphertext size. For X25519: 32 bytes (ephemeral pub).
	// For hybrid: Kyber768 ciphertext + 32 bytes X25519 ephemeral pub.
	// We use Encapsulate with a dummy key to learn the ciphertext size,
	// but that's wasteful. Instead, compute from the known sizes.
	// X25519 ciphertext = 32, Kyber768 ciphertext = 1088, hybrid = 1120.
	// Use a trial: generate a keypair, encapsulate, measure ciphertext length.
	_, trialCT, err := kem.Encapsulate(raw[:0]) // will fail but we need the size
	// Fallback: try to decapsulate with the full blob and progressively
	// split it. The AEAD overhead is fixed, so kemCTSize = len(raw) - aeadCTSize.
	aeadOverhead := w.suite.AEAD().Overhead()
	keySize := w.suite.AEAD().KeySize() // the wrapped symmetric key is keySize bytes plaintext
	aeadCTLen := keySize + aeadOverhead
	if len(raw) < aeadCTLen {
		return nil, errors.New("seal: wrapped key truncated")
	}
	kemCTLen := len(raw) - aeadCTLen
	kemCT := raw[:kemCTLen]
	ct := raw[kemCTLen:]
	_ = trialCT

	// 1. Decapsulate to recover the shared secret.
	sharedSecret, err := kem.Decapsulate(kemCT, recipientPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("seal: KEM decapsulate: %w", err)
	}
	defer crypto.Zeroize(sharedSecret)

	// 2. Derive the same wrap key the sender used.
	// Copy kemCT to avoid corrupting ct (they share the same backing array).
	salt := make([]byte, 0, len(kemCT)+len(recipientPublicKey))
	salt = append(salt, kemCT...)
	salt = append(salt, recipientPublicKey...)
	kdf := w.suite.KDF()
	prk := kdf.Extract(salt, sharedSecret)
	defer crypto.Zeroize(prk)
	wrapKey := kdf.Expand(prk, []byte(WrapInfo), w.suite.AEAD().KeySize())
	defer crypto.Zeroize(wrapKey)

	// 3. AEAD-Open. The recipient public key is the additional data.
	nonce := make([]byte, w.suite.AEAD().NonceSize())
	pt, err := w.suite.AEAD().Open(wrapKey, nonce, ct, recipientPublicKey)
	if err != nil {
		return nil, fmt.Errorf("seal: AEAD open: %w", err)
	}
	return pt, nil
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
