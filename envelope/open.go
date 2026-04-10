package envelope

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/semp-dev/semp-go/brief"
	"github.com/semp-dev/semp-go/crypto"
	"github.com/semp-dev/semp-go/enclosure"
	"github.com/semp-dev/semp-go/keys"
	"github.com/semp-dev/semp-go/seal"
)

// VerifySignature verifies env.Seal.Signature against the sender domain's
// published public key. Routing servers MUST call this before forwarding
// (ENVELOPE.md §9.1 step 1).
func VerifySignature(env *Envelope, suite crypto.Suite, domainPublicKey []byte) error {
	if env == nil {
		return errors.New("envelope: nil envelope")
	}
	canonicalBytes, err := env.CanonicalBytes()
	if err != nil {
		return fmt.Errorf("envelope: canonical bytes: %w", err)
	}
	v := &seal.Verifier{Suite: suite}
	return v.VerifySignature(&env.Seal, canonicalBytes, domainPublicKey)
}

// VerifySessionMAC verifies env.Seal.SessionMAC using K_env_mac from the
// referenced session. Receiving servers MUST call this after VerifySignature
// and before processing the brief (ENVELOPE.md §9.1 step 4).
func VerifySessionMAC(env *Envelope, suite crypto.Suite, envMAC []byte) error {
	if env == nil {
		return errors.New("envelope: nil envelope")
	}
	canonicalBytes, err := env.CanonicalBytes()
	if err != nil {
		return fmt.Errorf("envelope: canonical bytes: %w", err)
	}
	v := &seal.Verifier{Suite: suite}
	return v.VerifySessionMAC(&env.Seal, canonicalBytes, envMAC)
}

// OpenBrief decrypts the encrypted brief payload using the recipient's
// private key, which MUST be authorized in env.Seal.BriefRecipients under
// recipientFingerprint. Used by both the receiving server (with its domain
// encryption private key) and the receiving client (with its client
// encryption private key) per ENVELOPE.md §7.2 steps 5–6 and step 8–9.
func OpenBrief(env *Envelope, suite crypto.Suite, recipientFingerprint keys.Fingerprint, recipientPrivateKey []byte) (*brief.Brief, error) {
	if env == nil {
		return nil, errors.New("envelope: nil envelope")
	}
	wrapped, ok := env.Seal.BriefRecipients[recipientFingerprint]
	if !ok {
		return nil, fmt.Errorf("envelope: no brief wrap for recipient %s", recipientFingerprint)
	}

	wrapper := seal.NewWrapper(suite)
	if wrapper == nil {
		return nil, errors.New("envelope: nil wrapper for suite")
	}
	kBrief, err := wrapper.Unwrap(recipientPrivateKey, wrapped)
	if err != nil {
		return nil, fmt.Errorf("envelope: unwrap K_brief: %w", err)
	}
	defer crypto.Zeroize(kBrief)

	plain, err := decryptBlob(suite, kBrief, env.Brief)
	if err != nil {
		return nil, fmt.Errorf("envelope: decrypt brief: %w", err)
	}
	var b brief.Brief
	if err := json.Unmarshal(plain, &b); err != nil {
		return nil, fmt.Errorf("envelope: parse brief: %w", err)
	}
	return &b, nil
}

// OpenEnclosure decrypts the encrypted enclosure payload using the
// recipient client's private key. The recipient server CANNOT call this:
// the enclosure is wrapped only for client encryption keys, never for
// domain keys (ENVELOPE.md §7.1 step 8).
func OpenEnclosure(env *Envelope, suite crypto.Suite, clientFingerprint keys.Fingerprint, clientPrivateKey []byte) (*enclosure.Enclosure, error) {
	if env == nil {
		return nil, errors.New("envelope: nil envelope")
	}
	wrapped, ok := env.Seal.EnclosureRecipients[clientFingerprint]
	if !ok {
		return nil, fmt.Errorf("envelope: no enclosure wrap for recipient %s", clientFingerprint)
	}

	wrapper := seal.NewWrapper(suite)
	if wrapper == nil {
		return nil, errors.New("envelope: nil wrapper for suite")
	}
	kEnclosure, err := wrapper.Unwrap(clientPrivateKey, wrapped)
	if err != nil {
		return nil, fmt.Errorf("envelope: unwrap K_enclosure: %w", err)
	}
	defer crypto.Zeroize(kEnclosure)

	plain, err := decryptBlob(suite, kEnclosure, env.Enclosure)
	if err != nil {
		return nil, fmt.Errorf("envelope: decrypt enclosure: %w", err)
	}
	var e enclosure.Enclosure
	if err := json.Unmarshal(plain, &e); err != nil {
		return nil, fmt.Errorf("envelope: parse enclosure: %w", err)
	}
	return &e, nil
}

// decryptBlob is the inverse of the encrypt-then-base64 step in Compose.
// The blob layout is: nonce || ciphertext-with-poly1305-tag, base64-encoded.
func decryptBlob(suite crypto.Suite, key []byte, blob string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(blob)
	if err != nil {
		return nil, fmt.Errorf("base64: %w", err)
	}
	aead := suite.AEAD()
	if len(raw) < aead.NonceSize()+aead.Overhead() {
		return nil, errors.New("blob truncated")
	}
	nonce := raw[:aead.NonceSize()]
	ct := raw[aead.NonceSize():]
	return aead.Open(key, nonce, ct, nil)
}
