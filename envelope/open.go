package envelope

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"semp.dev/semp-go/brief"
	"semp.dev/semp-go/crypto"
	"semp.dev/semp-go/enclosure"
	"semp.dev/semp-go/keys"
	"semp.dev/semp-go/seal"
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

// RecipientPrivateKey is a (fingerprint, private key) pair that a
// receiver can offer to the multi-candidate open helpers below. It
// supports two scenarios that come up once a user or domain has more
// than one active encryption key at once:
//
//   - Multi-device clients: a single user may have N registered
//     devices, each with its own encryption key. The sender wraps
//     K_brief and K_enclosure under every device's key (one seal
//     entry per device). The receiving device iterates its own
//     key ring via OpenBriefAny to find the entry wrapped for it.
//
//   - Key rotation: a device may hold a current encryption key plus
//     one or more retired keys needed to decrypt envelopes that
//     were sealed under the retired key. Per CLIENT.md §4.1 the
//     client SHOULD try retired keys during decryption.
//
// RecipientPrivateKey is a raw byte slice plus its fingerprint so
// the helpers can pick the right wrap entry without having to
// recompute fingerprints on every call.
type RecipientPrivateKey struct {
	// Fingerprint is the key's published fingerprint. It MUST match
	// the fingerprint the sender used when wrapping; otherwise the
	// helper will skip this entry and move on.
	Fingerprint keys.Fingerprint

	// PrivateKey is the raw X25519 private key bytes. Kept as []byte
	// rather than a typed struct so callers can zeroize the slice
	// on release.
	PrivateKey []byte
}

// OpenBriefAny iterates candidates in order and returns the first
// successful brief decryption. This is the multi-device / key-
// rotation counterpart to OpenBrief: a client that holds more than
// one candidate encryption key calls this once and lets the helper
// pick the entry that matches its key ring.
//
// The function tries each candidate whose Fingerprint is present in
// env.Seal.BriefRecipients; candidates whose fingerprints are not
// authorized are skipped silently (they're not an error — a
// multi-device user may pass the full key ring even when only one
// key has a wrap entry). If every present candidate fails to
// decrypt, the last underlying error is returned wrapped.
//
// Returns an error if candidates is empty or if no candidate is
// authorized on the envelope.
func OpenBriefAny(env *Envelope, suite crypto.Suite, candidates []RecipientPrivateKey) (*brief.Brief, error) {
	if env == nil {
		return nil, errors.New("envelope: nil envelope")
	}
	if len(candidates) == 0 {
		return nil, errors.New("envelope: no recipient candidates")
	}
	var lastErr error
	matched := false
	for _, cand := range candidates {
		if _, ok := env.Seal.BriefRecipients[cand.Fingerprint]; !ok {
			continue
		}
		matched = true
		b, err := OpenBrief(env, suite, cand.Fingerprint, cand.PrivateKey)
		if err == nil {
			return b, nil
		}
		lastErr = err
	}
	if !matched {
		return nil, errors.New("envelope: no candidate matches any brief_recipients entry")
	}
	return nil, fmt.Errorf("envelope: all candidate keys failed to open brief: %w", lastErr)
}

// OpenEnclosureAny is the enclosure counterpart to OpenBriefAny.
// Same candidate iteration semantics; only client encryption keys
// should appear in the candidate set because enclosure wraps are
// never created for domain keys (ENVELOPE.md §7.1 step 8).
func OpenEnclosureAny(env *Envelope, suite crypto.Suite, candidates []RecipientPrivateKey) (*enclosure.Enclosure, error) {
	if env == nil {
		return nil, errors.New("envelope: nil envelope")
	}
	if len(candidates) == 0 {
		return nil, errors.New("envelope: no recipient candidates")
	}
	var lastErr error
	matched := false
	for _, cand := range candidates {
		if _, ok := env.Seal.EnclosureRecipients[cand.Fingerprint]; !ok {
			continue
		}
		matched = true
		e, err := OpenEnclosure(env, suite, cand.Fingerprint, cand.PrivateKey)
		if err == nil {
			return e, nil
		}
		lastErr = err
	}
	if !matched {
		return nil, errors.New("envelope: no candidate matches any enclosure_recipients entry")
	}
	return nil, fmt.Errorf("envelope: all candidate keys failed to open enclosure: %w", lastErr)
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
