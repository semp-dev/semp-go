package recovery

import (
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/text/unicode/norm"

	"semp.dev/semp-go/crypto"
	"semp.dev/semp-go/internal/canonical"
)

// SecretForm names the recovery secret encoding per RECOVERY.md
// §3.1.
type SecretForm string

// Secret forms.
const (
	// SecretFormPassphrase is a user-chosen Unicode string. The
	// client normalizes via NFKC and trims surrounding whitespace
	// per §3.2.
	SecretFormPassphrase SecretForm = "passphrase"

	// SecretFormRecoveryCode is a BIP-39 24-word phrase. The client
	// joins words with a single ASCII space and lowercases per §3.2.
	SecretFormRecoveryCode SecretForm = "recovery_code"
)

// MinPassphraseBytes is the §3.1 hard minimum on a passphrase
// secret's UTF-8 byte length after NFKC normalization.
const MinPassphraseBytes = 12

// RecoverySignKeyInfo is the HKDF info string used to derive the
// recovery signing-key seed from K_bundle per §3.3. Versioned so
// future revisions of the derivation can coexist with v1.
const RecoverySignKeyInfo = "SEMP-RECOVERY-SIGN-KEY-v1"

// NormalizeRecoverySecret returns the UTF-8 byte representation of
// secret after applying the §3.2 normalization rules for form.
//
// For passphrase form: NFKC, trimmed of leading/trailing
// whitespace, no further transformation. Rejected if the resulting
// byte length is below MinPassphraseBytes.
//
// For recovery-code form: split on whitespace, join with single
// ASCII space, lowercased. Returns an error if the result is
// empty.
func NormalizeRecoverySecret(form SecretForm, raw string) ([]byte, error) {
	switch form {
	case SecretFormPassphrase:
		s := strings.TrimSpace(norm.NFKC.String(raw))
		if len(s) < MinPassphraseBytes {
			return nil, fmt.Errorf("recovery: passphrase length %d below %d-byte minimum", len(s), MinPassphraseBytes)
		}
		return []byte(s), nil
	case SecretFormRecoveryCode:
		fields := strings.Fields(raw)
		if len(fields) == 0 {
			return nil, errors.New("recovery: recovery code is empty")
		}
		for i, w := range fields {
			fields[i] = strings.ToLower(w)
		}
		return []byte(strings.Join(fields, " ")), nil
	default:
		return nil, fmt.Errorf("recovery: unsupported secret form %q", form)
	}
}

// DeriveBundleKey runs Argon2id over the normalized secret bytes
// and returns the 32-byte K_bundle per RECOVERY.md §2.5.
//
// kdf parameters MUST satisfy the spec minima (the function
// validates and returns an error otherwise).
func DeriveBundleKey(secretBytes []byte, kdf BundleKDF) ([]byte, error) {
	if len(secretBytes) == 0 {
		return nil, errors.New("recovery: empty recovery secret bytes")
	}
	if err := kdf.Validate(); err != nil {
		return nil, err
	}
	salt, err := base64.StdEncoding.DecodeString(kdf.Salt)
	if err != nil {
		return nil, fmt.Errorf("recovery: kdf salt base64: %w", err)
	}
	if len(salt) < MinKDFSaltBytes {
		return nil, fmt.Errorf("recovery: kdf salt length %d below %d-byte minimum", len(salt), MinKDFSaltBytes)
	}
	out := argon2.IDKey(secretBytes, salt, kdf.Iterations, kdf.MemoryKB, kdf.Parallelism, 32)
	return out, nil
}

// DeriveRecoverySignKey runs HKDF-Expand over the K_bundle output
// and returns the (recovery_sign_sk, recovery_verify_pk) Ed25519
// key pair per RECOVERY.md §3.3.
//
// The seed is HKDF-Expand(K_bundle, "SEMP-RECOVERY-SIGN-KEY-v1",
// 32) and is fed to ed25519.NewKeyFromSeed. The seed is consumed
// once and not stored.
func DeriveRecoverySignKey(bundleKey []byte) (signSK ed25519.PrivateKey, verifyPK ed25519.PublicKey, err error) {
	if len(bundleKey) == 0 {
		return nil, nil, errors.New("recovery: empty bundle key")
	}
	r := hkdf.Expand(sha512Func, bundleKey, []byte(RecoverySignKeyInfo))
	seed := make([]byte, ed25519.SeedSize)
	if _, err := io.ReadFull(r, seed); err != nil {
		return nil, nil, fmt.Errorf("recovery: hkdf expand: %w", err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	return priv, pub, nil
}

// sha512Func returns a fresh hash.Hash for HKDF over SHA-512.
// Wrapping the constructor as a func() is what hkdf.Expand wants.
var sha512Func = func() hash.Hash { return sha512.New() }

// EncryptBundlePayload XChaCha20-Poly1305-encrypts the JSON-encoded
// payload under K_bundle and returns the ciphertext. nonce MUST be
// 24 bytes (chacha20poly1305.NonceSizeX). Caller passes the nonce
// rather than letting the helper generate it so the bundle's
// payload_nonce field is the same value used here.
//
// Per §2.5 the AEAD additional-data field is empty.
func EncryptBundlePayload(bundleKey []byte, nonce []byte, payload BundlePayload) ([]byte, error) {
	if len(bundleKey) != 32 {
		return nil, fmt.Errorf("recovery: bundle key length %d, want 32", len(bundleKey))
	}
	if len(nonce) != chacha20poly1305.NonceSizeX {
		return nil, fmt.Errorf("recovery: payload nonce length %d, want %d", len(nonce), chacha20poly1305.NonceSizeX)
	}
	plaintext, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("recovery: marshal payload: %w", err)
	}
	aead, err := chacha20poly1305.NewX(bundleKey)
	if err != nil {
		return nil, fmt.Errorf("recovery: xchacha20-poly1305: %w", err)
	}
	return aead.Seal(nil, nonce, plaintext, nil), nil
}

// DecryptBundlePayload reverses EncryptBundlePayload.
func DecryptBundlePayload(bundleKey []byte, nonce []byte, ciphertext []byte) (*BundlePayload, error) {
	if len(bundleKey) != 32 {
		return nil, fmt.Errorf("recovery: bundle key length %d, want 32", len(bundleKey))
	}
	if len(nonce) != chacha20poly1305.NonceSizeX {
		return nil, fmt.Errorf("recovery: payload nonce length %d, want %d", len(nonce), chacha20poly1305.NonceSizeX)
	}
	aead, err := chacha20poly1305.NewX(bundleKey)
	if err != nil {
		return nil, fmt.Errorf("recovery: xchacha20-poly1305: %w", err)
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("recovery: payload aead open: %w", err)
	}
	var p BundlePayload
	if err := json.Unmarshal(plaintext, &p); err != nil {
		return nil, fmt.Errorf("recovery: parse payload: %w", err)
	}
	return &p, nil
}

// canonicalBundleBytes returns the canonical JSON form of b with
// signature.value elided to "" per RECOVERY.md §2.4.
func canonicalBundleBytes(b *BackupBundle) ([]byte, error) {
	if b == nil {
		return nil, errors.New("recovery: nil bundle")
	}
	return canonical.MarshalWithElision(b, func(v any) error {
		m, ok := v.(map[string]any)
		if !ok {
			return fmt.Errorf("recovery: expected top-level object, got %T", v)
		}
		sig, ok := m["signature"].(map[string]any)
		if !ok {
			return errors.New("recovery: bundle missing signature object")
		}
		sig["value"] = ""
		return nil
	})
}

// SignBundle populates b.Signature with the user's identity-key
// signature over the canonical bundle bytes per RECOVERY.md §2.4.
// identityPriv is the user's currently active identity private
// key; identityKeyID is its fingerprint.
func SignBundle(signer crypto.Signer, identityPriv []byte, identityKeyID string, b *BackupBundle) error {
	if signer == nil {
		return errors.New("recovery: nil signer")
	}
	if b == nil {
		return errors.New("recovery: nil bundle")
	}
	if len(identityPriv) == 0 {
		return errors.New("recovery: empty identity private key")
	}
	if identityKeyID == "" {
		return errors.New("recovery: empty identity key fingerprint")
	}
	if b.Type == "" {
		b.Type = BundleType
	}
	if b.Version == "" {
		b.Version = RecordVersion
	}
	if err := b.Validate(); err != nil {
		return err
	}
	b.Signature.Algorithm = SignatureAlgorithmEd25519
	b.Signature.KeyID = identityKeyID
	b.Signature.Value = ""
	bytes, err := canonicalBundleBytes(b)
	if err != nil {
		return err
	}
	prefixed := crypto.PrefixedMessage(crypto.SigCtxRecoveryBundle, bytes)
	sig, err := signer.Sign(identityPriv, prefixed)
	if err != nil {
		return fmt.Errorf("recovery: sign bundle: %w", err)
	}
	b.Signature.Value = base64.StdEncoding.EncodeToString(sig)
	return nil
}

// VerifyBundle checks b.Signature against identityPub.
func VerifyBundle(signer crypto.Signer, identityPub []byte, b *BackupBundle) error {
	if signer == nil {
		return errors.New("recovery: nil signer")
	}
	if b == nil {
		return errors.New("recovery: nil bundle")
	}
	if len(identityPub) == 0 {
		return errors.New("recovery: empty identity public key")
	}
	if b.Signature.Value == "" {
		return errors.New("recovery: bundle is unsigned")
	}
	if err := b.Validate(); err != nil {
		return err
	}
	sig, err := base64.StdEncoding.DecodeString(b.Signature.Value)
	if err != nil {
		return fmt.Errorf("recovery: bundle signature base64: %w", err)
	}
	bytes, err := canonicalBundleBytes(b)
	if err != nil {
		return err
	}
	prefixed := crypto.PrefixedMessage(crypto.SigCtxRecoveryBundle, bytes)
	if err := signer.Verify(identityPub, prefixed, sig); err != nil {
		return fmt.Errorf("recovery: verify bundle: %w", err)
	}
	return nil
}

// Validate reports whether b is structurally well-formed per
// RECOVERY.md §2.2 + §2.5. Does not verify the signature.
func (b *BackupBundle) Validate() error {
	if b == nil {
		return errors.New("recovery: nil bundle")
	}
	if b.Type != BundleType {
		return fmt.Errorf("recovery: bundle type %q, want %q", b.Type, BundleType)
	}
	if b.UserID == "" {
		return errors.New("recovery: bundle missing user_id")
	}
	if b.BundleID == "" {
		return errors.New("recovery: bundle missing bundle_id")
	}
	if b.CreatedAt.IsZero() {
		return errors.New("recovery: bundle missing created_at")
	}
	if err := b.KDF.Validate(); err != nil {
		return fmt.Errorf("recovery: bundle kdf: %w", err)
	}
	if b.PayloadAlgorithm != BundlePayloadAEAD {
		return fmt.Errorf("recovery: bundle payload_algorithm %q, want %q", b.PayloadAlgorithm, BundlePayloadAEAD)
	}
	if b.PayloadNonce == "" {
		return errors.New("recovery: bundle missing payload_nonce")
	}
	if b.EncryptedPayload == "" {
		return errors.New("recovery: bundle missing encrypted_payload")
	}
	if b.RecoveryVerifyPK.Algorithm == "" || b.RecoveryVerifyPK.PublicKey == "" {
		return errors.New("recovery: bundle missing recovery_verify_pk")
	}
	return nil
}

// Validate reports whether kdf meets the §2.5 minima.
func (kdf BundleKDF) Validate() error {
	if kdf.Algorithm != KDFAlgorithmArgon2id {
		return fmt.Errorf("kdf algorithm %q, want %q", kdf.Algorithm, KDFAlgorithmArgon2id)
	}
	if kdf.Salt == "" {
		return errors.New("kdf missing salt")
	}
	salt, err := base64.StdEncoding.DecodeString(kdf.Salt)
	if err != nil {
		return fmt.Errorf("kdf salt base64: %w", err)
	}
	if len(salt) < MinKDFSaltBytes {
		return fmt.Errorf("kdf salt length %d below %d-byte minimum", len(salt), MinKDFSaltBytes)
	}
	if kdf.MemoryKB < MinKDFMemoryKB {
		return fmt.Errorf("kdf memory_kb %d below %d minimum", kdf.MemoryKB, MinKDFMemoryKB)
	}
	if kdf.Iterations < MinKDFIterations {
		return fmt.Errorf("kdf iterations %d below %d minimum", kdf.Iterations, MinKDFIterations)
	}
	if kdf.Parallelism < MinKDFParallelism {
		return fmt.Errorf("kdf parallelism %d below %d minimum", kdf.Parallelism, MinKDFParallelism)
	}
	return nil
}

