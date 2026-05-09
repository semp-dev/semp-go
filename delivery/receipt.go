package delivery

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"semp.dev/semp-go/crypto"
	"semp.dev/semp-go/canonical"
)

// Wire-level constants for SEMP_DELIVERY_RECEIPT per DELIVERY.md
// §1.1.1.1.
const (
	DeliveryReceiptType    = "SEMP_DELIVERY_RECEIPT"
	DeliveryReceiptVersion = "1.0.0"

	// EnvelopeHashAlgorithmSHA256 is the only digest algorithm
	// defined for v1.0.0 receipts per §1.1.1.3.
	EnvelopeHashAlgorithmSHA256 = "sha-256"

	// ReceiptSignatureAlgorithmEd25519 is the recipient-domain
	// signing algorithm.
	ReceiptSignatureAlgorithmEd25519 = "ed25519"

	// ReceiptClockSkewToleranceSeconds is the receiver-side
	// tolerance window per §1.1.1.5: "Verifiers MUST NOT reject a
	// receipt solely because accepted_at is within 120 seconds of
	// their own current time in either direction." Receipts that
	// drift further still verify cryptographically; the caller
	// decides whether to surface a warning.
	ReceiptClockSkewToleranceSeconds = 120
)

// EnvelopeHash is the hash binding inside a DeliveryReceipt per
// §1.1.1.3.
type EnvelopeHash struct {
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"` // base64
}

// ReceiptSignature mirrors the §1.1.1.4 signature block.
type ReceiptSignature struct {
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"key_id"`
	Value     string `json:"value"`
}

// DeliveryReceipt is a SEMP_DELIVERY_RECEIPT record per
// DELIVERY.md §1.1.1. It proves the recipient domain accepted a
// specific envelope at a specific time.
type DeliveryReceipt struct {
	Type            string           `json:"type"`
	Version         string           `json:"version"`
	EnvelopeHash    EnvelopeHash     `json:"envelope_hash"`
	RecipientDomain string           `json:"recipient_domain"`
	AcceptedAt      time.Time        `json:"accepted_at"`
	Signature       ReceiptSignature `json:"signature"`
}

// ComputeEnvelopeHash returns the SHA-256 of canonicalEnvelopeBytes
// per §1.1.1.3. The caller computes canonical bytes via
// envelope.Envelope.CanonicalBytes(), which already applies the
// §4.3 elision rules (signature, session_mac, and hop_count
// excluded). The result is the value to put in
// DeliveryReceipt.EnvelopeHash.Value (base64-encoded).
func ComputeEnvelopeHash(canonicalEnvelopeBytes []byte) string {
	sum := sha256.Sum256(canonicalEnvelopeBytes)
	return base64.StdEncoding.EncodeToString(sum[:])
}

// canonicalReceiptBytes returns the canonical JSON form of r with
// signature.value elided to "" per §1.1.1.4.
func canonicalReceiptBytes(r *DeliveryReceipt) ([]byte, error) {
	if r == nil {
		return nil, errors.New("delivery: nil receipt")
	}
	return canonical.MarshalWithElision(r, func(v any) error {
		m, ok := v.(map[string]any)
		if !ok {
			return fmt.Errorf("delivery: expected top-level object, got %T", v)
		}
		sig, ok := m["signature"].(map[string]any)
		if !ok {
			return errors.New("delivery: receipt missing signature object")
		}
		sig["value"] = ""
		return nil
	})
}

// SignDeliveryReceipt populates r.Signature with the recipient
// domain's signature over the canonical receipt bytes per
// §1.1.1.4. domainPriv is the recipient domain's signing private
// key; domainKeyID is its fingerprint.
func SignDeliveryReceipt(signer crypto.Signer, domainPriv []byte, domainKeyID string, r *DeliveryReceipt) error {
	if signer == nil {
		return errors.New("delivery: nil signer")
	}
	if r == nil {
		return errors.New("delivery: nil receipt")
	}
	if len(domainPriv) == 0 {
		return errors.New("delivery: empty domain private key")
	}
	if domainKeyID == "" {
		return errors.New("delivery: empty domain key fingerprint")
	}
	if r.Type == "" {
		r.Type = DeliveryReceiptType
	}
	if r.Version == "" {
		r.Version = DeliveryReceiptVersion
	}
	if err := r.Validate(); err != nil {
		return err
	}
	r.Signature.Algorithm = ReceiptSignatureAlgorithmEd25519
	r.Signature.KeyID = domainKeyID
	r.Signature.Value = ""
	canonicalBytes, err := canonicalReceiptBytes(r)
	if err != nil {
		return err
	}
	prefixed := crypto.PrefixedMessage(crypto.SigCtxDeliveryReceipt, canonicalBytes)
	sig, err := signer.Sign(domainPriv, prefixed)
	if err != nil {
		return fmt.Errorf("delivery: sign receipt: %w", err)
	}
	r.Signature.Value = base64.StdEncoding.EncodeToString(sig)
	return nil
}

// VerifyDeliveryReceipt checks r.Signature against domainPub. The
// caller looks up domainPub from the recipient domain's published
// signing keys by r.Signature.KeyID per §1.1.1.7 step 2.
//
// VerifyDeliveryReceipt does NOT cross-check accepted_at against
// the verifier's clock; that is a §1.1.1.5 caller-side decision and
// MUST be applied with the 120-second tolerance window.
func VerifyDeliveryReceipt(signer crypto.Signer, domainPub []byte, r *DeliveryReceipt) error {
	if signer == nil {
		return errors.New("delivery: nil signer")
	}
	if r == nil {
		return errors.New("delivery: nil receipt")
	}
	if len(domainPub) == 0 {
		return errors.New("delivery: empty domain public key")
	}
	if r.Signature.Value == "" {
		return errors.New("delivery: receipt is unsigned")
	}
	if err := r.Validate(); err != nil {
		return err
	}
	sig, err := base64.StdEncoding.DecodeString(r.Signature.Value)
	if err != nil {
		return fmt.Errorf("delivery: receipt signature base64: %w", err)
	}
	canonicalBytes, err := canonicalReceiptBytes(r)
	if err != nil {
		return err
	}
	prefixed := crypto.PrefixedMessage(crypto.SigCtxDeliveryReceipt, canonicalBytes)
	if err := signer.Verify(domainPub, prefixed, sig); err != nil {
		return fmt.Errorf("delivery: verify receipt: %w", err)
	}
	return nil
}

// VerifyEnvelopeBinding cross-checks that r.EnvelopeHash.Value
// matches the SHA-256 of canonicalEnvelopeBytes per §1.1.1.7
// step 4. Returns nil when the binding holds.
func VerifyEnvelopeBinding(r *DeliveryReceipt, canonicalEnvelopeBytes []byte) error {
	if r == nil {
		return errors.New("delivery: nil receipt")
	}
	if r.EnvelopeHash.Algorithm != EnvelopeHashAlgorithmSHA256 {
		return fmt.Errorf("delivery: receipt envelope_hash.algorithm %q, want %q",
			r.EnvelopeHash.Algorithm, EnvelopeHashAlgorithmSHA256)
	}
	want := ComputeEnvelopeHash(canonicalEnvelopeBytes)
	if r.EnvelopeHash.Value != want {
		return errors.New("delivery: receipt envelope_hash does not match envelope canonical bytes")
	}
	return nil
}

// Validate reports whether r is structurally well-formed per
// §1.1.1.2.
func (r *DeliveryReceipt) Validate() error {
	if r == nil {
		return errors.New("delivery: nil receipt")
	}
	if r.Type != DeliveryReceiptType {
		return fmt.Errorf("delivery: receipt type %q, want %q", r.Type, DeliveryReceiptType)
	}
	if r.EnvelopeHash.Algorithm == "" {
		return errors.New("delivery: receipt missing envelope_hash.algorithm")
	}
	if r.EnvelopeHash.Value == "" {
		return errors.New("delivery: receipt missing envelope_hash.value")
	}
	if r.RecipientDomain == "" {
		return errors.New("delivery: receipt missing recipient_domain")
	}
	if r.AcceptedAt.IsZero() {
		return errors.New("delivery: receipt missing accepted_at")
	}
	return nil
}
