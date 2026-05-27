package delivery

import (
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/semp-dev/semp-go/canonical"
	"github.com/semp-dev/semp-go/crypto"
)

// SEMP_STATUS message constants per draft-gokce-semp-delivery
// §1.6.5. The client composes a signed StatusMessage carrying the
// user's State, optional Message and Until, plus the Visibility
// rule that determines which senders may receive the status in
// acknowledgments. The client transmits the record to the home
// server as a signed message under the originating device's key;
// the home server verifies, checks DeviceID against the
// registered device set, and applies the latest update by
// UpdatedAt.
const (
	StatusMessageType    = "SEMP_STATUS"
	StatusMessageVersion = "1.0.0"
)

// StatusMessage is the signed SEMP_STATUS recipient-status
// configuration record per §1.6.5. Distinct from RecipientStatus,
// which is the delivery-side surface a recipient server attaches
// to delivered acknowledgments per §1.6.1.
type StatusMessage struct {
	Type       string           `json:"type"`
	Version    string           `json:"version"`
	UserID     string           `json:"user_id"`
	State      State            `json:"state"`
	Message    string           `json:"message,omitempty"`
	Until      *time.Time       `json:"until,omitempty"`
	Visibility Visibility       `json:"visibility"`
	UpdatedAt  time.Time        `json:"updated_at"`
	DeviceID   string           `json:"device_id"`
	Signature  ReceiptSignature `json:"signature"`
}

func canonicalStatusMessageBytes(m *StatusMessage) ([]byte, error) {
	if m == nil {
		return nil, errors.New("delivery: nil status message")
	}
	return canonical.MarshalWithElision(m, func(v any) error {
		root, ok := v.(map[string]any)
		if !ok {
			return fmt.Errorf("delivery: expected top-level object, got %T", v)
		}
		sig, ok := root["signature"].(map[string]any)
		if !ok {
			return errors.New("delivery: status message missing signature object")
		}
		sig["value"] = ""
		return nil
	})
}

// SignStatusMessage populates m.Signature with the originating
// device's signature over the canonical record bytes prefixed by
// SEMP-STATUS:.
func SignStatusMessage(signer crypto.Signer, devicePriv []byte, deviceKeyID string, m *StatusMessage) error {
	if signer == nil {
		return errors.New("delivery: nil signer")
	}
	if m == nil {
		return errors.New("delivery: nil status message")
	}
	if len(devicePriv) == 0 {
		return errors.New("delivery: empty device private key")
	}
	if deviceKeyID == "" {
		return errors.New("delivery: empty device key fingerprint")
	}
	if m.Type == "" {
		m.Type = StatusMessageType
	}
	if m.Version == "" {
		m.Version = StatusMessageVersion
	}
	if err := m.Validate(); err != nil {
		return err
	}
	m.Signature.Algorithm = ReceiptSignatureAlgorithmEd25519
	m.Signature.KeyID = deviceKeyID
	m.Signature.Value = ""
	canonicalBytes, err := canonicalStatusMessageBytes(m)
	if err != nil {
		return err
	}
	prefixed := crypto.PrefixedMessage(crypto.SigCtxStatus, canonicalBytes)
	sig, err := signer.Sign(devicePriv, prefixed)
	if err != nil {
		return fmt.Errorf("delivery: sign status message: %w", err)
	}
	m.Signature.Value = base64.StdEncoding.EncodeToString(sig)
	return nil
}

// VerifyStatusMessage checks m.Signature against devicePub per
// §1.6.5.
func VerifyStatusMessage(signer crypto.Signer, devicePub []byte, m *StatusMessage) error {
	if signer == nil {
		return errors.New("delivery: nil signer")
	}
	if m == nil {
		return errors.New("delivery: nil status message")
	}
	if len(devicePub) == 0 {
		return errors.New("delivery: empty device public key")
	}
	if m.Signature.Value == "" {
		return errors.New("delivery: status message is unsigned")
	}
	if err := m.Validate(); err != nil {
		return err
	}
	sig, err := base64.StdEncoding.DecodeString(m.Signature.Value)
	if err != nil {
		return fmt.Errorf("delivery: status message signature base64: %w", err)
	}
	canonicalBytes, err := canonicalStatusMessageBytes(m)
	if err != nil {
		return err
	}
	prefixed := crypto.PrefixedMessage(crypto.SigCtxStatus, canonicalBytes)
	if err := signer.Verify(devicePub, prefixed, sig); err != nil {
		return fmt.Errorf("delivery: verify status message: %w", err)
	}
	return nil
}

// Validate reports whether m is structurally well-formed per
// §1.6.5.
func (m *StatusMessage) Validate() error {
	if m == nil {
		return errors.New("delivery: nil status message")
	}
	if m.Type != StatusMessageType {
		return fmt.Errorf("delivery: status message type %q, want %q",
			m.Type, StatusMessageType)
	}
	if m.Version == "" {
		return errors.New("delivery: status message missing version")
	}
	if m.UserID == "" {
		return errors.New("delivery: status message missing user_id")
	}
	if m.State == "" {
		return errors.New("delivery: status message missing state")
	}
	if m.DeviceID == "" {
		return errors.New("delivery: status message missing device_id")
	}
	if m.UpdatedAt.IsZero() {
		return errors.New("delivery: status message missing updated_at")
	}
	if m.Visibility.Mode == "" {
		return errors.New("delivery: status message visibility.mode is empty")
	}
	if len(m.Message) > MaxStatusMessageBytes {
		return fmt.Errorf(
			"delivery: status message field exceeds %d bytes",
			MaxStatusMessageBytes,
		)
	}
	return nil
}
