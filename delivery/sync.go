package delivery

import (
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"semp.dev/semp-go/crypto"
	"semp.dev/semp-go/internal/canonical"
	"semp.dev/semp-go/keys"
)

// SyncMessageType is the wire-level type discriminator for block list sync
// messages (DELIVERY.md §6.1).
const SyncMessageType = "SEMP_BLOCK"

// SyncStep is the only defined step.
const SyncStep = "update"

// SyncOp identifies the kind of sync operation.
type SyncOp string

// Defined sync operations.
const (
	OpAdd    SyncOp = "add"
	OpRemove SyncOp = "remove"
	OpModify SyncOp = "modify"
)

// SyncOperation is one entry in a SyncMessage's operations array.
type SyncOperation struct {
	Op      SyncOp      `json:"op"`
	EntryID string      `json:"entry_id,omitempty"` // for remove and modify
	Entry   *BlockEntry `json:"entry,omitempty"`    // for add and modify
}

// SyncMessage is the SEMP_BLOCK sync message used to propagate block list
// changes from a client to its home server and onward to the user's other
// devices (DELIVERY.md §6.1).
//
// The message MUST be signed by the originating device's key. The home
// server MUST verify the signature before storing or propagating
// (DELIVERY.md §6.2, §8.2).
type SyncMessage struct {
	Type        string                    `json:"type"`
	Step        string                    `json:"step"`
	Version     string                    `json:"version"`
	UserID      string                    `json:"user_id"`
	DeviceID    string                    `json:"device_id"`
	ListVersion uint64                    `json:"list_version"`
	Timestamp   time.Time                 `json:"timestamp"`
	Operations  []SyncOperation           `json:"operations"`
	Signature   keys.PublicationSignature `json:"signature"`
}

// canonicalSyncMessageBytes returns the canonical JSON form of m with
// signature.value elided — the same pattern used by observation,
// discovery, and revocation signing. The algorithm and key_id fields
// are preserved so an attacker cannot swap them without invalidating
// the signature.
func canonicalSyncMessageBytes(m *SyncMessage) ([]byte, error) {
	if m == nil {
		return nil, errors.New("delivery: nil sync message")
	}
	return canonical.MarshalWithElision(m, func(v any) error {
		top, ok := v.(map[string]any)
		if !ok {
			return fmt.Errorf("delivery: expected top-level object, got %T", v)
		}
		sig, ok := top["signature"].(map[string]any)
		if !ok {
			return errors.New("delivery: sync message has no signature object")
		}
		sig["value"] = ""
		return nil
	})
}

// Sign computes an Ed25519 signature over the canonical form of m
// with signature.value elided, and populates m.Signature. The private
// key is the originating device's identity key — DELIVERY.md §6.2
// requires every sync message to be signed by the device that
// produced the update.
//
// Sign also fills in m.Type, m.Step, and m.Version if they are empty
// so callers don't have to remember the wire discriminators.
func (m *SyncMessage) Sign(signer crypto.Signer, devicePrivKey []byte, deviceKeyID keys.Fingerprint) error {
	if signer == nil {
		return errors.New("delivery: nil signer")
	}
	if m == nil {
		return errors.New("delivery: nil sync message")
	}
	if len(devicePrivKey) == 0 {
		return errors.New("delivery: empty device private key")
	}
	if m.Type == "" {
		m.Type = SyncMessageType
	}
	if m.Step == "" {
		m.Step = SyncStep
	}
	if m.Version == "" {
		m.Version = "1.0.0"
	}
	m.Signature.Algorithm = keys.SignatureAlgorithmEd25519
	m.Signature.KeyID = deviceKeyID
	msg, err := canonicalSyncMessageBytes(m)
	if err != nil {
		return fmt.Errorf("delivery: canonical sync message: %w", err)
	}
	sigBytes, err := signer.Sign(devicePrivKey, msg)
	if err != nil {
		return fmt.Errorf("delivery: sign sync message: %w", err)
	}
	m.Signature.Value = base64.StdEncoding.EncodeToString(sigBytes)
	return nil
}

// Verify checks the signature on a SyncMessage against the
// originating device's public key. Returns nil if the signature is
// valid; returns an error otherwise. Per DELIVERY.md §6.2 + §8.2,
// the home server MUST call Verify before storing or propagating the
// sync message. Unsigned or unverifiable sync messages MUST be
// rejected.
func (m *SyncMessage) Verify(signer crypto.Signer, devicePubKey []byte) error {
	if signer == nil {
		return errors.New("delivery: nil signer")
	}
	if m == nil {
		return errors.New("delivery: nil sync message")
	}
	if m.Signature.Value == "" {
		return errors.New("delivery: sync message is unsigned")
	}
	if len(devicePubKey) == 0 {
		return errors.New("delivery: empty device public key")
	}
	sigBytes, err := base64.StdEncoding.DecodeString(m.Signature.Value)
	if err != nil {
		return fmt.Errorf("delivery: sync signature base64: %w", err)
	}
	msg, err := canonicalSyncMessageBytes(m)
	if err != nil {
		return fmt.Errorf("delivery: canonical sync message: %w", err)
	}
	if err := signer.Verify(devicePubKey, msg, sigBytes); err != nil {
		return fmt.Errorf("delivery: verify sync message: %w", err)
	}
	return nil
}
