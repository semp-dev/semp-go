package delivery_test

import (
	"strings"
	"testing"
	"time"

	semp "github.com/semp-dev/semp-go"
	"github.com/semp-dev/semp-go/crypto"
	"github.com/semp-dev/semp-go/delivery"
	"github.com/semp-dev/semp-go/keys"
)

// newDeviceKeypair generates an Ed25519 keypair for a device.
func newDeviceKeypair(t *testing.T) (pub, priv []byte, fp keys.Fingerprint) {
	t.Helper()
	pub, priv, err := crypto.SuiteBaseline.Signer().GenerateKeyPair()
	if err != nil {
		t.Fatalf("device keypair: %v", err)
	}
	return pub, priv, keys.Compute(pub)
}

// sampleSyncMessage builds a minimal SyncMessage with one add
// operation ready for signing.
func sampleSyncMessage() *delivery.SyncMessage {
	return &delivery.SyncMessage{
		Type:        delivery.SyncMessageType,
		Step:        delivery.SyncStep,
		Version:     "1.0.0",
		UserID:      "alice@example.com",
		DeviceID:    "01JDEVICE00000000000000001",
		ListVersion: 42,
		Timestamp:   time.Date(2026, 4, 12, 12, 0, 0, 0, time.UTC),
		Operations: []delivery.SyncOperation{
			{
				Op: delivery.OpAdd,
				Entry: &delivery.BlockEntry{
					ID: "block-1",
					Entity: delivery.Entity{
						Type:    delivery.EntityUser,
						Address: "spammer@evil.example",
					},
					Acknowledgment: semp.AckRejected,
					Scope:          delivery.ScopeAll,
					CreatedAt:      time.Date(2026, 4, 12, 12, 0, 0, 0, time.UTC),
				},
			},
		},
	}
}

// TestSyncMessageSignVerifyRoundTrip confirms Sign + Verify under
// the same device key succeeds.
func TestSyncMessageSignVerifyRoundTrip(t *testing.T) {
	pub, priv, fp := newDeviceKeypair(t)
	msg := sampleSyncMessage()

	if err := msg.Sign(crypto.SuiteBaseline.Signer(), priv, fp); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if msg.Signature.Value == "" {
		t.Error("signature value is empty after Sign")
	}
	if msg.Signature.Algorithm != keys.SignatureAlgorithmEd25519 {
		t.Errorf("algorithm = %s, want ed25519", msg.Signature.Algorithm)
	}
	if msg.Signature.KeyID != fp {
		t.Errorf("key_id = %s, want %s", msg.Signature.KeyID, fp)
	}
	if err := msg.Verify(crypto.SuiteBaseline.Signer(), pub); err != nil {
		t.Errorf("Verify: %v", err)
	}
}

// TestSyncMessageVerifyRejectsTamper confirms mutating any covered
// field after signing breaks verification. Per §8.2 the server MUST
// reject unsigned or unverifiable sync messages.
func TestSyncMessageVerifyRejectsTamper(t *testing.T) {
	pub, priv, fp := newDeviceKeypair(t)

	tests := []struct {
		name   string
		mutate func(*delivery.SyncMessage)
	}{
		{"user_id", func(m *delivery.SyncMessage) { m.UserID = "bob@example.com" }},
		{"device_id", func(m *delivery.SyncMessage) { m.DeviceID = "attacker-device" }},
		{"list_version", func(m *delivery.SyncMessage) { m.ListVersion = 999 }},
		{"timestamp", func(m *delivery.SyncMessage) { m.Timestamp = m.Timestamp.Add(time.Hour) }},
		{"operation", func(m *delivery.SyncMessage) { m.Operations[0].Op = delivery.OpRemove }},
		{"entry address", func(m *delivery.SyncMessage) { m.Operations[0].Entry.Entity.Address = "other@evil.example" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			msg := sampleSyncMessage()
			if err := msg.Sign(crypto.SuiteBaseline.Signer(), priv, fp); err != nil {
				t.Fatalf("Sign: %v", err)
			}
			tc.mutate(msg)
			if err := msg.Verify(crypto.SuiteBaseline.Signer(), pub); err == nil {
				t.Errorf("tamper on %s should have broken verification", tc.name)
			}
		})
	}
}

// TestSyncMessageVerifyRejectsWrongKey confirms verification fails
// under a different device key.
func TestSyncMessageVerifyRejectsWrongKey(t *testing.T) {
	_, priv, fp := newDeviceKeypair(t)
	otherPub, _, _ := newDeviceKeypair(t)
	msg := sampleSyncMessage()
	_ = msg.Sign(crypto.SuiteBaseline.Signer(), priv, fp)
	if err := msg.Verify(crypto.SuiteBaseline.Signer(), otherPub); err == nil {
		t.Error("wrong device key should fail verification")
	}
}

// TestSyncMessageVerifyRejectsUnsigned confirms an unsigned message
// is rejected per §8.2 ("Unsigned sync messages MUST be rejected").
func TestSyncMessageVerifyRejectsUnsigned(t *testing.T) {
	pub, _, _ := newDeviceKeypair(t)
	msg := sampleSyncMessage()
	if err := msg.Verify(crypto.SuiteBaseline.Signer(), pub); err == nil {
		t.Error("unsigned sync message should be rejected")
	}
	if !strings.Contains(msg.Verify(crypto.SuiteBaseline.Signer(), pub).Error(), "unsigned") {
		t.Errorf("error should mention unsigned: %v", msg.Verify(crypto.SuiteBaseline.Signer(), pub))
	}
}

// TestSyncMessageSignFillsDefaults confirms Sign populates the
// wire-level type/step/version if empty, so callers don't have to
// remember the discriminators.
func TestSyncMessageSignFillsDefaults(t *testing.T) {
	_, priv, fp := newDeviceKeypair(t)
	msg := &delivery.SyncMessage{
		UserID:      "alice@example.com",
		DeviceID:    "dev-1",
		ListVersion: 1,
		Timestamp:   time.Now().UTC(),
		Operations:  []delivery.SyncOperation{{Op: delivery.OpRemove, EntryID: "b-1"}},
	}
	if err := msg.Sign(crypto.SuiteBaseline.Signer(), priv, fp); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if msg.Type != delivery.SyncMessageType {
		t.Errorf("Type = %q, want %q", msg.Type, delivery.SyncMessageType)
	}
	if msg.Step != delivery.SyncStep {
		t.Errorf("Step = %q, want %q", msg.Step, delivery.SyncStep)
	}
	if msg.Version != "1.0.0" {
		t.Errorf("Version = %q, want 1.0.0", msg.Version)
	}
}

// TestSyncMessageSignNilInputs confirms input validation.
func TestSyncMessageSignNilInputs(t *testing.T) {
	_, priv, fp := newDeviceKeypair(t)
	signer := crypto.SuiteBaseline.Signer()

	// Nil message.
	var nilMsg *delivery.SyncMessage
	if err := nilMsg.Sign(signer, priv, fp); err == nil {
		t.Error("nil message should error")
	}
	// Nil signer.
	msg := sampleSyncMessage()
	if err := msg.Sign(nil, priv, fp); err == nil {
		t.Error("nil signer should error")
	}
	// Empty private key.
	if err := msg.Sign(signer, nil, fp); err == nil {
		t.Error("empty private key should error")
	}
}

// TestSyncMessageVerifyNilInputs confirms input validation.
func TestSyncMessageVerifyNilInputs(t *testing.T) {
	pub, priv, fp := newDeviceKeypair(t)
	signer := crypto.SuiteBaseline.Signer()
	msg := sampleSyncMessage()
	_ = msg.Sign(signer, priv, fp)

	// Nil signer.
	if err := msg.Verify(nil, pub); err == nil {
		t.Error("nil signer should error")
	}
	// Empty public key.
	if err := msg.Verify(signer, nil); err == nil {
		t.Error("empty public key should error")
	}
	// Nil message.
	var nilMsg *delivery.SyncMessage
	if err := nilMsg.Verify(signer, pub); err == nil {
		t.Error("nil message should error")
	}
}

// TestSyncMessageMultipleOperations confirms a message with
// multiple operations (add + remove + modify) signs and verifies
// correctly — each operation is covered by the single signature.
func TestSyncMessageMultipleOperations(t *testing.T) {
	pub, priv, fp := newDeviceKeypair(t)
	msg := sampleSyncMessage()
	msg.Operations = append(msg.Operations,
		delivery.SyncOperation{
			Op:      delivery.OpRemove,
			EntryID: "block-old",
		},
		delivery.SyncOperation{
			Op:      delivery.OpModify,
			EntryID: "block-existing",
			Entry: &delivery.BlockEntry{
				ID:             "block-existing",
				Entity:         delivery.Entity{Type: delivery.EntityDomain, Domain: "spam.example"},
				Acknowledgment: semp.AckSilent,
				Scope:          delivery.ScopeAll,
				CreatedAt:      time.Now().UTC(),
			},
		},
	)
	if err := msg.Sign(crypto.SuiteBaseline.Signer(), priv, fp); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := msg.Verify(crypto.SuiteBaseline.Signer(), pub); err != nil {
		t.Errorf("Verify multi-op: %v", err)
	}
}
