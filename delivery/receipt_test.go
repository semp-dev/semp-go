package delivery_test

import (
	"encoding/json"
	"testing"
	"time"

	"semp.dev/semp-go/crypto"
	"semp.dev/semp-go/delivery"
)

func TestDeliveryReceiptRoundTrip(t *testing.T) {
	signer := crypto.SuiteBaseline.Signer()
	pub, priv, err := signer.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	keyID := "domain-key-fp"

	canonicalBytes := []byte(`{"canonical":"envelope-bytes"}`)
	r := &delivery.DeliveryReceipt{
		EnvelopeHash: delivery.EnvelopeHash{
			Algorithm: delivery.EnvelopeHashAlgorithmSHA256,
			Value:     delivery.ComputeEnvelopeHash(canonicalBytes),
		},
		RecipientDomain: "recipient.example",
		AcceptedAt:      time.Now().UTC().Truncate(time.Second),
	}
	if err := delivery.SignDeliveryReceipt(signer, priv, keyID, r); err != nil {
		t.Fatalf("SignDeliveryReceipt: %v", err)
	}
	if r.Signature.Value == "" {
		t.Fatal("Signature.Value not populated after SignDeliveryReceipt")
	}
	if err := delivery.VerifyDeliveryReceipt(signer, pub, r); err != nil {
		t.Errorf("VerifyDeliveryReceipt: %v", err)
	}
	if err := delivery.VerifyEnvelopeBinding(r, canonicalBytes); err != nil {
		t.Errorf("VerifyEnvelopeBinding: %v", err)
	}
}

func TestDeliveryReceiptTamperBreaksSignature(t *testing.T) {
	signer := crypto.SuiteBaseline.Signer()
	pub, priv, _ := signer.GenerateKeyPair()
	r := &delivery.DeliveryReceipt{
		EnvelopeHash: delivery.EnvelopeHash{
			Algorithm: delivery.EnvelopeHashAlgorithmSHA256,
			Value:     delivery.ComputeEnvelopeHash([]byte("bytes")),
		},
		RecipientDomain: "recipient.example",
		AcceptedAt:      time.Now().UTC().Truncate(time.Second),
	}
	if err := delivery.SignDeliveryReceipt(signer, priv, "fp", r); err != nil {
		t.Fatalf("SignDeliveryReceipt: %v", err)
	}

	// Tamper accepted_at.
	r.AcceptedAt = r.AcceptedAt.Add(time.Hour)
	if err := delivery.VerifyDeliveryReceipt(signer, pub, r); err == nil {
		t.Error("VerifyDeliveryReceipt accepted a tampered AcceptedAt")
	}
}

func TestVerifyEnvelopeBindingDetectsMismatch(t *testing.T) {
	r := &delivery.DeliveryReceipt{
		EnvelopeHash: delivery.EnvelopeHash{
			Algorithm: delivery.EnvelopeHashAlgorithmSHA256,
			Value:     delivery.ComputeEnvelopeHash([]byte("envelope-A")),
		},
	}
	// Verifier holds envelope-B; binding fails.
	if err := delivery.VerifyEnvelopeBinding(r, []byte("envelope-B")); err == nil {
		t.Error("VerifyEnvelopeBinding accepted mismatched envelope bytes")
	}
}

func TestUserPolicyRoundTrip(t *testing.T) {
	signer := crypto.SuiteBaseline.Signer()
	pub, priv, err := signer.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	addEntry := json.RawMessage(`{"id":"01JBLOCK000000000000000001","entity":{"type":"user","address":"spammer@example.com"}}`)
	m := &delivery.UserPolicyMessage{
		UserID:        "alice@example.com",
		DeviceID:      "alice-laptop",
		PolicyVersion: 42,
		Timestamp:     time.Now().UTC(),
		Operations: []delivery.PolicyOperation{
			{Op: delivery.PolicyOpAdd, Kind: delivery.PolicyKindBlock, Entry: addEntry},
			{Op: delivery.PolicyOpRemove, Kind: delivery.PolicyKindAcceptedSender, EntryID: "old-sender-fp"},
		},
	}
	if err := delivery.SignUserPolicyMessage(signer, priv, "device-fp", m); err != nil {
		t.Fatalf("SignUserPolicyMessage: %v", err)
	}
	if err := delivery.VerifyUserPolicyMessage(signer, pub, m); err != nil {
		t.Errorf("VerifyUserPolicyMessage: %v", err)
	}
}

func TestUserPolicyValidateRejects(t *testing.T) {
	now := time.Now().UTC()
	cases := []struct {
		name string
		m    *delivery.UserPolicyMessage
	}{
		{"missing user_id", &delivery.UserPolicyMessage{
			Type: delivery.UserPolicyType, Step: delivery.UserPolicyStep, Version: delivery.UserPolicyVersion,
			DeviceID: "d", PolicyVersion: 1, Timestamp: now,
			Operations: []delivery.PolicyOperation{{Op: "add", Kind: "semp.dev/block", Entry: json.RawMessage(`{}`)}},
		}},
		{"version=0", &delivery.UserPolicyMessage{
			Type: delivery.UserPolicyType, Step: delivery.UserPolicyStep, Version: delivery.UserPolicyVersion,
			UserID: "u", DeviceID: "d", PolicyVersion: 0, Timestamp: now,
			Operations: []delivery.PolicyOperation{{Op: "add", Kind: "semp.dev/block", Entry: json.RawMessage(`{}`)}},
		}},
		{"empty operations", &delivery.UserPolicyMessage{
			Type: delivery.UserPolicyType, Step: delivery.UserPolicyStep, Version: delivery.UserPolicyVersion,
			UserID: "u", DeviceID: "d", PolicyVersion: 1, Timestamp: now,
		}},
		{"singleton add rejected", &delivery.UserPolicyMessage{
			Type: delivery.UserPolicyType, Step: delivery.UserPolicyStep, Version: delivery.UserPolicyVersion,
			UserID: "u", DeviceID: "d", PolicyVersion: 1, Timestamp: now,
			Operations: []delivery.PolicyOperation{
				{Op: delivery.PolicyOpAdd, Kind: delivery.PolicyKindFirstContact, Entry: json.RawMessage(`{}`)},
			},
		}},
		{"remove without entry_id", &delivery.UserPolicyMessage{
			Type: delivery.UserPolicyType, Step: delivery.UserPolicyStep, Version: delivery.UserPolicyVersion,
			UserID: "u", DeviceID: "d", PolicyVersion: 1, Timestamp: now,
			Operations: []delivery.PolicyOperation{
				{Op: delivery.PolicyOpRemove, Kind: delivery.PolicyKindBlock},
			},
		}},
		{"add without entry", &delivery.UserPolicyMessage{
			Type: delivery.UserPolicyType, Step: delivery.UserPolicyStep, Version: delivery.UserPolicyVersion,
			UserID: "u", DeviceID: "d", PolicyVersion: 1, Timestamp: now,
			Operations: []delivery.PolicyOperation{
				{Op: delivery.PolicyOpAdd, Kind: delivery.PolicyKindBlock},
			},
		}},
		{"unknown op", &delivery.UserPolicyMessage{
			Type: delivery.UserPolicyType, Step: delivery.UserPolicyStep, Version: delivery.UserPolicyVersion,
			UserID: "u", DeviceID: "d", PolicyVersion: 1, Timestamp: now,
			Operations: []delivery.PolicyOperation{
				{Op: "rebind", Kind: delivery.PolicyKindBlock, Entry: json.RawMessage(`{}`)},
			},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.m.Validate(); err == nil {
				t.Error("Validate accepted invalid user policy message")
			}
		})
	}
}

func TestUserPolicyTamperBreaksSignature(t *testing.T) {
	signer := crypto.SuiteBaseline.Signer()
	pub, priv, _ := signer.GenerateKeyPair()
	m := &delivery.UserPolicyMessage{
		UserID:        "alice@example.com",
		DeviceID:      "d",
		PolicyVersion: 1,
		Timestamp:     time.Now().UTC(),
		Operations: []delivery.PolicyOperation{
			{Op: delivery.PolicyOpAdd, Kind: delivery.PolicyKindBlock, Entry: json.RawMessage(`{}`)},
		},
	}
	if err := delivery.SignUserPolicyMessage(signer, priv, "fp", m); err != nil {
		t.Fatalf("SignUserPolicyMessage: %v", err)
	}
	m.PolicyVersion = 99
	if err := delivery.VerifyUserPolicyMessage(signer, pub, m); err == nil {
		t.Error("VerifyUserPolicyMessage accepted a tampered PolicyVersion")
	}
}
