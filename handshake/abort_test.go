package handshake_test

import (
	"encoding/json"
	"testing"

	semp "semp.dev/semp-go"
	"semp.dev/semp-go/handshake"
)

func TestNewClientRejectionUnsignedAndPartyClient(t *testing.T) {
	out, err := handshake.NewClientRejection(string(semp.ReasonChallengeInvalid), "difficulty 30 exceeds cap 28")
	if err != nil {
		t.Fatalf("NewClientRejection: %v", err)
	}
	var rej handshake.Rejected
	if err := json.Unmarshal(out, &rej); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if rej.Type != handshake.MessageType {
		t.Errorf("Type = %q, want %q", rej.Type, handshake.MessageType)
	}
	if rej.Step != handshake.StepRejected {
		t.Errorf("Step = %q, want %q", rej.Step, handshake.StepRejected)
	}
	if rej.Party != handshake.PartyClient {
		t.Errorf("Party = %q, want %q", rej.Party, handshake.PartyClient)
	}
	if rej.ReasonCode != string(semp.ReasonChallengeInvalid) {
		t.Errorf("ReasonCode = %q, want challenge_invalid", rej.ReasonCode)
	}
	if rej.ServerSignature != "" {
		t.Errorf("ServerSignature = %q, want empty (client aborts are unsigned)", rej.ServerSignature)
	}
	// Confirm the JSON output does not carry a `server_signature`
	// field at all (omitempty effect). The unsigned form leaks no
	// identity hint to the server.
	rawMap := map[string]any{}
	if err := json.Unmarshal(out, &rawMap); err != nil {
		t.Fatalf("raw unmarshal: %v", err)
	}
	if _, present := rawMap["server_signature"]; present {
		t.Error("raw JSON contains server_signature; client abort must omit it")
	}
}

func TestNewClientRejectionRejectsEmptyReasonCode(t *testing.T) {
	_, err := handshake.NewClientRejection("", "whatever")
	if err == nil {
		t.Error("NewClientRejection with empty reason_code: want error")
	}
}

func TestChallengeInvalidErrorIs(t *testing.T) {
	err := &handshake.ChallengeInvalidError{Reason: "test"}
	if !handshake.IsChallengeInvalid(err) {
		t.Error("IsChallengeInvalid on direct ChallengeInvalidError: want true")
	}
	other := errStub("something else")
	if handshake.IsChallengeInvalid(other) {
		t.Error("IsChallengeInvalid on unrelated error: want false")
	}
}

type errStub string

func (e errStub) Error() string { return string(e) }
