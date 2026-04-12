package envelope

import (
	"strings"
	"testing"
	"time"

	"semp.dev/semp-go/seal"
)

// TestEncodeDecodeRoundTrip confirms that an Envelope round-trips losslessly
// through Encode and Decode.
func TestEncodeDecodeRoundTrip(t *testing.T) {
	hop := 3
	src := New()
	src.Postmark = Postmark{
		ID:         "01J4K7P2XVEM3Q8YNZHBRC5T06",
		SessionID:  "01J4K7Q0ABCDEFGHJKLMNPQRST",
		FromDomain: "sender.example",
		ToDomain:   "recipient.example",
		Expires:    time.Date(2025, 6, 10, 21, 0, 0, 0, time.UTC),
		HopCount:   &hop,
	}
	src.Seal = seal.Seal{
		Algorithm:           "x25519-chacha20-poly1305",
		KeyID:               "deadbeef",
		Signature:           "c2lnLW5pbA==",
		SessionMAC:          "bWFjLW5pbA==",
		BriefRecipients:     seal.RecipientMap{"fp1": "wrapped1"},
		EnclosureRecipients: seal.RecipientMap{"fp1": "wrapped2"},
	}
	src.Brief = "ZW5jcnlwdGVkLWJyaWVm"
	src.Enclosure = "ZW5jcnlwdGVkLWVuY2xvc3VyZQ=="

	encoded, err := Encode(src)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if !strings.Contains(string(encoded), `"type":"SEMP_ENVELOPE"`) {
		t.Errorf("Encode output missing type discriminator: %s", encoded)
	}

	got, err := Decode(encoded)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Type != src.Type {
		t.Errorf("Type mismatch: %q vs %q", got.Type, src.Type)
	}
	if got.Postmark.ID != src.Postmark.ID {
		t.Errorf("Postmark.ID mismatch")
	}
	if got.Postmark.HopCount == nil || *got.Postmark.HopCount != 3 {
		t.Errorf("HopCount round-trip lost: %v", got.Postmark.HopCount)
	}
	if got.Seal.BriefRecipients["fp1"] != "wrapped1" {
		t.Errorf("BriefRecipients mismatch")
	}
	if got.Brief != src.Brief {
		t.Errorf("Brief mismatch")
	}
}

// TestDecodeRejectsWrongType ensures Decode flags a non-SEMP_ENVELOPE input.
func TestDecodeRejectsWrongType(t *testing.T) {
	if _, err := Decode([]byte(`{"type":"WRONG","version":"1.0.0"}`)); err == nil {
		t.Error("Decode accepted wrong type")
	}
}

// TestDecodeRejectsEmpty ensures Decode flags an empty input.
func TestDecodeRejectsEmpty(t *testing.T) {
	if _, err := Decode(nil); err == nil {
		t.Error("Decode accepted nil input")
	}
	if _, err := Decode([]byte{}); err == nil {
		t.Error("Decode accepted empty input")
	}
}

// TestCanonicalBytesElidesSealAndHopCount confirms that CanonicalBytes
// returns the form fed into seal signing: signature/session_mac empty,
// hop_count omitted.
func TestCanonicalBytesElidesSealAndHopCount(t *testing.T) {
	hop := 7
	e := New()
	e.Postmark = Postmark{
		ID:         "id",
		SessionID:  "sid",
		FromDomain: "a.example",
		ToDomain:   "b.example",
		Expires:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		HopCount:   &hop,
	}
	e.Seal = seal.Seal{
		Algorithm:           "x25519-chacha20-poly1305",
		KeyID:               "kid",
		Signature:           "MUST-BE-ELIDED",
		SessionMAC:          "MUST-BE-ELIDED",
		BriefRecipients:     seal.RecipientMap{},
		EnclosureRecipients: seal.RecipientMap{},
	}
	e.Brief = "Yg=="
	e.Enclosure = "ZQ=="

	out, err := e.CanonicalBytes()
	if err != nil {
		t.Fatalf("CanonicalBytes: %v", err)
	}
	s := string(out)
	if strings.Contains(s, "MUST-BE-ELIDED") {
		t.Errorf("canonical bytes still contain non-elided signature/MAC: %s", s)
	}
	if !strings.Contains(s, `"signature":""`) {
		t.Errorf(`canonical bytes missing signature:"" : %s`, s)
	}
	if !strings.Contains(s, `"session_mac":""`) {
		t.Errorf(`canonical bytes missing session_mac:"" : %s`, s)
	}
	if strings.Contains(s, `"hop_count"`) {
		t.Errorf("canonical bytes still contain hop_count: %s", s)
	}
}
