package handshake_test

import (
	"encoding/base64"
	"strings"
	"testing"

	"semp.dev/semp-go/handshake"
)

func TestComputeFirstContactPrefixBindsTriple(t *testing.T) {
	prefix, err := handshake.ComputeFirstContactPrefix("sender.example", "alice@recipient.example", "01HT-POSTMARK")
	if err != nil {
		t.Fatalf("ComputeFirstContactPrefix: %v", err)
	}
	if len(prefix) != handshake.FirstContactPrefixRandBytes+handshake.FirstContactBindingHashSize {
		t.Errorf("prefix length = %d, want %d",
			len(prefix),
			handshake.FirstContactPrefixRandBytes+handshake.FirstContactBindingHashSize)
	}

	// The same triple verifies against any prefix produced for it.
	if err := handshake.VerifyFirstContactBinding(prefix, "sender.example", "alice@recipient.example", "01HT-POSTMARK"); err != nil {
		t.Errorf("VerifyFirstContactBinding on matching triple: %v", err)
	}

	// A different postmark_id does not verify (the critical property).
	if err := handshake.VerifyFirstContactBinding(prefix, "sender.example", "alice@recipient.example", "01HT-DIFFERENT"); err == nil {
		t.Errorf("VerifyFirstContactBinding on different postmark_id: want error, got nil")
	}

	// A different sender_domain does not verify.
	if err := handshake.VerifyFirstContactBinding(prefix, "other.example", "alice@recipient.example", "01HT-POSTMARK"); err == nil {
		t.Errorf("VerifyFirstContactBinding on different sender_domain: want error, got nil")
	}

	// A different recipient_address does not verify.
	if err := handshake.VerifyFirstContactBinding(prefix, "sender.example", "bob@recipient.example", "01HT-POSTMARK"); err == nil {
		t.Errorf("VerifyFirstContactBinding on different recipient_address: want error, got nil")
	}
}

func TestComputeFirstContactPrefixFreshRandom(t *testing.T) {
	// Two prefixes for the same triple MUST differ (the 16-byte
	// random nonce ensures uniqueness).
	a, err := handshake.ComputeFirstContactPrefix("sender.example", "alice@recipient.example", "01HT")
	if err != nil {
		t.Fatalf("ComputeFirstContactPrefix a: %v", err)
	}
	b, err := handshake.ComputeFirstContactPrefix("sender.example", "alice@recipient.example", "01HT")
	if err != nil {
		t.Fatalf("ComputeFirstContactPrefix b: %v", err)
	}
	if string(a) == string(b) {
		t.Error("two prefixes for the same triple are equal; random nonce not applied")
	}
}

func TestComputeFirstContactPrefixRejectsEmpty(t *testing.T) {
	_, err := handshake.ComputeFirstContactPrefix("", "alice@r.example", "pm")
	if err == nil {
		t.Error("empty sender_domain: want error, got nil")
	}
	_, err = handshake.ComputeFirstContactPrefix("s.example", "", "pm")
	if err == nil {
		t.Error("empty recipient_address: want error, got nil")
	}
	_, err = handshake.ComputeFirstContactPrefix("s.example", "alice@r.example", "")
	if err == nil {
		t.Error("empty postmark_id: want error, got nil")
	}
}

func TestVerifyFirstContactBindingRejectsShortPrefix(t *testing.T) {
	err := handshake.VerifyFirstContactBinding([]byte{0x01, 0x02}, "s.example", "alice@r.example", "pm")
	if err == nil || !strings.Contains(err.Error(), "too short") {
		t.Errorf("VerifyFirstContactBinding on short prefix: got %v, want 'too short' error", err)
	}
}

func TestDecodeFirstContactPrefix(t *testing.T) {
	raw := []byte("any-bytes-here-abcdefghij")
	b64 := base64.StdEncoding.EncodeToString(raw)
	got, err := handshake.DecodeFirstContactPrefix(b64)
	if err != nil {
		t.Fatalf("DecodeFirstContactPrefix: %v", err)
	}
	if string(got) != string(raw) {
		t.Errorf("round-trip mismatch: got %q, want %q", got, raw)
	}
	if _, err := handshake.DecodeFirstContactPrefix("not valid base64!!"); err == nil {
		t.Error("DecodeFirstContactPrefix on invalid base64: want error")
	}
}
