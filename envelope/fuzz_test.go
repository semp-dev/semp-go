package envelope_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/semp-dev/semp-go/envelope"
)

// FuzzEnvelopeDecode feeds arbitrary bytes into envelope.Decode and
// asserts the parser never panics. A successful decode must be
// idempotent under Encode → Decode round-tripping.
//
// Seeds include a minimal well-formed envelope JSON so the fuzzer can
// mutate around it instead of exploring pure garbage.
func FuzzEnvelopeDecode(f *testing.F) {
	// Minimal-shape seed: every field Decode strictly requires.
	f.Add([]byte(`{
		"type": "SEMP_ENVELOPE",
		"version": "1.0.0",
		"postmark": {
			"id": "01JPOSTMARK0000000000000001",
			"session_id": "01JSESSION000000000000000001",
			"from_domain": "a.example",
			"to_domain": "b.example",
			"expires": "2030-01-01T00:00:00Z"
		},
		"seal": {
			"brief_recipients": {},
			"enclosure_recipients": {},
			"signature": "",
			"session_mac": ""
		},
		"brief": "QUJD",
		"enclosure": "QUJD"
	}`))
	// Missing fields — Decode should return an error, not panic.
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"type":"SEMP_ENVELOPE"}`))
	// Pure garbage.
	f.Add([]byte("not json at all"))
	f.Add([]byte(""))
	f.Add([]byte{0x00, 0x01, 0xff})

	f.Fuzz(func(t *testing.T, data []byte) {
		env, err := envelope.Decode(data)
		if err != nil {
			// Error path is fine; just require a nil envelope.
			if env != nil {
				t.Errorf("Decode returned envelope alongside error: %v", err)
			}
			return
		}
		// Success path: round-trip through Encode and Decode again.
		// The second decoded envelope MUST parse back identically.
		encoded, err := envelope.Encode(env)
		if err != nil {
			t.Fatalf("Encode after successful Decode failed: %v", err)
		}
		env2, err := envelope.Decode(encoded)
		if err != nil {
			t.Fatalf("Decode of re-encoded envelope failed: %v", err)
		}
		// Compare JSON canonicalizations of the two envelopes rather
		// than the envelopes themselves — the struct can carry
		// pointer-identity noise (e.g. Postmark.HopCount) that is
		// irrelevant to the wire format.
		a, _ := json.Marshal(env)
		b, _ := json.Marshal(env2)
		if !bytes.Equal(a, b) {
			t.Errorf("round-trip mismatch:\n a=%s\n b=%s", a, b)
		}
	})
}
