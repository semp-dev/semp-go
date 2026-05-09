package canonical

import (
	"encoding/json"
	"testing"
)

// TestMarshalDeterministic confirms that Marshal produces the same bytes
// for the same logical input regardless of the original key insertion
// order. This is the core property the seal layer depends on: signing
// and re-signing the same envelope must produce the same bytes.
func TestMarshalDeterministic(t *testing.T) {
	a := map[string]any{
		"zebra":  1,
		"apple":  2,
		"middle": 3,
	}
	b := map[string]any{
		"middle": 3,
		"apple":  2,
		"zebra":  1,
	}
	x, err := Marshal(a)
	if err != nil {
		t.Fatalf("Marshal a: %v", err)
	}
	y, err := Marshal(b)
	if err != nil {
		t.Fatalf("Marshal b: %v", err)
	}
	if string(x) != string(y) {
		t.Errorf("non-deterministic output:\n  %s\n  %s", x, y)
	}
	const want = `{"apple":2,"middle":3,"zebra":1}`
	if string(x) != want {
		t.Errorf("want %s, got %s", want, x)
	}
}

// TestMarshalNestedSorting confirms that nested objects are also sorted.
func TestMarshalNestedSorting(t *testing.T) {
	in := map[string]any{
		"outer": map[string]any{
			"z": 1,
			"a": 2,
		},
		"another": "value",
	}
	out, err := Marshal(in)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	const want = `{"another":"value","outer":{"a":2,"z":1}}`
	if string(out) != want {
		t.Errorf("want %s, got %s", want, out)
	}
}

// TestMarshalArraysPreserveOrder confirms array order is preserved.
func TestMarshalArraysPreserveOrder(t *testing.T) {
	in := []any{"c", "a", "b"}
	out, err := Marshal(in)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	const want = `["c","a","b"]`
	if string(out) != want {
		t.Errorf("want %s, got %s", want, out)
	}
}

// TestEnvelopeElider confirms the elider sets seal.signature and
// seal.session_mac to "" and removes postmark.hop_count.
func TestEnvelopeElider(t *testing.T) {
	const input = `{
		"postmark": {"hop_count": 5, "id": "abc"},
		"seal": {"signature": "abc", "session_mac": "def", "key_id": "k"}
	}`
	var v any
	if err := json.Unmarshal([]byte(input), &v); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	out, err := MarshalWithElision(v, EnvelopeElider())
	if err != nil {
		t.Fatalf("MarshalWithElision: %v", err)
	}
	const want = `{"postmark":{"id":"abc"},"seal":{"key_id":"k","session_mac":"","signature":""}}`
	if string(out) != want {
		t.Errorf("want %s, got %s", want, out)
	}
}

// TestHandshakeMessageElider strips server_signature.
func TestHandshakeMessageElider(t *testing.T) {
	const input = `{"type":"SEMP_HANDSHAKE","server_signature":"abc","data":"x"}`
	var v any
	if err := json.Unmarshal([]byte(input), &v); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	out, err := MarshalWithElision(v, HandshakeMessageElider())
	if err != nil {
		t.Fatalf("MarshalWithElision: %v", err)
	}
	const want = `{"data":"x","type":"SEMP_HANDSHAKE"}`
	if string(out) != want {
		t.Errorf("want %s, got %s", want, out)
	}
}

// TestHash returns SHA-256 of the input.
func TestHash(t *testing.T) {
	// Empty input → known SHA-256: e3b0c44298fc1c149afbf4c8996fb924...
	got := Hash([]byte{})
	const wantHex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	gotHex := bytesToHex(got)
	if gotHex != wantHex {
		t.Errorf("SHA-256(empty) = %s, want %s", gotHex, wantHex)
	}
}

func bytesToHex(b []byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, x := range b {
		out[i*2] = hexdigits[x>>4]
		out[i*2+1] = hexdigits[x&0x0f]
	}
	return string(out)
}
