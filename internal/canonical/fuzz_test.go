package canonical_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/semp-dev/semp-go/internal/canonical"
)

// FuzzCanonicalMarshal feeds arbitrary JSON bytes to canonical.Marshal
// and asserts two properties:
//
//  1. Marshal never panics on any input that json.Unmarshal accepts.
//  2. Marshal is deterministic: re-canonicalizing its own output
//     produces byte-identical results.
//
// Seeds cover a range of JSON shapes including nested maps (which
// exercise the key-sorting path), arrays (which must preserve order),
// and edge-case values (null, numbers, escaped strings).
func FuzzCanonicalMarshal(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`null`))
	f.Add([]byte(`true`))
	f.Add([]byte(`false`))
	f.Add([]byte(`0`))
	f.Add([]byte(`"hello"`))
	f.Add([]byte(`{"a":1,"b":2}`))
	f.Add([]byte(`{"b":2,"a":1}`))
	f.Add([]byte(`{"nested":{"z":1,"a":2},"arr":[3,1,2]}`))
	f.Add([]byte(`{"utf8":"héllo","escape":"\"quoted\""}`))
	f.Add([]byte(`{"num":3.14159,"big":12345678901234}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		var v any
		if err := json.Unmarshal(data, &v); err != nil {
			// Not valid JSON — canonical.Marshal is not required to
			// handle raw bytes that wouldn't have come from a
			// legitimate encoding/json producer.
			return
		}
		first, err := canonical.Marshal(v)
		if err != nil {
			// Shape-level rejection is fine; just make sure no
			// output was produced alongside the error.
			if first != nil {
				t.Errorf("Marshal returned bytes alongside error: %v", err)
			}
			return
		}
		// Determinism: marshaling the same value again should yield
		// the same bytes.
		second, err := canonical.Marshal(v)
		if err != nil {
			t.Fatalf("second Marshal after success: %v", err)
		}
		if !bytes.Equal(first, second) {
			t.Errorf("Marshal not deterministic:\n a=%s\n b=%s", first, second)
		}
		// Idempotence: re-parsing the canonical output and
		// canonicalizing again must match the first output.
		var reparsed any
		if err := json.Unmarshal(first, &reparsed); err != nil {
			t.Fatalf("canonical output is not valid JSON: %v\nbytes: %s", err, first)
		}
		third, err := canonical.Marshal(reparsed)
		if err != nil {
			t.Fatalf("Marshal of reparsed canonical bytes: %v", err)
		}
		if !bytes.Equal(first, third) {
			t.Errorf("Marshal not idempotent:\n a=%s\n c=%s", first, third)
		}
	})
}

// FuzzCanonicalHash confirms Hash never panics and always returns a
// 32-byte SHA-256 digest for any input.
func FuzzCanonicalHash(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte("hello"))
	f.Add([]byte{0x00, 0x01, 0xff})

	f.Fuzz(func(t *testing.T, data []byte) {
		sum := canonical.Hash(data)
		if len(sum) != 32 {
			t.Errorf("Hash returned %d bytes, want 32", len(sum))
		}
	})
}
