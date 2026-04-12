package handshake_test

import (
	"encoding/json"
	"testing"

	"semp.dev/semp-go/handshake"
)

// FuzzClientInitUnmarshal feeds arbitrary bytes into a ClientInit
// JSON decode. The guarantee is that json.Unmarshal into the struct
// never panics, regardless of input shape. Successful parses must
// also survive a re-marshal round-trip without changing the canonical
// structural fields (type, step, party).
func FuzzClientInitUnmarshal(f *testing.F) {
	f.Add([]byte(`{
		"type":"SEMP_HANDSHAKE",
		"step":"init",
		"party":"client",
		"version":"1.0.0",
		"nonce":"AAECAwQFBgcICQoLDA0ODw==",
		"transport":"ws",
		"capabilities":{},
		"extensions":{}
	}`))
	f.Add([]byte(`{"type":"SEMP_HANDSHAKE","step":"init"}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`"not an object"`))

	f.Fuzz(func(t *testing.T, data []byte) {
		var init handshake.ClientInit
		if err := json.Unmarshal(data, &init); err != nil {
			return
		}
		// A successful Unmarshal should itself be able to re-marshal
		// into valid JSON that parses back into the same struct.
		out, err := json.Marshal(init)
		if err != nil {
			t.Fatalf("re-Marshal failed: %v", err)
		}
		var init2 handshake.ClientInit
		if err := json.Unmarshal(out, &init2); err != nil {
			t.Fatalf("re-Unmarshal failed: %v\nbytes=%s", err, out)
		}
		if init.Type != init2.Type || init.Step != init2.Step || init.Party != init2.Party {
			t.Errorf("round-trip mismatch on discriminators:\n a=%+v\n b=%+v", init, init2)
		}
	})
}

// FuzzVerifySolution feeds arbitrary (prefix, challengeID, nonce,
// hash, difficulty) combinations to handshake.VerifySolution. The
// guarantee is no panic; verification failures are expected and fine.
func FuzzVerifySolution(f *testing.F) {
	// Canonical seed: short fields at easy difficulty. These will
	// almost always fail verification (the seed is not an actual
	// solution) but they exercise every code path in VerifySolution.
	f.Add([]byte("0123456789abcdef"), "ch-1", "AAECAwQFBgc=", "0000000000000000000000000000000000000000000000000000000000000000", 4)
	f.Add([]byte(""), "", "", "", 0)
	f.Add([]byte("short"), "id", "not-base64!", "nothex", -1)
	f.Add(bytes16(), "long-challenge-id", "MTIzNDU2Nzg=", "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 256)

	f.Fuzz(func(t *testing.T, prefix []byte, challengeID, nonceB64, hashHex string, difficulty int) {
		// No panic allowed; any error is fine.
		_ = handshake.VerifySolution(prefix, challengeID, nonceB64, hashHex, difficulty)
	})
}

// FuzzLeadingZeroBits asserts the popcount helper never returns a
// value outside [0, 8*len(hash)] and never panics. Seeds include
// all-zero, all-one, and mixed patterns at several lengths.
func FuzzLeadingZeroBits(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte{0x00})
	f.Add([]byte{0x00, 0x00, 0x00, 0x00})
	f.Add([]byte{0xff, 0xff})
	f.Add([]byte{0x00, 0x80})
	f.Add(bytes16())

	f.Fuzz(func(t *testing.T, hash []byte) {
		bits := handshake.LeadingZeroBits(hash)
		if bits < 0 {
			t.Errorf("LeadingZeroBits returned negative: %d", bits)
		}
		if max := 8 * len(hash); bits > max {
			t.Errorf("LeadingZeroBits returned %d > 8*len = %d", bits, max)
		}
	})
}

// bytes16 returns a 16-byte seed value.
func bytes16() []byte {
	return []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
}
