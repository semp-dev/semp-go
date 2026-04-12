package test

import (
	"encoding/hex"
	"testing"

	"semp.dev/semp-go/crypto"
)

// HKDF-SHA-512 session key derivation vector from VECTORS.md §2.1.
//
// IKM is 32 bytes of 0x0b followed by 32 bytes of 0x0c.
// Client nonce is 32 bytes of 0xaa.
// Server nonce is 32 bytes of 0xbb.
// Info labels are the five SEMP-v1-session-* strings from
// crypto/kdf.go.
var (
	vectorIKM = mustHex(
		"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b" +
			"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b" +
			"0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c" +
			"0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
	)
	vectorClientNonce = mustHex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	vectorServerNonce = mustHex("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")

	wantPRK = mustHex(
		"1ca5eed820a07ef313053ec19352a69c" +
			"6dd00c924139d012ff571faa55f07037" +
			"087ced0021ce2b853c3ee8ffeabea069" +
			"7586d06f989c315cab24859bb3b9ef6e",
	)

	wantEncC2S = mustHex("cf74d91d41de6ac8f838715bc44a31d7e23b8e9b4dd7dab6be6ad4b8d0567af6")
	wantEncS2C = mustHex("bed26f42d9b1762ab5665b429ef511316e2f9a9be7b4721a310488b3540f90cd")
	wantMacC2S = mustHex("7f7c8b61c27e91c160dba88063346afb920b99fa2736aa0c54b5d022ff58484e")
	wantMacS2C = mustHex("7905bf680e3095c0b71b4d331c2a586316171ab6ad072842b5bea4a0c374723a")
	wantEnvMac = mustHex("32925224f762c4f921db929271bfdc5e911b0d877bc30cd4695f9d6530337c02")
)

// HKDF-SHA-512 rekey derivation vector from VECTORS.md §2.2.
//
// IKM is 32 bytes of 0xd1 followed by 32 bytes of 0xe2.
// rekey_nonce is 32 bytes of 0xcc; responder_nonce is 32 bytes of 0xdd.
// Per VECTORS.md §2.2 the same five SEMP-v1-session-* expand labels are
// reused; the cross-context separation comes from the salt change, not
// from a different label namespace.
var (
	rekeyIKM = mustHex(
		"d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1" +
			"d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1" +
			"e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2" +
			"e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2",
	)
	rekeyNonce       = mustHex("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")
	rekeyResponderNonce = mustHex("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd")

	wantRekeyPRK = mustHex(
		"3e62694adf1c3ae0bf998d6c74498ba7" +
			"148406359c374cbd6fa54f14ca2a2561" +
			"260c9bc3944c48204505f4ad8455958a" +
			"616b2c5b9ba0eebe99ee6ad15eac9c23",
	)
)

// TestSessionPRK validates the intermediate HKDF-Extract output against
// the expected PRK from VECTORS.md §2.1, exercising the KDF directly so
// that a derivation failure can be localized to Extract vs Expand.
func TestSessionPRK(t *testing.T) {
	kdf := crypto.NewKDFHKDFSHA512()
	salt := append(append([]byte{}, vectorClientNonce...), vectorServerNonce...)
	got := kdf.Extract(salt, vectorIKM)
	if !bytesEqual(got, wantPRK) {
		t.Errorf("PRK mismatch:\n  got  %x\n  want %x", got, wantPRK)
	}
}

// TestSessionKeyDerivation validates DeriveSessionKeys against the
// canonical VECTORS.md §2.1 vector.
func TestSessionKeyDerivation(t *testing.T) {
	keys, err := crypto.DeriveSessionKeys(nil, vectorIKM, vectorClientNonce, vectorServerNonce)
	if err != nil {
		t.Fatalf("DeriveSessionKeys: %v", err)
	}
	checkKey(t, "K_enc_c2s", keys.EncC2S, wantEncC2S)
	checkKey(t, "K_enc_s2c", keys.EncS2C, wantEncS2C)
	checkKey(t, "K_mac_c2s", keys.MACC2S, wantMacC2S)
	checkKey(t, "K_mac_s2c", keys.MACS2C, wantMacS2C)
	checkKey(t, "K_env_mac", keys.EnvMAC, wantEnvMac)
}

// TestRekeyPRK validates the PRK from VECTORS.md §2.2 (rekey derivation).
// The salt construction differs (rekey_nonce || responder_nonce) but the
// HKDF-Extract operation is otherwise identical.
func TestRekeyPRK(t *testing.T) {
	kdf := crypto.NewKDFHKDFSHA512()
	salt := append(append([]byte{}, rekeyNonce...), rekeyResponderNonce...)
	got := kdf.Extract(salt, rekeyIKM)
	if !bytesEqual(got, wantRekeyPRK) {
		t.Errorf("rekey PRK mismatch:\n  got  %x\n  want %x", got, wantRekeyPRK)
	}
}

func checkKey(t *testing.T, name string, got, want []byte) {
	t.Helper()
	if !bytesEqual(got, want) {
		t.Errorf("%s mismatch:\n  got  %x\n  want %x", name, got, want)
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("test vector hex decode failed: " + err.Error())
	}
	return b
}
