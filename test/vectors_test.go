package test

import (
	"encoding/hex"
	"testing"

	"github.com/semp-dev/semp-go/crypto"
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

// TestSessionKeyDerivation validates DeriveSessionKeys against the
// canonical VECTORS.md §2.1 vector. Skipped until crypto.DeriveSessionKeys
// is implemented.
func TestSessionKeyDerivation(t *testing.T) {
	t.Skip("crypto.DeriveSessionKeys is not yet implemented (see crypto/kdf.go)")

	// Wiring is left in place so that flipping the t.Skip line is the
	// only change required when the implementation lands.
	keys, err := crypto.DeriveSessionKeys(nil, vectorIKM, vectorClientNonce, vectorServerNonce)
	if err != nil {
		t.Fatalf("DeriveSessionKeys: %v", err)
	}
	checkKey(t, "K_enc_c2s", keys.EncC2S, wantEncC2S)
	checkKey(t, "K_enc_s2c", keys.EncS2C, wantEncS2C)
	checkKey(t, "K_mac_c2s", keys.MACC2S, wantMacC2S)
	checkKey(t, "K_mac_s2c", keys.MACS2C, wantMacS2C)
	checkKey(t, "K_env_mac", keys.EnvMAC, wantEnvMac)

	_ = wantPRK // referenced by future PRK assertion
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
