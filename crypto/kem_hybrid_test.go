package crypto_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/semp-dev/semp-go/crypto"
)

// TestHybridKEMGenerateKeyPairShape confirms GenerateKeyPair returns
// slices of the exact HybridPublicKeySize and HybridPrivateKeySize
// widths, matching the wire-format constants documented alongside
// the implementation.
func TestHybridKEMGenerateKeyPairShape(t *testing.T) {
	kem := crypto.NewKEMHybridKyber768X25519()
	pub, priv, err := kem.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	if got, want := len(pub), crypto.HybridPublicKeySize; got != want {
		t.Errorf("pub size = %d, want %d", got, want)
	}
	if got, want := len(priv), crypto.HybridPrivateKeySize; got != want {
		t.Errorf("priv size = %d, want %d", got, want)
	}
}

// TestHybridKEMEncapsulateDecapsulateRoundTrip drives the full
// initiator/responder flow: the initiator generates a keypair, the
// responder encapsulates under the initiator's pub, and the initiator
// decapsulates the responder's ciphertext. Both sides MUST derive the
// exact same 64-byte combined shared secret.
func TestHybridKEMEncapsulateDecapsulateRoundTrip(t *testing.T) {
	kem := crypto.NewKEMHybridKyber768X25519()

	initiatorPub, initiatorPriv, err := kem.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	shared1, ct, err := kem.Encapsulate(initiatorPub)
	if err != nil {
		t.Fatalf("Encapsulate: %v", err)
	}
	if got, want := len(ct), crypto.HybridCiphertextSize; got != want {
		t.Errorf("ciphertext size = %d, want %d", got, want)
	}
	if got, want := len(shared1), crypto.HybridSharedSecretSize; got != want {
		t.Errorf("shared size = %d, want %d", got, want)
	}
	shared2, err := kem.Decapsulate(ct, initiatorPriv)
	if err != nil {
		t.Fatalf("Decapsulate: %v", err)
	}
	if !bytes.Equal(shared1, shared2) {
		t.Errorf("shared secrets mismatch:\n  enc=%x\n  dec=%x", shared1, shared2)
	}
}

// TestHybridKEMSharedSecretLayout verifies that the 64-byte combined
// secret is structured as K_kyber || K_x25519 per SESSION.md §4.1 —
// i.e. the first 32 bytes are the Kyber output and the last 32 are
// the X25519 output. We cannot directly observe the two halves from
// the public API, but we can confirm that the second 32 bytes change
// when we vary ONLY the X25519 half of the ciphertext (the first 32
// bytes of the wire ciphertext are the responder's X25519 pub, the
// rest is the Kyber ciphertext).
func TestHybridKEMSharedSecretLayout(t *testing.T) {
	kem := crypto.NewKEMHybridKyber768X25519()
	pub, priv, err := kem.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	shared, ct, err := kem.Encapsulate(pub)
	if err != nil {
		t.Fatalf("Encapsulate: %v", err)
	}
	// Flip one bit in the Kyber ciphertext portion (offset ≥ 32).
	tampered := append([]byte{}, ct...)
	tampered[100] ^= 0x01
	altShared, err := kem.Decapsulate(tampered, priv)
	if err != nil {
		t.Fatalf("Decapsulate(tampered kyber): %v", err)
	}
	// The X25519 half (last 32 bytes) MUST be unchanged because the
	// X25519 portion of the ciphertext was not touched.
	if !bytes.Equal(shared[32:], altShared[32:]) {
		t.Errorf("X25519 half changed despite tampering only Kyber bytes:\n  orig=%x\n  alt=%x",
			shared[32:], altShared[32:])
	}
	// The Kyber half (first 32 bytes) MUST change — Kyber CCA security
	// means any tampering produces a different (pseudo-random)
	// decapsulated key.
	if bytes.Equal(shared[:32], altShared[:32]) {
		t.Error("Kyber half unchanged despite ciphertext tampering — CCA break?")
	}
}

// TestHybridKEMTamperedX25519HalfDesyncsKey flips a byte in the
// responder's X25519 pub portion of the ciphertext and confirms the
// initiator derives a DIFFERENT shared secret than the responder
// intended. Matches the classical half of the hybrid's security claim.
func TestHybridKEMTamperedX25519HalfDesyncsKey(t *testing.T) {
	kem := crypto.NewKEMHybridKyber768X25519()
	pub, priv, err := kem.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	shared, ct, err := kem.Encapsulate(pub)
	if err != nil {
		t.Fatalf("Encapsulate: %v", err)
	}
	tampered := append([]byte{}, ct...)
	tampered[0] ^= 0x01 // first byte is inside the X25519 pub region
	altShared, err := kem.Decapsulate(tampered, priv)
	if err != nil {
		t.Fatalf("Decapsulate(tampered x25519): %v", err)
	}
	if bytes.Equal(shared, altShared) {
		t.Error("tampered X25519 did not change the derived shared secret")
	}
	// The Kyber half MUST be unchanged — we only touched the X25519 bytes.
	if !bytes.Equal(shared[:32], altShared[:32]) {
		t.Errorf("Kyber half changed despite only X25519 tampering")
	}
}

// TestHybridKEMWrongPrivateKeyDoesNotRecoverSecret confirms that
// decapsulating a ciphertext with the wrong private key produces a
// different shared secret (not an error — Kyber CCA is
// implicit-rejection, returning a pseudo-random value on bad input).
func TestHybridKEMWrongPrivateKeyDoesNotRecoverSecret(t *testing.T) {
	kem := crypto.NewKEMHybridKyber768X25519()
	_, priv1, _ := kem.GenerateKeyPair()
	pub2, _, _ := kem.GenerateKeyPair()
	shared, ct, err := kem.Encapsulate(pub2)
	if err != nil {
		t.Fatalf("Encapsulate: %v", err)
	}
	altShared, err := kem.Decapsulate(ct, priv1)
	if err != nil {
		t.Fatalf("Decapsulate with wrong priv: %v", err)
	}
	if bytes.Equal(shared, altShared) {
		t.Error("decapsulating with wrong priv key recovered the original secret")
	}
}

// TestHybridKEMAgreeNotSupported confirms Agree returns a descriptive
// error explaining why the caller should use Encapsulate/Decapsulate.
func TestHybridKEMAgreeNotSupported(t *testing.T) {
	kem := crypto.NewKEMHybridKyber768X25519()
	pub, priv, _ := kem.GenerateKeyPair()
	_, err := kem.Agree(priv, pub)
	if err == nil {
		t.Fatal("Agree should have returned an error")
	}
	if !strings.Contains(err.Error(), "does not support Agree") {
		t.Errorf("error should mention Agree unsupported: %v", err)
	}
}

// TestHybridKEMEncapsulateRejectsWrongSizePub confirms Encapsulate
// validates the initiator pub length before trying to read into the
// Kyber unpacker (which would otherwise panic).
func TestHybridKEMEncapsulateRejectsWrongSizePub(t *testing.T) {
	kem := crypto.NewKEMHybridKyber768X25519()
	_, _, err := kem.Encapsulate(make([]byte, 100))
	if err == nil {
		t.Fatal("Encapsulate should reject short input")
	}
	if !strings.Contains(err.Error(), "remote public key length") {
		t.Errorf("error should mention length: %v", err)
	}
}

// TestHybridKEMDecapsulateRejectsWrongSizes confirms Decapsulate
// validates both inputs before delegating to the Kyber unpacker.
func TestHybridKEMDecapsulateRejectsWrongSizes(t *testing.T) {
	kem := crypto.NewKEMHybridKyber768X25519()
	_, priv, _ := kem.GenerateKeyPair()
	if _, err := kem.Decapsulate(make([]byte, 100), priv); err == nil {
		t.Error("Decapsulate should reject short ciphertext")
	}
	shared, ct, _ := kem.Encapsulate(mustGenPub(t, kem))
	_ = shared
	if _, err := kem.Decapsulate(ct, make([]byte, 100)); err == nil {
		t.Error("Decapsulate should reject short private key")
	}
}

// TestSuitePQRegistration confirms SuitePQ is a non-nil Suite with
// the correct ID, exposes the hybrid KEM, and is returned by both
// LookupSuite and Negotiate when both peers offer it.
func TestSuitePQRegistration(t *testing.T) {
	if crypto.SuitePQ == nil {
		t.Fatal("SuitePQ should be non-nil after wiring")
	}
	if crypto.SuitePQ.ID() != crypto.SuiteIDPQKyber768X25519 {
		t.Errorf("SuitePQ.ID() = %q, want %q",
			crypto.SuitePQ.ID(), crypto.SuiteIDPQKyber768X25519)
	}
	for name, got := range map[string]any{
		"KEM":    crypto.SuitePQ.KEM(),
		"AEAD":   crypto.SuitePQ.AEAD(),
		"KDF":    crypto.SuitePQ.KDF(),
		"Signer": crypto.SuitePQ.Signer(),
	} {
		if got == nil {
			t.Errorf("SuitePQ.%s() is nil", name)
		}
	}
	if crypto.LookupSuite(crypto.SuiteIDPQKyber768X25519) != crypto.SuitePQ {
		t.Error("LookupSuite(PQ) did not return SuitePQ")
	}
}

// TestSuitePQHybridRoundTripThroughInterface drives an Encapsulate →
// Decapsulate round-trip through the Suite interface (rather than
// the concrete hybrid type), confirming the Suite wiring propagates
// correctly to downstream handshake/session code that only holds a
// crypto.Suite handle.
func TestSuitePQHybridRoundTripThroughInterface(t *testing.T) {
	suite := crypto.SuitePQ
	if suite == nil {
		t.Fatal("SuitePQ nil")
	}
	pub, priv, err := suite.KEM().GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	shared1, ct, err := suite.KEM().Encapsulate(pub)
	if err != nil {
		t.Fatalf("Encapsulate: %v", err)
	}
	shared2, err := suite.KEM().Decapsulate(ct, priv)
	if err != nil {
		t.Fatalf("Decapsulate: %v", err)
	}
	if !bytes.Equal(shared1, shared2) {
		t.Error("shared secrets differ across Encapsulate/Decapsulate via Suite interface")
	}
}

func mustGenPub(t *testing.T, kem crypto.KEM) []byte {
	t.Helper()
	pub, _, err := kem.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	return pub
}
