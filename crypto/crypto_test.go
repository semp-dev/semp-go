package crypto

import (
	"bytes"
	"testing"
)

// TestSuiteBaselineWired sanity-checks that SuiteBaseline returns
// non-nil components for every primitive. A nil component would crash the
// handshake state machine the first time it tried to use the suite.
func TestSuiteBaselineWired(t *testing.T) {
	s := SuiteBaseline
	if s == nil {
		t.Fatal("SuiteBaseline is nil")
	}
	if s.ID() != SuiteIDX25519ChaCha20Poly1305 {
		t.Errorf("ID = %q, want %q", s.ID(), SuiteIDX25519ChaCha20Poly1305)
	}
	if s.KEM() == nil {
		t.Error("KEM() is nil")
	}
	if s.AEAD() == nil {
		t.Error("AEAD() is nil")
	}
	if s.MAC([]byte("test-key-32-bytes-aaaaaaaaaaaaaa")) == nil {
		t.Error("MAC() is nil")
	}
	if s.KDF() == nil {
		t.Error("KDF() is nil")
	}
	if s.Signer() == nil {
		t.Error("Signer() is nil")
	}
}

// TestEd25519RoundTrip exercises the Signer interface end-to-end.
func TestEd25519RoundTrip(t *testing.T) {
	signer := NewSignerEd25519()
	pub, priv, err := signer.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	if len(pub) != signer.PublicKeySize() {
		t.Errorf("public key length = %d, want %d", len(pub), signer.PublicKeySize())
	}

	msg := []byte("the quick brown fox jumps over the lazy dog")
	sig, err := signer.Sign(priv, msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) != signer.SignatureSize() {
		t.Errorf("signature length = %d, want %d", len(sig), signer.SignatureSize())
	}

	if err := signer.Verify(pub, msg, sig); err != nil {
		t.Errorf("Verify(valid): %v", err)
	}

	// Tampered message must fail.
	tampered := append([]byte{}, msg...)
	tampered[0] ^= 0x01
	if err := signer.Verify(pub, tampered, sig); err == nil {
		t.Error("Verify(tampered) accepted a forged message")
	}
}

// TestChaCha20Poly1305RoundTrip exercises the AEAD interface end-to-end.
func TestChaCha20Poly1305RoundTrip(t *testing.T) {
	aead := NewAEADChaCha20Poly1305()

	key, err := FreshKey(aead)
	if err != nil {
		t.Fatalf("FreshKey: %v", err)
	}
	nonce, err := FreshNonce(aead)
	if err != nil {
		t.Fatalf("FreshNonce: %v", err)
	}

	plaintext := []byte("encrypted-brief-payload")
	ad := []byte("additional-authenticated-data")

	ct, err := aead.Seal(key, nonce, plaintext, ad)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if len(ct) != len(plaintext)+aead.Overhead() {
		t.Errorf("ciphertext length = %d, want %d", len(ct), len(plaintext)+aead.Overhead())
	}

	out, err := aead.Open(key, nonce, ct, ad)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(out, plaintext) {
		t.Errorf("Open mismatch:\n  got  %q\n  want %q", out, plaintext)
	}

	// Wrong AD must fail.
	if _, err := aead.Open(key, nonce, ct, []byte("wrong-ad")); err == nil {
		t.Error("Open accepted a tampered AD")
	}
}

// TestX25519Agreement exercises the KEM interface and confirms that two
// peers compute the same shared secret via Agree, and via Encapsulate /
// Decapsulate.
func TestX25519Agreement(t *testing.T) {
	kem := NewKEMX25519()

	alicePub, alicePriv, err := kem.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Alice GenerateKeyPair: %v", err)
	}
	bobPub, bobPriv, err := kem.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Bob GenerateKeyPair: %v", err)
	}

	aliceSecret, err := kem.Agree(alicePriv, bobPub)
	if err != nil {
		t.Fatalf("Alice Agree: %v", err)
	}
	bobSecret, err := kem.Agree(bobPriv, alicePub)
	if err != nil {
		t.Fatalf("Bob Agree: %v", err)
	}
	if !bytes.Equal(aliceSecret, bobSecret) {
		t.Errorf("DH agreement mismatch:\n  alice %x\n  bob   %x", aliceSecret, bobSecret)
	}

	// Encapsulate / Decapsulate round-trip.
	encSecret, ciphertext, err := kem.Encapsulate(bobPub)
	if err != nil {
		t.Fatalf("Encapsulate: %v", err)
	}
	decSecret, err := kem.Decapsulate(ciphertext, bobPriv)
	if err != nil {
		t.Fatalf("Decapsulate: %v", err)
	}
	if !bytes.Equal(encSecret, decSecret) {
		t.Errorf("Encapsulate/Decapsulate mismatch:\n  enc %x\n  dec %x", encSecret, decSecret)
	}
}

// TestHMACSHA256Verify exercises the MAC interface and the constant-time
// Verify helper.
func TestHMACSHA256Verify(t *testing.T) {
	key := []byte("test-key-of-arbitrary-length")
	msg := []byte("authenticated message body")

	tag := ComputeMAC(key, msg)
	if len(tag) != 32 {
		t.Errorf("HMAC-SHA-256 tag length = %d, want 32", len(tag))
	}

	again := ComputeMAC(key, msg)
	if !Verify(tag, again) {
		t.Error("Verify rejected matching tags")
	}

	// Tampered tag must fail.
	tampered := append([]byte{}, tag...)
	tampered[0] ^= 0x01
	if Verify(tag, tampered) {
		t.Error("Verify accepted a tampered tag")
	}
}

// TestZeroize confirms Zeroize actually zeros the slice.
func TestZeroize(t *testing.T) {
	b := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	Zeroize(b)
	for i, v := range b {
		if v != 0 {
			t.Errorf("Zeroize: b[%d] = %d, want 0", i, v)
		}
	}
	// Empty / nil slices must be safe.
	Zeroize(nil)
	Zeroize([]byte{})
}

// TestNegotiateBaseline exercises the suite negotiation logic. With only
// the baseline suite implemented, Negotiate must select baseline when both
// peers offer it, and return an error when only the unimplemented PQ suite
// is offered by both peers.
func TestNegotiateBaseline(t *testing.T) {
	// Baseline mutually offered → baseline selected.
	id, err := Negotiate(
		[]SuiteID{SuiteIDX25519ChaCha20Poly1305},
		[]SuiteID{SuiteIDX25519ChaCha20Poly1305},
	)
	if err != nil {
		t.Fatalf("baseline negotiation: %v", err)
	}
	if id != SuiteIDX25519ChaCha20Poly1305 {
		t.Errorf("got %q, want %q", id, SuiteIDX25519ChaCha20Poly1305)
	}

	// Both PQ and baseline offered → PQ selected (preferred per
	// SESSION.md §4.3: servers MUST prefer the post-quantum hybrid
	// when both peers support one).
	id, err = Negotiate(
		[]SuiteID{SuiteIDPQKyber768X25519, SuiteIDX25519ChaCha20Poly1305},
		[]SuiteID{SuiteIDPQKyber768X25519, SuiteIDX25519ChaCha20Poly1305},
	)
	if err != nil {
		t.Fatalf("hybrid negotiation: %v", err)
	}
	if id != SuiteIDPQKyber768X25519 {
		t.Errorf("got %q, want %q (PQ preferred)", id, SuiteIDPQKyber768X25519)
	}

	// PQ only on both sides → PQ selected.
	id, err = Negotiate(
		[]SuiteID{SuiteIDPQKyber768X25519},
		[]SuiteID{SuiteIDPQKyber768X25519},
	)
	if err != nil {
		t.Fatalf("PQ-only negotiation: %v", err)
	}
	if id != SuiteIDPQKyber768X25519 {
		t.Errorf("got %q, want %q", id, SuiteIDPQKyber768X25519)
	}

	// Disjoint sets → error.
	_, err = Negotiate(
		[]SuiteID{SuiteIDX25519ChaCha20Poly1305},
		[]SuiteID{SuiteIDPQKyber768X25519},
	)
	if err == nil {
		t.Error("expected error for disjoint suites")
	}
}

// TestSuiteEndToEnd combines KEM, KDF, AEAD, MAC, and Signer in a tiny
// scenario that mirrors what the handshake state machine will do: derive
// a shared secret via X25519, expand it into session keys via HKDF, then
// use the keys to seal a payload and produce a session MAC tag, then
// verify both on the receiving side.
func TestSuiteEndToEnd(t *testing.T) {
	suite := SuiteBaseline

	// 1. Two ephemeral key pairs.
	alicePub, alicePriv, _ := suite.KEM().GenerateKeyPair()
	bobPub, bobPriv, _ := suite.KEM().GenerateKeyPair()

	// 2. Both sides agree on the same shared secret.
	aliceSec, _ := suite.KEM().Agree(alicePriv, bobPub)
	bobSec, _ := suite.KEM().Agree(bobPriv, alicePub)
	if !bytes.Equal(aliceSec, bobSec) {
		t.Fatal("ephemeral agreement disagrees")
	}

	// 3. Both sides derive identical session keys.
	clientNonce := make([]byte, 32)
	serverNonce := make([]byte, 32)
	for i := range clientNonce {
		clientNonce[i] = 0x11
		serverNonce[i] = 0x22
	}
	aliceKeys, err := DeriveSessionKeys(suite.KDF(), aliceSec, clientNonce, serverNonce)
	if err != nil {
		t.Fatalf("alice DeriveSessionKeys: %v", err)
	}
	bobKeys, err := DeriveSessionKeys(suite.KDF(), bobSec, clientNonce, serverNonce)
	if err != nil {
		t.Fatalf("bob DeriveSessionKeys: %v", err)
	}
	if !bytes.Equal(aliceKeys.EncC2S, bobKeys.EncC2S) {
		t.Error("alice/bob disagree on K_enc_c2s")
	}
	if !bytes.Equal(aliceKeys.EnvMAC, bobKeys.EnvMAC) {
		t.Error("alice/bob disagree on K_env_mac")
	}

	// 4. Alice seals a payload to Bob using K_enc_c2s.
	plaintext := []byte("the inner identity proof block goes here")
	nonce, _ := FreshNonce(suite.AEAD())
	ct, err := suite.AEAD().Seal(aliceKeys.EncC2S, nonce, plaintext, nil)
	if err != nil {
		t.Fatalf("Alice Seal: %v", err)
	}
	out, err := suite.AEAD().Open(bobKeys.EncC2S, nonce, ct, nil)
	if err != nil {
		t.Fatalf("Bob Open: %v", err)
	}
	if !bytes.Equal(out, plaintext) {
		t.Errorf("Open mismatch")
	}

	// 5. Alice computes seal.session_mac; Bob verifies it.
	canonicalEnvelope := []byte("CANONICAL_ENVELOPE_BYTES_PLACEHOLDER")
	tag := ComputeMAC(aliceKeys.EnvMAC, canonicalEnvelope)
	if !Verify(tag, ComputeMAC(bobKeys.EnvMAC, canonicalEnvelope)) {
		t.Error("session MAC verification failed")
	}

	// 6. Erase keys; subsequent zeroize must be visible.
	aliceKeys.Erase()
	bobKeys.Erase()
	for _, b := range [][]byte{aliceKeys.EncC2S, aliceKeys.EnvMAC} {
		for _, x := range b {
			if x != 0 {
				t.Error("Erase did not zero key bytes")
			}
		}
	}
}
