package seal

import (
	"bytes"
	"encoding/base64"
	"testing"

	"semp.dev/semp-go/crypto"
	"semp.dev/semp-go/keys"
)

// TestWrapUnwrapRoundTrip exercises the X25519-based ephemeral wrap.
func TestWrapUnwrapRoundTrip(t *testing.T) {
	suite := crypto.SuiteBaseline
	wrapper := NewWrapper(suite)

	// Recipient generates a long-term encryption key pair (we reuse the
	// X25519 KEM for both ephemeral and long-term keys here — same
	// curve, same key material shape).
	recipientPub, recipientPriv, err := suite.KEM().GenerateKeyPair()
	if err != nil {
		t.Fatalf("recipient keypair: %v", err)
	}

	// Sender generates a fresh symmetric key (32 bytes).
	symmetricKey, err := crypto.FreshKey(suite.AEAD())
	if err != nil {
		t.Fatalf("symmetric key: %v", err)
	}

	wrapped, err := wrapper.Wrap(recipientPub, symmetricKey)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	if wrapped == "" {
		t.Fatal("Wrap returned empty string")
	}

	out, err := wrapper.Unwrap(recipientPriv, wrapped)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if !bytes.Equal(out, symmetricKey) {
		t.Errorf("Unwrap returned wrong key:\n  got  %x\n  want %x", out, symmetricKey)
	}
}

// TestWrapUnwrapWrongRecipientFails confirms that a wrapped key cannot be
// opened by a different recipient's private key.
func TestWrapUnwrapWrongRecipientFails(t *testing.T) {
	suite := crypto.SuiteBaseline
	wrapper := NewWrapper(suite)

	alicePub, _, _ := suite.KEM().GenerateKeyPair()
	_, mallorPriv, _ := suite.KEM().GenerateKeyPair()

	symmetricKey, _ := crypto.FreshKey(suite.AEAD())
	wrapped, err := wrapper.Wrap(alicePub, symmetricKey)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	if _, err := wrapper.Unwrap(mallorPriv, wrapped); err == nil {
		t.Error("Unwrap accepted a key from the wrong recipient")
	}
}

// TestWrapTamperedFails confirms a tampered wrapped blob fails AEAD-Open.
func TestWrapTamperedFails(t *testing.T) {
	suite := crypto.SuiteBaseline
	wrapper := NewWrapper(suite)

	pub, priv, _ := suite.KEM().GenerateKeyPair()
	k, _ := crypto.FreshKey(suite.AEAD())
	wrapped, err := wrapper.Wrap(pub, k)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}

	// Tamper with the last byte (inside the AEAD ciphertext).
	raw, _ := base64.StdEncoding.DecodeString(wrapped)
	raw[len(raw)-1] ^= 0x01
	tampered := base64.StdEncoding.EncodeToString(raw)
	if _, err := wrapper.Unwrap(priv, tampered); err == nil {
		t.Error("Unwrap accepted a tampered wrap")
	}
}

// TestWrapForRecipientsMultiple builds a RecipientMap with multiple
// recipients and confirms each one can independently unwrap.
func TestWrapForRecipientsMultiple(t *testing.T) {
	suite := crypto.SuiteBaseline
	wrapper := NewWrapper(suite)

	type peer struct {
		fp   keys.Fingerprint
		pub  []byte
		priv []byte
	}
	peers := make([]peer, 3)
	recipients := make([]RecipientKey, 0, 3)
	for i := range peers {
		pub, priv, _ := suite.KEM().GenerateKeyPair()
		fp := keys.Compute(pub)
		peers[i] = peer{fp: fp, pub: pub, priv: priv}
		recipients = append(recipients, RecipientKey{Fingerprint: fp, PublicKey: pub})
	}

	symmetricKey, _ := crypto.FreshKey(suite.AEAD())
	rmap, err := WrapForRecipients(wrapper, symmetricKey, recipients)
	if err != nil {
		t.Fatalf("WrapForRecipients: %v", err)
	}
	if len(rmap) != len(peers) {
		t.Fatalf("RecipientMap size = %d, want %d", len(rmap), len(peers))
	}
	for _, p := range peers {
		wrapped, ok := rmap[p.fp]
		if !ok {
			t.Errorf("missing entry for %s", p.fp)
			continue
		}
		out, err := wrapper.Unwrap(p.priv, wrapped)
		if err != nil {
			t.Errorf("Unwrap for %s: %v", p.fp, err)
			continue
		}
		if !bytes.Equal(out, symmetricKey) {
			t.Errorf("Unwrap for %s returned wrong key", p.fp)
		}
	}
}

// TestSignVerifyRoundTrip exercises the dual-proof Signer / Verifier.
func TestSignVerifyRoundTrip(t *testing.T) {
	suite := crypto.SuiteBaseline
	pub, priv, err := suite.Signer().GenerateKeyPair()
	if err != nil {
		t.Fatalf("Signer keypair: %v", err)
	}
	envMAC, _ := crypto.FreshKey(suite.AEAD())

	signer := &Signer{
		Suite:            suite,
		DomainPrivateKey: priv,
		EnvMAC:           envMAC,
	}

	canonicalBytes := []byte(`{"type":"SEMP_ENVELOPE","version":"1.0.0"}`)
	s := &Seal{}
	if err := signer.Sign(s, canonicalBytes); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if s.Signature == "" || s.SessionMAC == "" {
		t.Fatal("Sign did not populate fields")
	}

	v := &Verifier{Suite: suite}
	if err := v.VerifySignature(s, canonicalBytes, pub); err != nil {
		t.Errorf("VerifySignature(valid): %v", err)
	}
	if err := v.VerifySessionMAC(s, canonicalBytes, envMAC); err != nil {
		t.Errorf("VerifySessionMAC(valid): %v", err)
	}

	// Tampered canonical bytes must fail both proofs.
	tampered := append([]byte{}, canonicalBytes...)
	tampered[0] ^= 0x01
	if err := v.VerifySignature(s, tampered, pub); err == nil {
		t.Error("VerifySignature accepted tampered canonical bytes")
	}
	if err := v.VerifySessionMAC(s, tampered, envMAC); err == nil {
		t.Error("VerifySessionMAC accepted tampered canonical bytes")
	}

	// Wrong env MAC must fail session MAC verify.
	wrongMAC, _ := crypto.FreshKey(suite.AEAD())
	if err := v.VerifySessionMAC(s, canonicalBytes, wrongMAC); err == nil {
		t.Error("VerifySessionMAC accepted wrong K_env_mac")
	}
}
