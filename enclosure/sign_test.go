package enclosure_test

import (
	"testing"
	"time"

	"semp.dev/semp-go/crypto"
	"semp.dev/semp-go/enclosure"
)

func newTestSuiteAndKeys(t *testing.T) (crypto.Suite, []byte, []byte) {
	t.Helper()
	suite := crypto.SuiteBaseline
	pub, priv, err := suite.Signer().GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}
	return suite, pub, priv
}

func TestSignEnclosureRoundTrip(t *testing.T) {
	suite, pub, priv := newTestSuiteAndKeys(t)
	enc := &enclosure.Enclosure{
		Subject:     "test",
		ContentType: "text/plain",
		Body:        enclosure.Body{"text/plain": "hello"},
	}
	if err := enclosure.SignEnclosure(enc, suite, priv, "identity-fp"); err != nil {
		t.Fatalf("SignEnclosure: %v", err)
	}
	if enc.SenderSignature == nil || enc.SenderSignature.Value == "" {
		t.Fatal("SenderSignature not populated")
	}
	if enc.SenderSignature.Algorithm != enclosure.SignatureAlgorithmEd25519 {
		t.Errorf("algorithm = %q, want %q", enc.SenderSignature.Algorithm, enclosure.SignatureAlgorithmEd25519)
	}
	if enc.SenderSignature.KeyID != "identity-fp" {
		t.Errorf("key_id = %q, want identity-fp", enc.SenderSignature.KeyID)
	}

	if err := enclosure.VerifyEnclosureSignature(enc, suite, pub); err != nil {
		t.Errorf("VerifyEnclosureSignature: %v", err)
	}
}

func TestVerifyEnclosureSignatureDetectsTamper(t *testing.T) {
	suite, pub, priv := newTestSuiteAndKeys(t)
	enc := &enclosure.Enclosure{
		Subject:     "test",
		ContentType: "text/plain",
		Body:        enclosure.Body{"text/plain": "hello"},
	}
	if err := enclosure.SignEnclosure(enc, suite, priv, "identity-fp"); err != nil {
		t.Fatalf("SignEnclosure: %v", err)
	}
	// Tamper with the body after signing.
	enc.Body["text/plain"] = "goodbye"
	if err := enclosure.VerifyEnclosureSignature(enc, suite, pub); err == nil {
		t.Error("Verify returned nil on tampered body; want error")
	}
}

func TestVerifyEnclosureSignatureMissingSignature(t *testing.T) {
	suite, pub, _ := newTestSuiteAndKeys(t)
	enc := &enclosure.Enclosure{
		ContentType: "text/plain",
		Body:        enclosure.Body{"text/plain": "hello"},
	}
	if err := enclosure.VerifyEnclosureSignature(enc, suite, pub); err == nil {
		t.Error("Verify returned nil on missing signature; want error")
	}
}

func TestSignForwarderAttestationRoundTrip(t *testing.T) {
	suite, pub, priv := newTestSuiteAndKeys(t)
	ff := &enclosure.ForwardedFrom{
		OriginalEnclosurePlaintext: &enclosure.Enclosure{
			ContentType: "text/plain",
			Body:        enclosure.Body{"text/plain": "original"},
		},
		OriginalSenderAddress: "alice@original.example",
		ReceivedAt:            time.Date(2026, 4, 15, 14, 30, 0, 0, time.UTC),
	}
	if err := enclosure.SignForwarderAttestation(ff, suite, priv, "forwarder-fp"); err != nil {
		t.Fatalf("SignForwarderAttestation: %v", err)
	}
	if ff.ForwarderAttestation == nil || ff.ForwarderAttestation.Value == "" {
		t.Fatal("ForwarderAttestation not populated")
	}
	if err := enclosure.VerifyForwarderAttestation(ff, suite, pub); err != nil {
		t.Errorf("VerifyForwarderAttestation: %v", err)
	}
}

func TestVerifyForwarderAttestationDetectsTamper(t *testing.T) {
	suite, pub, priv := newTestSuiteAndKeys(t)
	ff := &enclosure.ForwardedFrom{
		OriginalEnclosurePlaintext: &enclosure.Enclosure{
			ContentType: "text/plain",
			Body:        enclosure.Body{"text/plain": "original"},
		},
		OriginalSenderAddress: "alice@original.example",
		ReceivedAt:            time.Date(2026, 4, 15, 14, 30, 0, 0, time.UTC),
	}
	if err := enclosure.SignForwarderAttestation(ff, suite, priv, "forwarder-fp"); err != nil {
		t.Fatalf("SignForwarderAttestation: %v", err)
	}
	ff.OriginalSenderAddress = "mallory@attacker.example"
	if err := enclosure.VerifyForwarderAttestation(ff, suite, pub); err == nil {
		t.Error("Verify returned nil on tampered forwarded_from; want error")
	}
}
