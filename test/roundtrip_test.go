package test

import (
	"testing"
	"time"

	"semp.dev/semp-go/brief"
	"semp.dev/semp-go/crypto"
	"semp.dev/semp-go/enclosure"
	"semp.dev/semp-go/envelope"
	"semp.dev/semp-go/keys"
	"semp.dev/semp-go/seal"
)

// TestEnvelopeRoundTrip exercises the full happy path of an envelope:
//
//   compose → sign → encode → decode → verify-signature → verify-session-MAC
//   → server-unwraps-brief → client-unwraps-brief → client-unwraps-enclosure
//
// All in one process. No transports, no real handshake, no real key
// distribution — those layers are still stubs. The point is to prove that
// the data model and the seal layer mesh correctly with the crypto layer:
// every byte that the sender produces is consumable by the receiver,
// and every tampered byte is rejected.
//
// This is the milestone-2 acceptance test.
func TestEnvelopeRoundTrip(t *testing.T) {
	suite := crypto.SuiteBaseline

	// --- Sender side: domain key (long-term, used to sign envelopes).
	senderDomainPub, senderDomainPriv, err := suite.Signer().GenerateKeyPair()
	if err != nil {
		t.Fatalf("sender domain keypair: %v", err)
	}
	senderDomainKeyID := keys.Compute(senderDomainPub)

	// --- Sender's home server: K_env_mac for the active session.
	// In a real flow this comes from a completed handshake; here we
	// fabricate a fresh 32-byte key.
	envMAC, _ := crypto.FreshKey(suite.AEAD())

	// --- Receiver server: domain encryption key pair (used to unwrap
	// the brief). NOTE: in the real protocol, the domain key used to
	// SIGN envelopes is Ed25519, while the domain key used to RECEIVE
	// wrapped K_brief values is an X25519 encryption key. The same
	// domain has both. We model that here with a separate X25519
	// keypair.
	receiverServerEncPub, receiverServerEncPriv, err := suite.KEM().GenerateKeyPair()
	if err != nil {
		t.Fatalf("receiver server enc keypair: %v", err)
	}
	receiverServerKeyID := keys.Compute(receiverServerEncPub)

	// --- Receiver client: encryption key pair (used to unwrap brief +
	// enclosure).
	receiverClientEncPub, receiverClientEncPriv, err := suite.KEM().GenerateKeyPair()
	if err != nil {
		t.Fatalf("receiver client enc keypair: %v", err)
	}
	receiverClientKeyID := keys.Compute(receiverClientEncPub)

	// --- 1. Sender client composes brief + enclosure.
	bf := brief.Brief{
		MessageID: "01JTESTROUNDTRIP000000000001",
		From:      "alice@sender.example",
		To:        []brief.Address{"bob@recipient.example"},
		SentAt:    time.Date(2026, 4, 9, 12, 0, 0, 0, time.UTC),
	}
	enc := enclosure.Enclosure{
		Subject:     "round-trip test",
		ContentType: "text/plain",
		Body: enclosure.Body{
			"text/plain": "the only acceptable proof that the data model is wired up.",
		},
	}

	in := &envelope.ComposeInput{
		Suite: suite,
		Postmark: envelope.Postmark{
			ID:         "01JTESTPOSTMARK00000000000001",
			SessionID:  "01JTESTSESSION0000000000000001",
			FromDomain: "sender.example",
			ToDomain:   "recipient.example",
			Expires:    time.Date(2026, 4, 9, 13, 0, 0, 0, time.UTC),
		},
		Brief:             bf,
		Enclosure:         enc,
		SenderDomainKeyID: senderDomainKeyID,
		BriefRecipients: []seal.RecipientKey{
			{Fingerprint: receiverServerKeyID, PublicKey: receiverServerEncPub},
			{Fingerprint: receiverClientKeyID, PublicKey: receiverClientEncPub},
		},
		EnclosureRecipients: []seal.RecipientKey{
			{Fingerprint: receiverClientKeyID, PublicKey: receiverClientEncPub},
		},
	}

	env, err := envelope.Compose(in)
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	if env.Seal.Signature != "" || env.Seal.SessionMAC != "" {
		t.Fatal("Compose should leave signature/session_mac empty until Sign is called")
	}

	// --- 2. Sender's home server signs.
	if err := envelope.Sign(env, suite, senderDomainPriv, envMAC); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if env.Seal.Signature == "" || env.Seal.SessionMAC == "" {
		t.Fatal("Sign did not populate signature/session_mac")
	}

	// --- 3. Wire transmission: encode and decode.
	wire, err := envelope.Encode(env)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	t.Logf("envelope on the wire: %d bytes", len(wire))

	got, err := envelope.Decode(wire)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}

	// --- 4. Receiving server verifies the domain signature.
	if err := envelope.VerifySignature(got, suite, senderDomainPub); err != nil {
		t.Fatalf("VerifySignature(valid): %v", err)
	}

	// --- 5. Receiving server verifies the session MAC.
	if err := envelope.VerifySessionMAC(got, suite, envMAC); err != nil {
		t.Fatalf("VerifySessionMAC(valid): %v", err)
	}

	// --- 6. Receiving server unwraps and reads the brief.
	briefForServer, err := envelope.OpenBrief(got, suite, receiverServerKeyID, receiverServerEncPriv, receiverServerEncPub)
	if err != nil {
		t.Fatalf("server OpenBrief: %v", err)
	}
	if briefForServer.MessageID != bf.MessageID {
		t.Errorf("server-side brief MessageID mismatch: got %q, want %q", briefForServer.MessageID, bf.MessageID)
	}
	if string(briefForServer.From) != string(bf.From) {
		t.Errorf("server-side brief From mismatch")
	}

	// --- 7. Receiving client unwraps and reads the brief.
	briefForClient, err := envelope.OpenBrief(got, suite, receiverClientKeyID, receiverClientEncPriv, receiverClientEncPub)
	if err != nil {
		t.Fatalf("client OpenBrief: %v", err)
	}
	if briefForClient.MessageID != bf.MessageID {
		t.Errorf("client-side brief MessageID mismatch")
	}

	// --- 8. Receiving client unwraps and reads the enclosure.
	encForClient, err := envelope.OpenEnclosure(got, suite, receiverClientKeyID, receiverClientEncPriv, receiverClientEncPub)
	if err != nil {
		t.Fatalf("client OpenEnclosure: %v", err)
	}
	if encForClient.Subject != enc.Subject {
		t.Errorf("enclosure Subject mismatch: got %q, want %q", encForClient.Subject, enc.Subject)
	}
	if encForClient.Body["text/plain"] != enc.Body["text/plain"] {
		t.Errorf("enclosure body mismatch")
	}

	// --- 9. Receiving server CANNOT decrypt the enclosure (no wrap).
	if _, err := envelope.OpenEnclosure(got, suite, receiverServerKeyID, receiverServerEncPriv, receiverServerEncPub); err == nil {
		t.Error("server was able to decrypt the enclosure — this MUST NOT happen")
	}

	// --- 10. Tampering with the wire bytes must fail signature verification.
	tampered := append([]byte{}, wire...)
	// Flip a byte inside the postmark (somewhere likely to be inside
	// the canonical region).
	tampered[len(tampered)/3] ^= 0x01
	if tEnv, terr := envelope.Decode(tampered); terr == nil {
		if err := envelope.VerifySignature(tEnv, suite, senderDomainPub); err == nil {
			t.Error("VerifySignature accepted a tampered envelope")
		}
	}
}

// TestEnvelopeRejectsWrongDomainKey confirms that a different domain's
// public key cannot validate a signature.
func TestEnvelopeRejectsWrongDomainKey(t *testing.T) {
	suite := crypto.SuiteBaseline

	_, senderPriv, _ := suite.Signer().GenerateKeyPair()
	wrongPub, _, _ := suite.Signer().GenerateKeyPair()
	envMAC, _ := crypto.FreshKey(suite.AEAD())

	recipPub, _, _ := suite.KEM().GenerateKeyPair()
	recipFP := keys.Compute(recipPub)

	in := &envelope.ComposeInput{
		Suite: suite,
		Postmark: envelope.Postmark{
			ID:         "x",
			SessionID:  "x",
			FromDomain: "a.example",
			ToDomain:   "b.example",
			Expires:    time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
		},
		Brief:             brief.Brief{MessageID: "m"},
		Enclosure:         enclosure.Enclosure{ContentType: "text/plain", Body: enclosure.Body{"text/plain": "x"}},
		SenderDomainKeyID: keys.Compute(wrongPub),
		BriefRecipients:   []seal.RecipientKey{{Fingerprint: recipFP, PublicKey: recipPub}},
		EnclosureRecipients: []seal.RecipientKey{{Fingerprint: recipFP, PublicKey: recipPub}},
	}
	env, err := envelope.Compose(in)
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	if err := envelope.Sign(env, suite, senderPriv, envMAC); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := envelope.VerifySignature(env, suite, wrongPub); err == nil {
		t.Error("VerifySignature accepted the wrong public key")
	}
}
