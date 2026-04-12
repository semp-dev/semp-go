package test

import (
	"testing"
	"time"

	"semp.dev/semp-go/brief"
	"semp.dev/semp-go/crypto"
	"semp.dev/semp-go/enclosure"
	"semp.dev/semp-go/envelope"
	"semp.dev/semp-go/handshake"
	"semp.dev/semp-go/keys"
	"semp.dev/semp-go/seal"
)

// TestCrossDomainEnvelopeFlow combines the federation handshake with the
// envelope round trip. It models the full SEMP cross-domain delivery path
// at the protocol layer:
//
//   1. Server A and Server B establish a federation session via the
//      handshake (Initiator + Responder).
//   2. Alice (a client on Server A) composes an envelope addressed to
//      Bob on Server B.
//   3. Server A signs the envelope with its sender domain key AND with
//      K_env_mac from the federation session.
//   4. Wire bytes flow A → B.
//   5. Server B verifies the seal signature and the session MAC against
//      the same K_env_mac it derived during the federation handshake.
//   6. Server B unwraps the brief.
//   7. Bob's client unwraps both the brief and the enclosure.
//
// This is the smallest possible end-to-end demonstration that everything
// from the handshake layer down through the envelope/seal layer composes
// correctly. It is intentionally still single-process: there is no transport
// and no real discovery, but the cryptographic boundaries are real.
func TestCrossDomainEnvelopeFlow(t *testing.T) {
	suite := crypto.SuiteBaseline

	// --- Federation handshake setup
	storeA := newMemStore()
	storeB := newMemStore()

	// Sender server (a.example) ed25519 domain SIGNING key.
	sigPubA, sigPrivA, _ := suite.Signer().GenerateKeyPair()
	sigFPA := storeA.putDomainKey("a.example", sigPubA)
	storeB.putDomainKey("a.example", sigPubA)

	// Recipient server (b.example) ed25519 domain SIGNING key.
	sigPubB, sigPrivB, _ := suite.Signer().GenerateKeyPair()
	sigFPB := storeA.putDomainKey("b.example", sigPubB)
	storeB.putDomainKey("b.example", sigPubB)
	_ = sigFPB

	// Recipient server (b.example) X25519 ENCRYPTION key — this is what
	// the seal wraps K_brief under so the recipient server can read the
	// brief for delivery policy.
	encPubB, encPrivB, _ := suite.KEM().GenerateKeyPair()
	encFPB := keys.Compute(encPubB)

	// Recipient client (bob@b.example) X25519 encryption key — this is
	// what wraps both K_brief and K_enclosure for the client.
	clientPubB, clientPrivB, _ := suite.KEM().GenerateKeyPair()
	clientFPB := keys.Compute(clientPubB)

	// --- Federation handshake A → B
	initiator := handshake.NewInitiator(handshake.InitiatorConfig{
		Suite:                 suite,
		Store:                 storeA,
		LocalDomain:           "a.example",
		LocalDomainKeyID:      sigFPA,
		LocalDomainPrivateKey: sigPrivA,
		PeerDomain:            "b.example",
		DomainProof:           handshake.DomainProof{Method: handshake.DomainVerifyTestTrust, Data: "ok"},
	})
	responder := handshake.NewResponder(handshake.ResponderConfig{
		Suite:                 suite,
		Store:                 storeB,
		LocalDomain:           "b.example",
		LocalDomainKeyID:      sigFPB,
		LocalDomainPrivateKey: sigPrivB,
		Policy: handshake.FederationPolicy{
			MessageRetention: "7d",
			UserDiscovery:    "allowed",
			RelayAllowed:     true,
		},
		SessionTTL: 3600,
	})
	defer initiator.Erase()
	defer responder.Erase()

	initBytes, err := initiator.Init()
	if err != nil {
		t.Fatalf("initiator.Init: %v", err)
	}
	respBytes, err := responder.OnInit(initBytes)
	if err != nil {
		t.Fatalf("responder.OnInit: %v", err)
	}
	confirmBytes, sessA, err := initiator.OnResponse(respBytes)
	if err != nil {
		t.Fatalf("initiator.OnResponse: %v", err)
	}
	acceptedBytes, sessB, err := responder.OnConfirm(confirmBytes)
	if err != nil {
		t.Fatalf("responder.OnConfirm: %v", err)
	}
	if err := initiator.OnAccepted(acceptedBytes, sessA); err != nil {
		t.Fatalf("initiator.OnAccepted: %v", err)
	}

	if !bytesEqual(sessA.EnvMAC(), sessB.EnvMAC()) {
		t.Fatal("federation K_env_mac mismatch")
	}
	if sessA.ID != sessB.ID {
		t.Fatalf("federation session ID mismatch: A=%s B=%s", sessA.ID, sessB.ID)
	}

	// --- Envelope composition (alice@a.example → bob@b.example)
	bf := brief.Brief{
		MessageID: "01JCROSSDOMAIN00000000000001",
		From:      "alice@a.example",
		To:        []brief.Address{"bob@b.example"},
		SentAt:    time.Date(2026, 4, 9, 12, 0, 0, 0, time.UTC),
	}
	enc := enclosure.Enclosure{
		Subject:     "cross-domain hello",
		ContentType: "text/plain",
		Body: enclosure.Body{
			"text/plain": "the federation session is real and the envelope rides on its K_env_mac.",
		},
	}

	in := &envelope.ComposeInput{
		Suite: suite,
		Postmark: envelope.Postmark{
			ID:         "01JCROSSDOMAINPOSTMARK00000001",
			SessionID:  sessA.ID, // bind the envelope to the federation session
			FromDomain: "a.example",
			ToDomain:   "b.example",
			Expires:    time.Date(2026, 4, 9, 13, 0, 0, 0, time.UTC),
		},
		Brief:             bf,
		Enclosure:         enc,
		SenderDomainKeyID: sigFPA,
		BriefRecipients: []seal.RecipientKey{
			{Fingerprint: encFPB, PublicKey: encPubB},     // recipient SERVER
			{Fingerprint: clientFPB, PublicKey: clientPubB}, // recipient CLIENT
		},
		EnclosureRecipients: []seal.RecipientKey{
			{Fingerprint: clientFPB, PublicKey: clientPubB}, // client only
		},
	}
	env, err := envelope.Compose(in)
	if err != nil {
		t.Fatalf("envelope.Compose: %v", err)
	}

	// --- Sender's home server signs with its domain priv key AND with
	// K_env_mac drawn from the federation session it just established.
	if err := envelope.Sign(env, suite, sigPrivA, sessA.EnvMAC()); err != nil {
		t.Fatalf("envelope.Sign: %v", err)
	}

	// --- Wire bytes
	wire, err := envelope.Encode(env)
	if err != nil {
		t.Fatalf("envelope.Encode: %v", err)
	}
	t.Logf("cross-domain envelope on the wire: %d bytes", len(wire))

	got, err := envelope.Decode(wire)
	if err != nil {
		t.Fatalf("envelope.Decode: %v", err)
	}

	// --- Receiving server (Server B) verifies BOTH proofs:
	// 1. the routing-layer signature against Server A's published domain key
	// 2. the delivery-layer session MAC against the K_env_mac IT derived
	//    during the same federation handshake (sessB.EnvMAC()).
	if err := envelope.VerifySignature(got, suite, sigPubA); err != nil {
		t.Fatalf("VerifySignature: %v", err)
	}
	if err := envelope.VerifySessionMAC(got, suite, sessB.EnvMAC()); err != nil {
		t.Fatalf("VerifySessionMAC: %v", err)
	}

	// --- Server B unwraps the brief.
	briefForServer, err := envelope.OpenBrief(got, suite, encFPB, encPrivB)
	if err != nil {
		t.Fatalf("server OpenBrief: %v", err)
	}
	if briefForServer.MessageID != bf.MessageID {
		t.Errorf("server brief MessageID mismatch")
	}
	if string(briefForServer.From) != string(bf.From) {
		t.Errorf("server brief From mismatch")
	}

	// --- Bob's client unwraps both layers.
	briefForClient, err := envelope.OpenBrief(got, suite, clientFPB, clientPrivB)
	if err != nil {
		t.Fatalf("client OpenBrief: %v", err)
	}
	if briefForClient.MessageID != bf.MessageID {
		t.Errorf("client brief MessageID mismatch")
	}
	encForClient, err := envelope.OpenEnclosure(got, suite, clientFPB, clientPrivB)
	if err != nil {
		t.Fatalf("client OpenEnclosure: %v", err)
	}
	if encForClient.Subject != enc.Subject {
		t.Errorf("client enclosure subject mismatch: got %q want %q", encForClient.Subject, enc.Subject)
	}
	if encForClient.Body["text/plain"] != enc.Body["text/plain"] {
		t.Errorf("client enclosure body mismatch")
	}

	// --- The recipient server MUST NOT be able to decrypt the enclosure.
	if _, err := envelope.OpenEnclosure(got, suite, encFPB, encPrivB); err == nil {
		t.Error("recipient server was able to decrypt the enclosure — privacy boundary broken")
	}

	// --- Tamper detection still works on cross-domain envelopes.
	tampered := append([]byte{}, wire...)
	tampered[len(tampered)/2] ^= 0x01
	if tEnv, terr := envelope.Decode(tampered); terr == nil {
		if err := envelope.VerifySignature(tEnv, suite, sigPubA); err == nil {
			t.Error("VerifySignature accepted a tampered cross-domain envelope")
		}
	}
}

// TestCrossDomainSessionMACMismatch confirms that an envelope produced under
// one federation session's K_env_mac CANNOT be verified against a different
// session's K_env_mac. This is the cryptographic guarantee that envelopes
// are bound to a specific established session per ENVELOPE.md §10.3.
func TestCrossDomainSessionMACMismatch(t *testing.T) {
	suite := crypto.SuiteBaseline

	// Sender domain key.
	sigPub, sigPriv, _ := suite.Signer().GenerateKeyPair()
	sigFP := keys.Compute(sigPub)

	// Two unrelated K_env_macs — pretend they came from two different
	// federation sessions.
	macA, _ := crypto.FreshKey(suite.AEAD())
	macB, _ := crypto.FreshKey(suite.AEAD())

	recipPub, _, _ := suite.KEM().GenerateKeyPair()
	recipFP := keys.Compute(recipPub)

	in := &envelope.ComposeInput{
		Suite: suite,
		Postmark: envelope.Postmark{
			ID:         "id",
			SessionID:  "session-A",
			FromDomain: "a.example",
			ToDomain:   "b.example",
			Expires:    time.Now().Add(time.Hour),
		},
		Brief:               brief.Brief{MessageID: "m"},
		Enclosure:           enclosure.Enclosure{ContentType: "text/plain", Body: enclosure.Body{"text/plain": "x"}},
		SenderDomainKeyID:   sigFP,
		BriefRecipients:     []seal.RecipientKey{{Fingerprint: recipFP, PublicKey: recipPub}},
		EnclosureRecipients: []seal.RecipientKey{{Fingerprint: recipFP, PublicKey: recipPub}},
	}
	env, err := envelope.Compose(in)
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	if err := envelope.Sign(env, suite, sigPriv, macA); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	// Same envelope, verified under the WRONG K_env_mac, MUST fail.
	if err := envelope.VerifySessionMAC(env, suite, macB); err == nil {
		t.Error("VerifySessionMAC accepted an envelope sealed with a different session key")
	}
	// Sanity: verifies under the CORRECT key.
	if err := envelope.VerifySessionMAC(env, suite, macA); err != nil {
		t.Errorf("VerifySessionMAC under correct key failed: %v", err)
	}
}
