package test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"semp.dev/semp-go/brief"
	"semp.dev/semp-go/crypto"
	"semp.dev/semp-go/enclosure"
	"semp.dev/semp-go/envelope"
	"semp.dev/semp-go/handshake"
	"semp.dev/semp-go/keys"
	"semp.dev/semp-go/seal"
	"semp.dev/semp-go/session"
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

	// Sender user identity key (signs the enclosure per ENVELOPE.md §6.5).
	identityPubA, identityPrivA, _ := suite.Signer().GenerateKeyPair()
	identityFPA := keys.Compute(identityPubA)

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
			Expires:    time.Now().UTC().Add(time.Hour),
		},
		Brief:              bf,
		Enclosure:          enc,
		SenderDomainKeyID:  sigFPA,
		IdentityPrivateKey: identityPrivA,
		IdentityKeyID:      string(identityFPA),
		BriefRecipients: []seal.RecipientKey{
			{Fingerprint: encFPB, PublicKey: encPubB, Kind: seal.KindServerDomain},     // recipient SERVER
			{Fingerprint: clientFPB, PublicKey: clientPubB, Kind: seal.KindUserClient}, // recipient CLIENT
		},
		EnclosureRecipients: []seal.RecipientKey{
			{Fingerprint: clientFPB, PublicKey: clientPubB, Kind: seal.KindUserClient}, // client only
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
	briefForServer, err := envelope.OpenBrief(got, suite, encFPB, encPrivB, encPubB)
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
	briefForClient, err := envelope.OpenBrief(got, suite, clientFPB, clientPrivB, clientPubB)
	if err != nil {
		t.Fatalf("client OpenBrief: %v", err)
	}
	if briefForClient.MessageID != bf.MessageID {
		t.Errorf("client brief MessageID mismatch")
	}
	encForClient, err := envelope.OpenEnclosure(got, suite, clientFPB, clientPrivB, clientPubB)
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
	if _, err := envelope.OpenEnclosure(got, suite, encFPB, encPrivB, encPubB); err == nil {
		t.Error("recipient server was able to decrypt the enclosure — privacy boundary broken")
	}

	// --- Tamper detection still works on cross-domain envelopes.
	// Flip a byte inside the signed area rather than at the middle of
	// the wire, because the middle of a size-padded envelope now lands
	// inside the `padding` field (which is intentionally excluded from
	// the signature scope per ENVELOPE.md §4.3).
	tampered := append([]byte{}, wire...)
	tamperIdx := indexOfSignedRegion(t, tampered)
	tampered[tamperIdx] ^= 0x01
	if tEnv, terr := envelope.Decode(tampered); terr == nil {
		if err := envelope.VerifySignature(tEnv, suite, sigPubA); err == nil {
			t.Error("VerifySignature accepted a tampered cross-domain envelope")
		}
	}
}

// indexOfSignedRegion returns a byte offset in wire that sits inside a
// field covered by seal.signature. Padding occupies most of the wire
// for size-padded envelopes, so we target the `postmark` object near
// the start of the JSON instead.
func indexOfSignedRegion(t *testing.T, wire []byte) int {
	t.Helper()
	marker := []byte(`"postmark":{`)
	idx := bytes.Index(wire, marker)
	if idx < 0 {
		t.Fatalf("could not locate postmark in wire")
	}
	return idx + len(marker) + 2
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
	identityPub, identityPriv, _ := suite.Signer().GenerateKeyPair()

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
		IdentityPrivateKey:  identityPriv,
		IdentityKeyID:       string(keys.Compute(identityPub)),
		BriefRecipients:     []seal.RecipientKey{{Fingerprint: recipFP, PublicKey: recipPub, Kind: seal.KindUserClient}},
		EnclosureRecipients: []seal.RecipientKey{{Fingerprint: recipFP, PublicKey: recipPub, Kind: seal.KindUserClient}},
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

// TestFederationHandshakeResume exercises HANDSHAKE.md §2.8.7
// federation resumption: an initiator and responder complete a normal
// federation handshake (the responder issues a ResumptionTicket),
// then the initiator uses Initiator.Resume on a fresh state machine
// to short-circuit to a resumed federation session via
// Responder.OnResume, and the resumed session's K_env_mac matches
// across both sides.
func TestFederationHandshakeResume(t *testing.T) {
	suite := crypto.SuiteBaseline

	storeA := newMemStore()
	storeB := newMemStore()
	sigPubA, sigPrivA, _ := suite.Signer().GenerateKeyPair()
	sigFPA := storeA.putDomainKey("a.example", sigPubA)
	storeB.putDomainKey("a.example", sigPubA)
	sigPubB, sigPrivB, _ := suite.Signer().GenerateKeyPair()
	sigFPB := storeA.putDomainKey("b.example", sigPubB)
	storeB.putDomainKey("b.example", sigPubB)
	_ = sigFPB

	ticketKey := make([]byte, suite.AEAD().KeySize())
	for i := range ticketKey {
		ticketKey[i] = byte(i + 1)
	}
	issuer, err := session.NewStatelessTicketIssuer(suite.AEAD(), ticketKey)
	if err != nil {
		t.Fatalf("NewStatelessTicketIssuer: %v", err)
	}

	mkInitiator := func() *handshake.Initiator {
		return handshake.NewInitiator(handshake.InitiatorConfig{
			Suite:                 suite,
			Store:                 storeA,
			LocalDomain:           "a.example",
			LocalServerID:         "server-a-1",
			LocalDomainKeyID:      sigFPA,
			LocalDomainPrivateKey: sigPrivA,
			PeerDomain:            "b.example",
			DomainProof: handshake.DomainProof{
				Method: handshake.DomainVerifyTestTrust, Data: "ok",
			},
		})
	}
	mkResponder := func() *handshake.Responder {
		return handshake.NewResponder(handshake.ResponderConfig{
			Suite:                 suite,
			Store:                 storeB,
			LocalDomain:           "b.example",
			LocalServerID:         "server-b-1",
			LocalDomainKeyID:      sigFPB,
			LocalDomainPrivateKey: sigPrivB,
			Policy: handshake.FederationPolicy{
				MessageRetention: "7d",
				UserDiscovery:    "allowed",
				RelayAllowed:     true,
			},
			SessionTTL:   3600,
			TicketIssuer: issuer,
		})
	}

	// ---- 1. Full federation handshake to obtain the ticket.
	initiator1 := mkInitiator()
	responder1 := mkResponder()
	defer initiator1.Erase()
	defer responder1.Erase()

	initBytes, err := initiator1.Init()
	if err != nil {
		t.Fatalf("initiator1.Init: %v", err)
	}
	respBytes, err := responder1.OnInit(initBytes)
	if err != nil {
		t.Fatalf("responder1.OnInit: %v", err)
	}
	confirmBytes, sessA1, err := initiator1.OnResponse(respBytes)
	if err != nil {
		t.Fatalf("initiator1.OnResponse: %v", err)
	}
	acceptedBytes, _, err := responder1.OnConfirm(confirmBytes)
	if err != nil {
		t.Fatalf("responder1.OnConfirm: %v", err)
	}
	if err := initiator1.OnAccepted(acceptedBytes, sessA1); err != nil {
		t.Fatalf("initiator1.OnAccepted: %v", err)
	}

	// Pull the ticket.
	var firstAcc struct {
		ResumptionTicket *struct {
			Value     string    `json:"value"`
			ExpiresAt time.Time `json:"expires_at"`
		} `json:"resumption_ticket"`
	}
	if err := json.Unmarshal(acceptedBytes, &firstAcc); err != nil {
		t.Fatalf("unmarshal first accepted: %v", err)
	}
	if firstAcc.ResumptionTicket == nil {
		t.Fatal("responder did not issue a federation resumption ticket")
	}
	ticketBytes, err := base64.StdEncoding.DecodeString(firstAcc.ResumptionTicket.Value)
	if err != nil {
		t.Fatalf("decode federation ticket: %v", err)
	}
	resumptionSecret := append([]byte(nil), sessA1.Resumption()...)
	if len(resumptionSecret) == 0 {
		t.Fatal("federation session has no K_resumption")
	}

	// ---- 2. Federation resume on fresh state machines.
	initiator2 := mkInitiator()
	responder2 := mkResponder()
	defer initiator2.Erase()
	defer responder2.Erase()

	initiator2.LoadResumptionSecret(resumptionSecret)
	resumeBytes, err := initiator2.Resume(ticketBytes, 0)
	if err != nil {
		t.Fatalf("initiator2.Resume: %v", err)
	}
	resumedAcceptedBytes, sessB2, err := responder2.OnResume(resumeBytes)
	if err != nil {
		t.Fatalf("responder2.OnResume: %v", err)
	}
	sessA2, newTicketBytes, err := initiator2.OnResumeAccepted(resumedAcceptedBytes)
	if err != nil {
		t.Fatalf("initiator2.OnResumeAccepted: %v", err)
	}

	// ---- 3. Both sides agree on the resumed session keys.
	if sessA2.ID != sessB2.ID {
		t.Errorf("resumed federation session ID mismatch: A=%s B=%s", sessA2.ID, sessB2.ID)
	}
	if !bytesEqualHelper(sessA2.EnvMAC(), sessB2.EnvMAC()) {
		t.Error("resumed federation K_env_mac mismatch between initiator and responder")
	}
	if bytesEqualHelper(sessA1.EnvMAC(), sessA2.EnvMAC()) {
		t.Error("resumed federation K_env_mac matches original; resume did not derive fresh keys")
	}
	if sessB2.PeerIdentity != "a.example" {
		t.Errorf("resumed responder peer identity = %q, want a.example", sessB2.PeerIdentity)
	}
	if len(newTicketBytes) == 0 {
		t.Error("OnResumeAccepted returned empty federation replacement ticket")
	}

	// ---- 4. Single-use enforcement: a second resume with the SAME
	// ticket MUST fail.
	initiator3 := mkInitiator()
	defer initiator3.Erase()
	responder3 := mkResponder()
	defer responder3.Erase()
	initiator3.LoadResumptionSecret(resumptionSecret)
	resumeBytes2, err := initiator3.Resume(ticketBytes, 0)
	if err != nil {
		t.Fatalf("initiator3.Resume: %v", err)
	}
	if _, _, err := responder3.OnResume(resumeBytes2); err == nil {
		t.Error("second federation OnResume with consumed ticket: want error, got nil")
	}
}
