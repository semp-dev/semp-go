package test

import (
	"context"
	"testing"
	"time"

	"semp.dev/semp-go/brief"
	"semp.dev/semp-go/crypto"
	"semp.dev/semp-go/enclosure"
	"semp.dev/semp-go/envelope"
	"semp.dev/semp-go/handshake"
	"semp.dev/semp-go/internal/demoseed"
	"semp.dev/semp-go/keys"
	"semp.dev/semp-go/seal"
	"semp.dev/semp-go/transport/ws"
)

// TestMultiDeviceSEMPKeysReturnsAllDevices drives a real SEMP_KEYS
// round trip for a user with two registered encryption keys (two
// devices), verifies the response carries both records, and then
// uses envelope.Compose to wrap K_brief/K_enclosure for both devices
// and confirms EACH device can independently decrypt the envelope.
//
// This is the milestone-3ee acceptance test: the library's Compose
// API already supports multi-device wrapping via the BriefRecipients
// slice, the SEMP_KEYS path already returns multiple keys per user,
// and OpenBriefAny/OpenEnclosureAny give the receiver a clean way to
// iterate a candidate key set. All the pieces were present; this
// test pins that they compose correctly end-to-end.
func TestMultiDeviceSEMPKeysReturnsAllDevices(t *testing.T) {
	const (
		seed   = "test-multidevice"
		domain = "example.com"
		alice  = "alice@example.com"
		bob    = "bob@example.com"
	)
	suite := crypto.SuiteBaseline

	srv := bringUpServer(t, seed, domain, []string{alice, bob})
	defer srv.close()

	// Register a SECOND encryption key for bob, simulating a
	// newly-registered second device. The first encryption key was
	// pre-seeded by bringUpServer via demoseed; this second one is
	// just a random keypair.
	bob2Pub, bob2Priv, err := suite.KEM().GenerateKeyPair()
	if err != nil {
		t.Fatalf("second device keypair: %v", err)
	}
	bob2FP := srv.store.PutUserKey(bob, keys.TypeEncryption, "x25519-chacha20-poly1305", bob2Pub)

	// Open a client session as alice and fetch bob's keys.
	wsTransport := ws.NewWithConfig(ws.Config{AllowInsecure: true})
	dialCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := wsTransport.Dial(dialCtx, srv.wsURL)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	clientStore := newClientStore(t, seed, domain, alice, srv.store)
	identityFP := keys.Compute(mustIdentityPub(seed, alice))
	cli := handshake.NewClient(handshake.ClientConfig{
		Suite:         suite,
		Store:         clientStore,
		Identity:      alice,
		IdentityKeyID: identityFP,
		ServerDomain:  domain,
	})
	defer cli.Erase()
	hsCtx, hsCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer hsCancel()
	if _, err := handshake.RunClient(hsCtx, conn, cli); err != nil {
		t.Fatalf("RunClient: %v", err)
	}

	fetcher := keys.NewFetcher(conn)
	req := keys.NewRequest("md-1", []string{bob})
	resp, err := fetcher.FetchKeys(hsCtx, req)
	if err != nil {
		t.Fatalf("FetchKeys: %v", err)
	}

	// Verify the response via the keys.Verifier.
	verifier := &keys.Verifier{Suite: suite}
	if err := verifier.Verify(resp); err != nil {
		t.Fatalf("Verifier.Verify: %v", err)
	}

	// Count encryption keys in bob's result.
	if len(resp.Results) != 1 || resp.Results[0].Status != keys.StatusFound {
		t.Fatalf("expected one found result for bob, got %+v", resp.Results)
	}
	var encKeys []*keys.Record
	for _, rec := range resp.Results[0].UserKeys {
		if rec.Type == keys.TypeEncryption {
			encKeys = append(encKeys, rec)
		}
	}
	if len(encKeys) != 2 {
		t.Fatalf("expected 2 encryption keys for bob (1 demoseed + 1 second device), got %d", len(encKeys))
	}

	// Extract both keys' public bytes + fingerprints. We'll wrap
	// for both in the envelope below.
	bob1Pub, _, err := demoseed.Encryption(seed, bob)
	if err != nil {
		t.Fatalf("derive bob device1 key: %v", err)
	}
	bob1FP := keys.Compute(bob1Pub)
	_, bob1Priv, err := demoseed.Encryption(seed, bob)
	if err != nil {
		t.Fatalf("derive bob device1 priv: %v", err)
	}

	// Compose an envelope addressed to bob, wrapping K_brief and
	// K_enclosure for BOTH bob devices. This mirrors what the CLI's
	// fixed runSend now does via fetchRecipientKeys.
	domainEncPub, _, err := demoseed.DomainEncryption(seed, domain)
	if err != nil {
		t.Fatalf("derive domain enc: %v", err)
	}
	domainEncFP := keys.Compute(domainEncPub)

	in := &envelope.ComposeInput{
		Suite: suite,
		Postmark: envelope.Postmark{
			ID:         "01JTESTMULTIDEVICE00000000001",
			SessionID:  "01JTESTMULTIDEVICESESSION0001",
			FromDomain: domain,
			ToDomain:   domain,
			Expires:    time.Now().UTC().Add(time.Hour),
		},
		Brief: brief.Brief{
			MessageID: "01JTESTMULTIDEVICEMSG0000001",
			From:      brief.Address(alice),
			To:        []brief.Address{brief.Address(bob)},
			SentAt:    time.Now().UTC(),
		},
		Enclosure: enclosure.Enclosure{
			Subject:     "delivered to both devices",
			ContentType: "text/plain",
			Body:        enclosure.Body{"text/plain": "each of bob's two devices should decrypt this"},
		},
		SenderDomainKeyID: keys.Fingerprint("server-fills-in"),
		BriefRecipients: []seal.RecipientKey{
			{Fingerprint: domainEncFP, PublicKey: domainEncPub},
			{Fingerprint: bob1FP, PublicKey: bob1Pub},
			{Fingerprint: bob2FP, PublicKey: bob2Pub},
		},
		EnclosureRecipients: []seal.RecipientKey{
			{Fingerprint: bob1FP, PublicKey: bob1Pub},
			{Fingerprint: bob2FP, PublicKey: bob2Pub},
		},
	}
	env, err := envelope.Compose(in)
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}

	// Sign the envelope (simulates the home server's Sign step so
	// verification would also work if we chose to assert it).
	_, domainSignPriv := demoseed.DomainSigning(seed, domain)
	envMAC, _ := crypto.FreshKey(suite.AEAD())
	if err := envelope.Sign(env, suite, domainSignPriv, envMAC); err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Device 1 opens with its own key only.
	dev1Candidates := []envelope.RecipientPrivateKey{
		{Fingerprint: bob1FP, PrivateKey: bob1Priv},
	}
	bf1, err := envelope.OpenBriefAny(env, suite, dev1Candidates)
	if err != nil {
		t.Fatalf("device1 OpenBriefAny: %v", err)
	}
	if bf1.MessageID != "01JTESTMULTIDEVICEMSG0000001" {
		t.Errorf("device1 brief MessageID mismatch: %q", bf1.MessageID)
	}
	enc1, err := envelope.OpenEnclosureAny(env, suite, dev1Candidates)
	if err != nil {
		t.Fatalf("device1 OpenEnclosureAny: %v", err)
	}
	if enc1.Subject != "delivered to both devices" {
		t.Errorf("device1 subject mismatch: %q", enc1.Subject)
	}

	// Device 2 opens with its own key only.
	dev2Candidates := []envelope.RecipientPrivateKey{
		{Fingerprint: bob2FP, PrivateKey: bob2Priv},
	}
	bf2, err := envelope.OpenBriefAny(env, suite, dev2Candidates)
	if err != nil {
		t.Fatalf("device2 OpenBriefAny: %v", err)
	}
	if bf2.MessageID != "01JTESTMULTIDEVICEMSG0000001" {
		t.Errorf("device2 brief MessageID mismatch: %q", bf2.MessageID)
	}
	enc2, err := envelope.OpenEnclosureAny(env, suite, dev2Candidates)
	if err != nil {
		t.Fatalf("device2 OpenEnclosureAny: %v", err)
	}
	if enc2.Body["text/plain"] != "each of bob's two devices should decrypt this" {
		t.Errorf("device2 body mismatch: %q", enc2.Body["text/plain"])
	}

	// Both devices see the same brief bytes (plaintext equality).
	if bf1.MessageID != bf2.MessageID || bf1.From != bf2.From {
		t.Error("two devices decrypted different briefs from the same envelope")
	}
	if enc1.Subject != enc2.Subject {
		t.Error("two devices decrypted different enclosures from the same envelope")
	}
}
