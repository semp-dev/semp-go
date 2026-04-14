package test

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	semp "semp.dev/semp-go"
	"semp.dev/semp-go/brief"
	"semp.dev/semp-go/crypto"
	"semp.dev/semp-go/delivery"
	"semp.dev/semp-go/delivery/inboxd"
	"semp.dev/semp-go/enclosure"
	"semp.dev/semp-go/envelope"
	"semp.dev/semp-go/handshake"
	"semp.dev/semp-go/internal/demoseed"
	"semp.dev/semp-go/keys"
	"semp.dev/semp-go/keys/memstore"
	"semp.dev/semp-go/seal"
	"semp.dev/semp-go/transport"
	"semp.dev/semp-go/transport/ws"
)

// TestDeviceCertificateScopeEnforcement drives a delegated-device
// flow end to end. alice has a primary identity key (registered in
// the store) and a DEVICE identity key whose certificate restricts
// it to sending only to bob@example.com. carol@example.com is a
// valid local user but is NOT in the allow list.
//
// The test authenticates as the delegated device (signs identity
// proofs with the device key, not the primary key), submits two
// envelopes — one to bob, one to carol — and asserts:
//
//  1. bob's delivery succeeds (recipient in the allow list).
//  2. carol's delivery is rejected with scope_exceeded.
//  3. Submission to carol only (nothing allowed) still returns a
//     per-recipient response with status=rejected.
//
// After flipping the certificate to scope.send.mode=all, a send
// to carol succeeds. After flipping to mode=none, bob's own
// submission is rejected.
func TestDeviceCertificateScopeEnforcement(t *testing.T) {
	const (
		seed    = "test-device-cert"
		domain  = "example.com"
		alice   = "alice@example.com"
		bob     = "bob@example.com"
		carol   = "carol@example.com"
	)
	suite := crypto.SuiteBaseline

	// We can't reuse bringUpServer because the delegated device
	// needs a DIFFERENT identity key than demoseed.Identity(seed,
	// alice) would produce. Build the fixture inline with a custom
	// primary/device keypair for alice.
	store := memstore.New()
	inbox := delivery.NewInbox()

	domainSignPub, domainSignPriv := demoseed.DomainSigning(seed, domain)
	domainSignFP := store.PutDomainKey(domain, domainSignPub)
	domainEncPub, domainEncPriv, err := demoseed.DomainEncryption(seed, domain)
	if err != nil {
		t.Fatalf("derive domain enc: %v", err)
	}
	domainEncFP := store.PutDomainEncryptionKey(domain, domainEncPub)

	// alice's primary identity key — the one that signs device
	// certificates.
	primaryPub, primaryPriv, err := suite.Signer().GenerateKeyPair()
	if err != nil {
		t.Fatalf("primary keypair: %v", err)
	}
	primaryFP := store.PutUserKey(alice, keys.TypeIdentity, "ed25519", primaryPub)

	// alice's delegated device identity key — what the CLI will
	// authenticate as. The primary key signs a DeviceCertificate
	// binding this device's fingerprint to a scope.
	devicePub, devicePriv, err := suite.Signer().GenerateKeyPair()
	if err != nil {
		t.Fatalf("device keypair: %v", err)
	}
	deviceFP := store.PutUserKey(alice, keys.TypeIdentity, "ed25519", devicePub)

	// alice encryption key (for completeness; the delegated device
	// still uses the user's shared encryption key for decryption).
	aliceEncPub, _, err := demoseed.Encryption(seed, alice)
	if err != nil {
		t.Fatalf("derive alice enc: %v", err)
	}
	store.PutUserKey(alice, keys.TypeEncryption, "x25519-chacha20-poly1305", aliceEncPub)

	// Pre-seed bob and carol with their encryption keys so the
	// SEMP_KEYS lookup finds them.
	for _, u := range []string{bob, carol} {
		idPub, _ := demoseed.Identity(seed, u)
		store.PutUserKey(u, keys.TypeIdentity, "ed25519", idPub)
		encPub, _, err := demoseed.Encryption(seed, u)
		if err != nil {
			t.Fatalf("derive %s enc: %v", u, err)
		}
		store.PutUserKey(u, keys.TypeEncryption, "x25519-chacha20-poly1305", encPub)
	}

	// Build the certificate: restrict the device to bob only.
	cert := &keys.DeviceCertificate{
		Type:               "SEMP_DEVICE_CERTIFICATE",
		Version:            "1.0.0",
		UserID:             alice,
		DeviceID:           "01JTESTDELEGATED0000000000001",
		DeviceKeyID:        deviceFP,
		IssuingDeviceKeyID: primaryFP,
		Scope: keys.Scope{
			Send: keys.SendScope{
				Mode:  keys.SendModeRestricted,
				Allow: []string{bob},
			},
			Receive: true,
		},
		IssuedAt: time.Now().UTC(),
	}
	if err := keys.SignDeviceCertificate(suite.Signer(), primaryPriv, cert); err != nil {
		t.Fatalf("SignDeviceCertificate: %v", err)
	}
	if err := store.PutDeviceCertificate(context.Background(), cert); err != nil {
		t.Fatalf("PutDeviceCertificate: %v", err)
	}

	// Stand up an httptest server wired to inboxd in ModeClient.
	wsTransport := ws.NewWithConfig(ws.Config{AllowInsecure: true, OriginPatterns: []string{"*"}})
	silent := log.New(io.Discard, "", 0)
	var wg sync.WaitGroup
	mux := http.NewServeMux()
	mux.Handle("/v1/ws", ws.NewHandler(ws.Config{AllowInsecure: true, OriginPatterns: []string{"*"}},
		func(conn transport.Conn) {
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer conn.Close()
				srv := handshake.NewServer(handshake.ServerConfig{
					Suite:            suite,
					Store:            store,
					Policy:           permitAllPolicy{},
					Domain:           domain,
					DomainKeyID:      domainSignFP,
					DomainPrivateKey: domainSignPriv,
				})
				defer srv.Erase()
				hsCtx, hsCancel := context.WithTimeout(context.Background(), 5*time.Second)
				sess, err := handshake.RunServer(hsCtx, conn, srv)
				hsCancel()
				if err != nil {
					return
				}
				loop := &inboxd.Server{
					Mode:           inboxd.ModeClient,
					Suite:          suite,
					Store:          store,
					Inbox:          inbox,
					LocalDomain:    domain,
					DomainSignFP:   domainSignFP,
					DomainSignPriv: domainSignPriv,
					DomainEncFP:    domainEncFP,
					DomainEncPriv:  domainEncPriv,
					DomainEncPub:   domainEncPub,
					Identity:       srv.ClientIdentity(),
					DeviceKeyID:    srv.ClientDeviceKeyID(),
					Session:        sess,
					Logger:         silent,
				}
				_ = loop.Serve(context.Background(), conn)
			}()
		}))
	httpSrv := httptest.NewServer(mux)
	defer func() {
		httpSrv.Close()
		wg.Wait()
	}()
	wsURL := "ws://" + strings.TrimPrefix(httpSrv.URL, "http://") + "/v1/ws"

	// Helper: open a client session as alice's DELEGATED DEVICE
	// (signing identity_signature with devicePriv, publishing
	// deviceFP as ClientLongTermKeyID).
	newDelegatedConn := func() transport.Conn {
		clientStore := memstore.New()
		clientStore.PutUserKey(alice, keys.TypeIdentity, "ed25519", devicePub)
		clientStore.PutPrivateKey(deviceFP, devicePriv)
		clientStore.PutDomainKey(domain, domainSignPub)

		dialCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn, err := wsTransport.Dial(dialCtx, wsURL)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		cli := handshake.NewClient(handshake.ClientConfig{
			Suite:         suite,
			Store:         clientStore,
			Identity:      alice,
			IdentityKeyID: deviceFP,
			ServerDomain:  domain,
		})
		hsCtx, hsCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer hsCancel()
		if _, err := handshake.RunClient(hsCtx, conn, cli); err != nil {
			_ = conn.Close()
			t.Fatalf("RunClient: %v", err)
		}
		return conn
	}

	// --- Case 1: restricted scope allows bob, blocks carol in the
	// same submission. Both recipients are in the same envelope.
	conn := newDelegatedConn()
	resp := submitTwoRecipients(t, suite, conn, seed, domain, alice, bob, carol, "hello", "hi")
	_ = conn.Close()

	// Expect one delivered (bob) and one scope_exceeded (carol).
	gotDelivered, gotRejected := 0, 0
	for _, r := range resp.Results {
		switch r.Status {
		case semp.StatusDelivered:
			gotDelivered++
			if r.Recipient != bob {
				t.Errorf("delivered to %s, want %s", r.Recipient, bob)
			}
		case semp.StatusRejected:
			gotRejected++
			if r.Recipient != carol {
				t.Errorf("rejected %s, want %s", r.Recipient, carol)
			}
			if r.ReasonCode != semp.ReasonScopeExceeded {
				t.Errorf("reject reason = %s, want scope_exceeded", r.ReasonCode)
			}
		}
	}
	if gotDelivered != 1 || gotRejected != 1 {
		t.Errorf("expected 1 delivered + 1 rejected, got %d + %d", gotDelivered, gotRejected)
	}

	// --- Case 2: flip the certificate to mode=all. A send to carol
	// now succeeds.
	cert.Scope.Send = keys.SendScope{Mode: keys.SendModeAll}
	cert.Signature = keys.PublicationSignature{}
	if err := keys.SignDeviceCertificate(suite.Signer(), primaryPriv, cert); err != nil {
		t.Fatalf("re-sign cert (mode=all): %v", err)
	}
	if err := store.PutDeviceCertificate(context.Background(), cert); err != nil {
		t.Fatalf("PutDeviceCertificate: %v", err)
	}
	conn = newDelegatedConn()
	resp = submitOneRecipient(t, suite, conn, seed, domain, alice, carol, "carol is fine now", "after mode=all")
	_ = conn.Close()
	if len(resp.Results) != 1 || resp.Results[0].Status != semp.StatusDelivered {
		t.Errorf("mode=all: expected delivered, got %+v", resp.Results)
	}

	// --- Case 3: flip to mode=none. Even bob is rejected.
	cert.Scope.Send = keys.SendScope{Mode: keys.SendModeNone}
	cert.Signature = keys.PublicationSignature{}
	if err := keys.SignDeviceCertificate(suite.Signer(), primaryPriv, cert); err != nil {
		t.Fatalf("re-sign cert (mode=none): %v", err)
	}
	if err := store.PutDeviceCertificate(context.Background(), cert); err != nil {
		t.Fatalf("PutDeviceCertificate: %v", err)
	}
	conn = newDelegatedConn()
	resp = submitOneRecipient(t, suite, conn, seed, domain, alice, bob, "mode=none", "should be blocked")
	_ = conn.Close()
	if len(resp.Results) != 1 || resp.Results[0].Status != semp.StatusRejected {
		t.Errorf("mode=none: expected rejected, got %+v", resp.Results)
	}
	if resp.Results[0].ReasonCode != semp.ReasonScopeExceeded {
		t.Errorf("mode=none: reject reason = %s, want scope_exceeded", resp.Results[0].ReasonCode)
	}
}

// TestDeviceCertificateMissingCertIsFullAccess confirms the
// backward-compatible path: a device key with no registered
// certificate is treated as full-access (primary device), so
// submissions are not affected by the scope code.
func TestDeviceCertificateMissingCertIsFullAccess(t *testing.T) {
	const (
		seed   = "test-full-access"
		domain = "example.com"
		alice  = "alice@example.com"
		bob    = "bob@example.com"
	)
	suite := crypto.SuiteBaseline

	srv := bringUpServer(t, seed, domain, []string{alice, bob})
	defer srv.close()

	// No PutDeviceCertificate call — alice is a primary device.
	// The existing submitEnvelopeCrossDomain helper drives the
	// demoseed-based identity, which means srv sees a
	// ClientDeviceKeyID but no cert is in the store.
	results := submitEnvelopeCrossDomain(t, suite, srv, seed, domain, alice, bob, "primary", "no cert")
	if len(results) != 1 || results[0].Status != semp.StatusDelivered {
		t.Errorf("expected delivered, got %+v", results)
	}
}

// submitTwoRecipients composes an envelope addressed to two
// recipients, submits it over the already-open conn, and returns
// the parsed SubmissionResponse.
func submitTwoRecipients(t *testing.T, suite crypto.Suite, conn transport.Conn, seed, domain, from, to1, to2, subject, body string) *delivery.SubmissionResponse {
	t.Helper()
	return submitMultiRecipient(t, suite, conn, seed, domain, from, []string{to1, to2}, subject, body)
}

// submitOneRecipient composes an envelope addressed to a single
// recipient and submits it.
func submitOneRecipient(t *testing.T, suite crypto.Suite, conn transport.Conn, seed, domain, from, to, subject, body string) *delivery.SubmissionResponse {
	t.Helper()
	return submitMultiRecipient(t, suite, conn, seed, domain, from, []string{to}, subject, body)
}

// submitMultiRecipient does the actual envelope composition and
// submission. It derives the necessary encryption keys via
// demoseed (same seed as the server), so the in-process test
// fixture can decrypt the brief and enforce scope.
func submitMultiRecipient(t *testing.T, suite crypto.Suite, conn transport.Conn, seed, domain, from string, to []string, subject, body string) *delivery.SubmissionResponse {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	senderDomainEncPub, _, err := demoseed.DomainEncryption(seed, domain)
	if err != nil {
		t.Fatalf("derive sender server enc: %v", err)
	}
	senderDomainEncFP := keys.Compute(senderDomainEncPub)

	briefRecipients := []seal.RecipientKey{
		{Fingerprint: senderDomainEncFP, PublicKey: senderDomainEncPub},
	}
	enclosureRecipients := []seal.RecipientKey{}
	briefTo := make([]brief.Address, 0, len(to))
	for _, recip := range to {
		briefTo = append(briefTo, brief.Address(recip))
		encPub, _, err := demoseed.Encryption(seed, recip)
		if err != nil {
			t.Fatalf("derive recipient enc: %v", err)
		}
		encFP := keys.Compute(encPub)
		briefRecipients = append(briefRecipients, seal.RecipientKey{Fingerprint: encFP, PublicKey: encPub})
		enclosureRecipients = append(enclosureRecipients, seal.RecipientKey{Fingerprint: encFP, PublicKey: encPub})
	}

	// Need any handshake-established session_id for the postmark.
	// We don't actually have direct access to it here — any unique
	// ULID-shaped string works since inboxd re-signs the envelope
	// before storage.
	in := &envelope.ComposeInput{
		Suite: suite,
		Postmark: envelope.Postmark{
			ID:         "01JTESTSCOPE00000000000000001",
			SessionID:  "01JTESTSCOPESESSION0000000001",
			FromDomain: domain,
			ToDomain:   domain,
			Expires:    time.Now().UTC().Add(time.Hour),
		},
		Brief: brief.Brief{
			MessageID: "01JTESTSCOPEMESSAGE0000000001",
			From:      brief.Address(from),
			To:        briefTo,
			SentAt:    time.Now().UTC(),
		},
		Enclosure: enclosure.Enclosure{
			Subject:     subject,
			ContentType: "text/plain",
			Body:        enclosure.Body{"text/plain": body},
		},
		SenderDomainKeyID:   keys.Fingerprint("server-fills-in"),
		BriefRecipients:     briefRecipients,
		EnclosureRecipients: enclosureRecipients,
	}
	env, err := envelope.Compose(in)
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	wire, err := envelope.Encode(env)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if err := conn.Send(ctx, wire); err != nil {
		t.Fatalf("send envelope: %v", err)
	}
	respRaw, err := conn.Recv(ctx)
	if err != nil {
		t.Fatalf("recv response: %v", err)
	}
	var resp delivery.SubmissionResponse
	if err := json.Unmarshal(respRaw, &resp); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	return &resp
}
