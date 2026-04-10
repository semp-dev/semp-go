package test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	semp "github.com/semp-dev/semp-go"
	"github.com/semp-dev/semp-go/brief"
	"github.com/semp-dev/semp-go/crypto"
	"github.com/semp-dev/semp-go/delivery"
	"github.com/semp-dev/semp-go/delivery/inboxd"
	"github.com/semp-dev/semp-go/enclosure"
	"github.com/semp-dev/semp-go/envelope"
	"github.com/semp-dev/semp-go/handshake"
	"github.com/semp-dev/semp-go/internal/demoseed"
	"github.com/semp-dev/semp-go/keys"
	"github.com/semp-dev/semp-go/keys/memstore"
	"github.com/semp-dev/semp-go/seal"
	"github.com/semp-dev/semp-go/transport"
	"github.com/semp-dev/semp-go/transport/ws"
)

// TestInboxRouting drives the full demo-binary flow in-process:
//
//   1. Stand up an httptest WebSocket server with the semp.v1 handler.
//   2. Mount the inboxd post-handshake loop on every accepted connection.
//   3. Connection 1: alice runs the handshake and submits an envelope
//      addressed to bob.
//   4. Connection 2: bob runs the handshake and SEMP_FETCHes his inbox.
//   5. Bob decrypts the envelope and the assertions confirm subject and
//      body round-trip byte-for-byte.
//
// This is the milestone-3g acceptance test: it proves the protocol layer
// (handshake + envelope + seal) and the demo-binary glue (inbox +
// inboxd loop + SEMP_SUBMISSION + SEMP_FETCH) compose end-to-end.
func TestInboxRouting(t *testing.T) {
	const (
		seed   = "test-seed-do-not-use-elsewhere"
		domain = "example.com"
		alice  = "alice@example.com"
		bob    = "bob@example.com"
	)
	suite := crypto.SuiteBaseline

	// --- Build the server's keys store and seed it with everything the
	// inboxd loop needs.
	store := memstore.New()
	inbox := delivery.NewInbox()

	domainSignPub, domainSignPriv := demoseed.DomainSigning(seed, domain)
	domainSignFP := store.PutDomainKey(domain, domainSignPub)

	domainEncPub, domainEncPriv, err := demoseed.DomainEncryption(seed, domain)
	if err != nil {
		t.Fatalf("derive domain encryption: %v", err)
	}
	domainEncFP := keys.Compute(domainEncPub)

	for _, u := range []string{alice, bob} {
		identityPub, _ := demoseed.Identity(seed, u)
		store.PutUserKey(u, keys.TypeIdentity, "ed25519", identityPub)

		encPub, _, err := demoseed.Encryption(seed, u)
		if err != nil {
			t.Fatalf("derive encryption %s: %v", u, err)
		}
		store.PutUserKey(u, keys.TypeEncryption, "x25519-chacha20-poly1305", encPub)
	}

	// --- httptest server: every accepted connection runs the handshake
	// and then the inboxd Serve loop.
	logger := log.New(io.Discard, "", 0) // silence the loop logger in tests
	mux := http.NewServeMux()
	var loopWG sync.WaitGroup
	mux.Handle("/v1/ws", ws.NewHandler(ws.Config{
		AllowInsecure:  true,
		OriginPatterns: []string{"*"},
	}, func(conn transport.Conn) {
		loopWG.Add(1)
		go func() {
			defer loopWG.Done()
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
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			sess, err := handshake.RunServer(ctx, conn, srv)
			if err != nil {
				return
			}
			loop := &inboxd.Server{
				Suite:          suite,
				Inbox:          inbox,
				LocalDomain:    domain,
				DomainSignFP:   domainSignFP,
				DomainSignPriv: domainSignPriv,
				DomainEncFP:    domainEncFP,
				DomainEncPriv:  domainEncPriv,
				Identity:       srv.ClientIdentity(),
				EnvMAC:         sess.EnvMAC(),
				Logger:         logger,
			}
			_ = loop.Serve(ctx, conn)
		}()
	}))
	httpServer := httptest.NewServer(mux)
	defer httpServer.Close()
	wsURL := "ws://" + strings.TrimPrefix(httpServer.URL, "http://") + "/v1/ws"

	// --- Connection 1: alice sends an envelope to bob.
	const subject = "ship the federation handshake"
	const body = "we have everything we need to do cross-domain delivery now."

	aliceSubmissionResults := submitEnvelope(t, suite, wsURL, seed, domain, alice, bob, subject, body, store)
	if len(aliceSubmissionResults) != 1 {
		t.Fatalf("expected 1 submission result, got %d", len(aliceSubmissionResults))
	}
	if aliceSubmissionResults[0].Status != semp.StatusDelivered {
		t.Errorf("submission status = %s, want delivered (reason=%s)",
			aliceSubmissionResults[0].Status, aliceSubmissionResults[0].Reason)
	}
	if aliceSubmissionResults[0].Recipient != bob {
		t.Errorf("submission recipient = %s, want %s", aliceSubmissionResults[0].Recipient, bob)
	}

	// --- Inbox state: bob should have one queued envelope.
	if got := inbox.Pending(bob); got != 1 {
		t.Errorf("inbox pending for bob = %d, want 1", got)
	}

	// --- Connection 2: bob fetches his inbox.
	envelopes := fetchInbox(t, suite, wsURL, seed, domain, bob, store)
	if len(envelopes) != 1 {
		t.Fatalf("bob fetched %d envelopes, want 1", len(envelopes))
	}
	got := envelopes[0]
	if got.subject != subject {
		t.Errorf("subject mismatch: got %q want %q", got.subject, subject)
	}
	if got.body != body {
		t.Errorf("body mismatch: got %q want %q", got.body, body)
	}
	if got.from != alice {
		t.Errorf("from mismatch: got %q want %q", got.from, alice)
	}

	// Privacy boundary: the server holds K_brief (so it can route on
	// brief.to) but it MUST NEVER hold K_enclosure. The client wraps
	// K_enclosure only under the recipient client's encryption key in
	// seal.enclosure_recipients, never under the server's domain
	// encryption key. Re-decode the same envelope bytes the server
	// stored and confirm that decrypting the enclosure with the
	// server's domain encryption key fails. (TestEnvelopeRoundTrip and
	// TestCrossDomainEnvelopeFlow assert the same property in their
	// own scopes; this assertion catches the case where someone
	// accidentally adds the server to EnclosureRecipients in the
	// inbox routing path.)
	storedEnv, err := envelope.Decode(got.raw)
	if err != nil {
		t.Fatalf("decode stored envelope for privacy check: %v", err)
	}
	if _, err := envelope.OpenEnclosure(storedEnv, suite, domainEncFP, domainEncPriv); err == nil {
		t.Error("server's domain encryption key was able to decrypt the enclosure — privacy boundary broken")
	}
	// Sanity: the same key SHOULD be able to unwrap the brief, since
	// that's exactly what inboxd uses it for during routing.
	if _, err := envelope.OpenBrief(storedEnv, suite, domainEncFP, domainEncPriv); err != nil {
		t.Errorf("server's domain encryption key cannot unwrap K_brief: %v", err)
	}

	// After fetch, bob's inbox should be empty.
	if got := inbox.Pending(bob); got != 0 {
		t.Errorf("inbox pending after fetch = %d, want 0", got)
	}

	// Wait for the server-side handler goroutines to finish their current
	// iteration so the test exits cleanly under -race.
	httpServer.Close()
	loopWG.Wait()
}

// submitEnvelope opens a session as `from`, composes a single-recipient
// envelope to `to`, sends it, and returns the parsed SubmissionResults.
func submitEnvelope(t *testing.T, suite crypto.Suite, wsURL, seed, domain, from, to, subject, body string, serverStore *memstore.Store) []delivery.SubmissionResult {
	t.Helper()

	// Sender-side store: the server's signing key + alice's identity.
	store := newClientStore(t, seed, domain, from, serverStore)

	// Dial the server.
	wsTransport := ws.NewWithConfig(ws.Config{AllowInsecure: true})
	dialCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := wsTransport.Dial(dialCtx, wsURL)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	identityFP := keys.Compute(mustIdentityPub(seed, from))
	cli := handshake.NewClient(handshake.ClientConfig{
		Suite:         suite,
		Store:         store,
		Identity:      from,
		IdentityKeyID: identityFP,
		ServerDomain:  domain,
	})
	defer cli.Erase()

	hsCtx, hsCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer hsCancel()
	sess, err := handshake.RunClient(hsCtx, conn, cli)
	if err != nil {
		t.Fatalf("RunClient: %v", err)
	}

	// Compose envelope.
	recipEncPub, _, err := demoseed.Encryption(seed, to)
	if err != nil {
		t.Fatalf("derive recipient encryption: %v", err)
	}
	recipEncFP := keys.Compute(recipEncPub)
	domainEncPub, _, err := demoseed.DomainEncryption(seed, domain)
	if err != nil {
		t.Fatalf("derive domain encryption: %v", err)
	}
	domainEncFP := keys.Compute(domainEncPub)

	in := &envelope.ComposeInput{
		Suite: suite,
		Postmark: envelope.Postmark{
			ID:         "01JTESTPOSTMARK00000000000001",
			SessionID:  sess.ID,
			FromDomain: domainOf(from),
			ToDomain:   domainOf(to),
			Expires:    time.Now().UTC().Add(time.Hour),
		},
		Brief: brief.Brief{
			MessageID: "01JTESTMESSAGE0000000000000001",
			From:      brief.Address(from),
			To:        []brief.Address{brief.Address(to)},
			SentAt:    time.Now().UTC(),
		},
		Enclosure: enclosure.Enclosure{
			Subject:     subject,
			ContentType: "text/plain",
			Body:        enclosure.Body{"text/plain": body},
		},
		SenderDomainKeyID: keys.Fingerprint("server-fills-in"),
		BriefRecipients: []seal.RecipientKey{
			{Fingerprint: domainEncFP, PublicKey: domainEncPub},
			{Fingerprint: recipEncFP, PublicKey: recipEncPub},
		},
		EnclosureRecipients: []seal.RecipientKey{
			{Fingerprint: recipEncFP, PublicKey: recipEncPub},
		},
	}
	env, err := envelope.Compose(in)
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	wire, err := envelope.Encode(env)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if err := conn.Send(hsCtx, wire); err != nil {
		t.Fatalf("send envelope: %v", err)
	}

	respRaw, err := conn.Recv(hsCtx)
	if err != nil {
		t.Fatalf("recv submission response: %v", err)
	}
	var resp delivery.SubmissionResponse
	if err := json.Unmarshal(respRaw, &resp); err != nil {
		t.Fatalf("parse submission response: %v", err)
	}
	if resp.Type != delivery.SubmissionType {
		t.Fatalf("response type = %q, want %q", resp.Type, delivery.SubmissionType)
	}
	return resp.Results
}

// receivedEnvelope is a small bag for the fetched-and-decrypted contents
// of a single envelope. raw retains the on-the-wire bytes so tests can
// run additional cryptographic checks (e.g. confirming that the server's
// domain key cannot decrypt the enclosure).
type receivedEnvelope struct {
	from    string
	subject string
	body    string
	raw     []byte
}

// fetchInbox opens a session as `identity`, sends SEMP_FETCH, and returns
// the decrypted contents of every envelope the server delivered.
func fetchInbox(t *testing.T, suite crypto.Suite, wsURL, seed, domain, identity string, serverStore *memstore.Store) []receivedEnvelope {
	t.Helper()

	store := newClientStore(t, seed, domain, identity, serverStore)
	wsTransport := ws.NewWithConfig(ws.Config{AllowInsecure: true})
	dialCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := wsTransport.Dial(dialCtx, wsURL)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	identityFP := keys.Compute(mustIdentityPub(seed, identity))
	cli := handshake.NewClient(handshake.ClientConfig{
		Suite:         suite,
		Store:         store,
		Identity:      identity,
		IdentityKeyID: identityFP,
		ServerDomain:  domain,
	})
	defer cli.Erase()
	hsCtx, hsCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer hsCancel()
	if _, err := handshake.RunClient(hsCtx, conn, cli); err != nil {
		t.Fatalf("RunClient: %v", err)
	}

	myEncPub, myEncPriv, err := demoseed.Encryption(seed, identity)
	if err != nil {
		t.Fatalf("derive own encryption: %v", err)
	}
	myEncFP := keys.Compute(myEncPub)

	req, _ := json.Marshal(delivery.NewFetchRequest())
	if err := conn.Send(hsCtx, req); err != nil {
		t.Fatalf("send fetch request: %v", err)
	}
	respRaw, err := conn.Recv(hsCtx)
	if err != nil {
		t.Fatalf("recv fetch response: %v", err)
	}
	var resp delivery.FetchResponse
	if err := json.Unmarshal(respRaw, &resp); err != nil {
		t.Fatalf("parse fetch response: %v", err)
	}

	out := make([]receivedEnvelope, 0, len(resp.Envelopes))
	for i, b64 := range resp.Envelopes {
		raw, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			t.Fatalf("envelope %d base64: %v", i, err)
		}
		env, err := envelope.Decode(raw)
		if err != nil {
			t.Fatalf("envelope %d decode: %v", i, err)
		}
		bf, err := envelope.OpenBrief(env, suite, myEncFP, myEncPriv)
		if err != nil {
			t.Fatalf("envelope %d OpenBrief: %v", i, err)
		}
		enc, err := envelope.OpenEnclosure(env, suite, myEncFP, myEncPriv)
		if err != nil {
			t.Fatalf("envelope %d OpenEnclosure: %v", i, err)
		}
		out = append(out, receivedEnvelope{
			from:    string(bf.From),
			subject: enc.Subject,
			body:    enc.Body["text/plain"],
			raw:     raw,
		})
	}
	return out
}

// newClientStore builds an in-memory store for a single client process,
// pre-loaded with the client's identity keypair, the server's signing
// key, and the server's published encryption key for the user (which the
// handshake doesn't strictly need but lets the helper be reused for both
// send and receive paths).
func newClientStore(t *testing.T, seed, domain, identity string, serverStore *memstore.Store) *memstore.Store {
	t.Helper()
	store := memstore.New()
	identityPub, identityPriv := demoseed.Identity(seed, identity)
	identityFP := store.PutUserKey(identity, keys.TypeIdentity, "ed25519", identityPub)
	store.PutPrivateKey(identityFP, identityPriv)

	// Look up the server's published domain signing key from the
	// shared store and copy it locally.
	rec, err := serverStore.LookupDomainKey(context.Background(), domain)
	if err != nil || rec == nil {
		t.Fatalf("server store has no domain key for %s: %v", domain, err)
	}
	pub, err := base64.StdEncoding.DecodeString(rec.PublicKey)
	if err != nil {
		t.Fatalf("decode server domain key: %v", err)
	}
	store.PutDomainKey(domain, pub)
	return store
}

func mustIdentityPub(seed, identity string) []byte {
	pub, _ := demoseed.Identity(seed, identity)
	return []byte(pub)
}

func domainOf(address string) string {
	at := strings.LastIndexByte(address, '@')
	if at < 0 {
		return ""
	}
	return address[at+1:]
}
