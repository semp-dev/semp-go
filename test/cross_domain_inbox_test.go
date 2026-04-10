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

// TestCrossDomainInbox drives the full demo-binary cross-domain flow
// in-process:
//
//  1. Two httptest servers, one for a.example and one for b.example,
//     each serving /v1/ws (clients) and /v1/federate (peer servers).
//  2. Alice is pre-seeded on server A, bob on server B.
//  3. Server A is configured with b.example as a peer; its inboxd loop
//     is given a Forwarder that knows how to dial B's /v1/federate.
//  4. Alice connects to A, submits an envelope addressed to
//     bob@b.example. A's inboxd runs in ModeClient, signs the envelope,
//     and — because the recipient is not local — hands it off to the
//     Forwarder. The Forwarder runs the federation handshake to B,
//     re-binds seal.session_mac under the federation session's K_env_mac
//     (without touching seal.signature), and ships the envelope over.
//  5. Server B's federation endpoint runs inboxd in ModeFederation,
//     verifies the sender domain signature against A's published key,
//     verifies the session MAC against its own K_env_mac, unwraps the
//     brief, and stores the envelope in bob's inbox.
//  6. A's response to alice is synthesized from B's SubmissionResponse.
//  7. Bob connects to B's /v1/ws, runs SEMP_FETCH, and decrypts the
//     envelope. Subject and body must match.
//
// This is the milestone-3j acceptance test. Two independent servers,
// real WebSocket transports in both directions, a real federation
// handshake between them, and an envelope that flows from one user on
// one domain all the way to another user on another domain.
func TestCrossDomainInbox(t *testing.T) {
	const (
		seed    = "test-seed-3j-do-not-use-elsewhere"
		domainA = "a.example"
		domainB = "b.example"
		alice   = "alice@a.example"
		bob     = "bob@b.example"
	)
	suite := crypto.SuiteBaseline

	// Bring up server B first so we have its endpoint URL to give to
	// server A's forwarder.
	srvB := bringUpServer(t, seed, domainB, []string{bob})
	defer srvB.close()

	srvA := bringUpServer(t, seed, domainA, []string{alice})
	defer srvA.close()

	// Wire up A's forwarder to know about B.
	peerPubB, _ := demoseed.DomainSigning(seed, domainB)
	srvA.peers.Put(inboxd.PeerConfig{
		Domain:           domainB,
		Endpoint:         srvB.federateURL,
		DomainSigningKey: peerPubB,
	})

	// Publish each server's domain signing key in the other's store
	// so their federation responders can verify inbound handshakes.
	// In a real deployment this would come from discovery; for the
	// demo both sides know each other's public keys because they're
	// derived from the same seed.
	peerPubA, _ := demoseed.DomainSigning(seed, domainA)
	srvB.store.PutDomainKey(domainA, peerPubA)
	srvA.store.PutDomainKey(domainB, peerPubB)

	// Also register bob's encryption public key in A's store so alice's
	// client can wrap K_brief and K_enclosure for him. A real sender
	// would fetch this via SEMP_KEYS; in the demo we derive it from
	// the shared seed.
	bobEncPub, _, err := demoseed.Encryption(seed, bob)
	if err != nil {
		t.Fatalf("derive bob encryption: %v", err)
	}
	srvA.store.PutUserKey(bob, keys.TypeEncryption, "x25519-chacha20-poly1305", bobEncPub)

	// --- Alice submits the envelope to A.
	const subject = "x-domain greetings"
	const body = "one semp-server to another, via a real federation handshake."

	results := submitEnvelopeCrossDomain(t, suite, srvA, seed, domainA, alice, bob, subject, body)
	if len(results) != 1 {
		t.Fatalf("expected 1 submission result, got %d", len(results))
	}
	if results[0].Status != semp.StatusDelivered {
		t.Fatalf("submission status = %s, want delivered (reason=%s)", results[0].Status, results[0].Reason)
	}
	if results[0].Recipient != bob {
		t.Errorf("submission recipient = %s, want %s", results[0].Recipient, bob)
	}

	// --- B's inbox should now contain exactly one envelope for bob.
	if got := srvB.inbox.Pending(bob); got != 1 {
		t.Errorf("server B inbox pending for bob = %d, want 1", got)
	}

	// --- Bob fetches from server B.
	envelopes := fetchInboxCrossDomain(t, suite, srvB, seed, domainB, bob)
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

	// --- The domain signature on the delivered envelope MUST verify
	// against server A's public signing key. This is the whole point
	// of rebinding session_mac without re-signing: B's signature
	// verification uses A's key, not its own.
	senderPub, _ := demoseed.DomainSigning(seed, domainA)
	deliveredEnv, err := envelope.Decode(got.raw)
	if err != nil {
		t.Fatalf("decode delivered envelope: %v", err)
	}
	if err := envelope.VerifySignature(deliveredEnv, suite, senderPub); err != nil {
		t.Errorf("delivered envelope signature does not verify against A's domain key: %v", err)
	}

	// --- Bob's inbox should be empty after the fetch.
	if got := srvB.inbox.Pending(bob); got != 0 {
		t.Errorf("server B inbox pending after fetch = %d, want 0", got)
	}
}

// testServer bundles all the state a running in-process semp-server
// instance needs, along with the URLs tests use to talk to it.
type testServer struct {
	domain       string
	store        *memstore.Store
	inbox        *delivery.Inbox
	peers        *inboxd.PeerRegistry
	forwarder    *inboxd.Forwarder
	wsURL        string // /v1/ws (client endpoint)
	federateURL  string // /v1/federate (peer endpoint)
	httpSrv      *httptest.Server
	wgHandlers   *sync.WaitGroup
	closeOnce    sync.Once
	domainSignFP keys.Fingerprint
	domainEncFP  keys.Fingerprint
}

func (s *testServer) close() {
	s.closeOnce.Do(func() {
		// Close outbound federation sessions first. This causes our
		// peers' Serve loops to see EOF and exit, so their
		// handler goroutines return, so httpSrv.Close unblocks.
		if s.forwarder != nil {
			s.forwarder.Close()
		}
		s.httpSrv.Close()
		s.wgHandlers.Wait()
	})
}

// bringUpServer stands up a single in-process semp-server at an
// ephemeral httptest address.
func bringUpServer(t *testing.T, seed, domain string, users []string) *testServer {
	t.Helper()
	suite := crypto.SuiteBaseline
	store := memstore.New()
	inbox := delivery.NewInbox()

	domainSignPub, domainSignPriv := demoseed.DomainSigning(seed, domain)
	domainSignFP := store.PutDomainKey(domain, domainSignPub)

	domainEncPub, domainEncPriv, err := demoseed.DomainEncryption(seed, domain)
	if err != nil {
		t.Fatalf("derive domain encryption: %v", err)
	}
	domainEncFP := store.PutDomainEncryptionKey(domain, domainEncPub)

	for _, u := range users {
		identityPub, _ := demoseed.Identity(seed, u)
		store.PutUserKey(u, keys.TypeIdentity, "ed25519", identityPub)

		encPub, _, err := demoseed.Encryption(seed, u)
		if err != nil {
			t.Fatalf("derive encryption: %v", err)
		}
		store.PutUserKey(u, keys.TypeEncryption, "x25519-chacha20-poly1305", encPub)
	}

	wsTransport := ws.NewWithConfig(ws.Config{
		AllowInsecure:  true,
		OriginPatterns: []string{"*"},
	})
	peers := inboxd.NewPeerRegistry()
	forwarder := inboxd.NewForwarder(inboxd.ForwarderConfig{
		Suite:                 suite,
		LocalDomain:           domain,
		LocalDomainKeyID:      domainSignFP,
		LocalDomainPrivateKey: domainSignPriv,
		Peers:                 peers,
		Dial: func(ctx context.Context, endpoint string) (transport.Conn, error) {
			return wsTransport.Dial(ctx, endpoint)
		},
		Store: store,
	})

	silent := log.New(io.Discard, "", 0)
	var wg sync.WaitGroup

	mux := http.NewServeMux()
	mux.Handle("/v1/ws", ws.NewHandler(ws.Config{
		AllowInsecure:  true,
		OriginPatterns: []string{"*"},
	}, func(conn transport.Conn) {
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
			hsCtx, hsCancel := context.WithTimeout(context.Background(), 10*time.Second)
			sess, err := handshake.RunServer(hsCtx, conn, srv)
			hsCancel()
			if err != nil {
				return
			}
			ctx := context.Background()
			loop := &inboxd.Server{
				Mode:           inboxd.ModeClient,
				Suite:          suite,
				Store:          store,
				Inbox:          inbox,
				Forwarder:      forwarder,
				LocalDomain:    domain,
				DomainSignFP:   domainSignFP,
				DomainSignPriv: domainSignPriv,
				DomainEncFP:    domainEncFP,
				DomainEncPriv:  domainEncPriv,
				Identity:       srv.ClientIdentity(),
				DeviceKeyID:    srv.ClientDeviceKeyID(),
				Session:        sess,
				Logger:         silent,
			}
			_ = loop.Serve(ctx, conn)
		}()
	}))
	mux.Handle("/v1/federate", ws.NewHandler(ws.Config{
		AllowInsecure:  true,
		OriginPatterns: []string{"*"},
	}, func(conn transport.Conn) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer conn.Close()
			resp := handshake.NewResponder(handshake.ResponderConfig{
				Suite:                 suite,
				Store:                 store,
				Verifier:              handshake.TrustingDomainVerifier{},
				LocalDomain:           domain,
				LocalDomainKeyID:      domainSignFP,
				LocalDomainPrivateKey: domainSignPriv,
				Policy: handshake.FederationPolicy{
					MessageRetention: "7d",
					UserDiscovery:    "allowed",
					RelayAllowed:     true,
				},
				SessionTTL: 3600,
			})
			defer resp.Erase()
			hsCtx, hsCancel := context.WithTimeout(context.Background(), 10*time.Second)
			sess, err := handshake.RunResponder(hsCtx, conn, resp)
			hsCancel()
			if err != nil {
				return
			}
			ctx := context.Background()
			loop := &inboxd.Server{
				Mode:           inboxd.ModeFederation,
				Suite:          suite,
				Store:          store,
				Inbox:          inbox,
				LocalDomain:    domain,
				DomainSignFP:   domainSignFP,
				DomainSignPriv: domainSignPriv,
				DomainEncFP:    domainEncFP,
				DomainEncPriv:  domainEncPriv,
				Identity:       resp.PeerDomain(),
				Session:        sess,
				Logger:         silent,
			}
			_ = loop.Serve(ctx, conn)
		}()
	}))
	httpSrv := httptest.NewServer(mux)

	return &testServer{
		domain:       domain,
		store:        store,
		inbox:        inbox,
		peers:        peers,
		forwarder:    forwarder,
		wsURL:        "ws://" + strings.TrimPrefix(httpSrv.URL, "http://") + "/v1/ws",
		federateURL:  "ws://" + strings.TrimPrefix(httpSrv.URL, "http://") + "/v1/federate",
		httpSrv:      httpSrv,
		wgHandlers:   &wg,
		domainSignFP: domainSignFP,
		domainEncFP:  domainEncFP,
	}
}

// submitEnvelopeCrossDomain opens a client session to srvA as `from`,
// composes an envelope for `to` (on a different domain), submits it,
// and returns the parsed SubmissionResults.
func submitEnvelopeCrossDomain(t *testing.T, suite crypto.Suite, srvA *testServer, seed, senderDomain, from, to, subject, body string) []delivery.SubmissionResult {
	t.Helper()

	store := newClientStore(t, seed, senderDomain, from, srvA.store)

	wsTransport := ws.NewWithConfig(ws.Config{AllowInsecure: true})
	dialCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := wsTransport.Dial(dialCtx, srvA.wsURL)
	if err != nil {
		t.Fatalf("dial A: %v", err)
	}
	defer conn.Close()

	identityFP := keys.Compute(mustIdentityPub(seed, from))
	cli := handshake.NewClient(handshake.ClientConfig{
		Suite:         suite,
		Store:         store,
		Identity:      from,
		IdentityKeyID: identityFP,
		ServerDomain:  senderDomain,
	})
	defer cli.Erase()

	hsCtx, hsCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer hsCancel()
	sess, err := handshake.RunClient(hsCtx, conn, cli)
	if err != nil {
		t.Fatalf("RunClient: %v", err)
	}

	// Recipient's encryption public key (derived from the shared seed;
	// a real sender would fetch this via SEMP_KEYS).
	recipEncPub, _, err := demoseed.Encryption(seed, to)
	if err != nil {
		t.Fatalf("derive recipient encryption: %v", err)
	}
	recipEncFP := keys.Compute(recipEncPub)

	// Sender's home server domain encryption key. A needs this to
	// unwrap K_brief so it can route the envelope locally and decide
	// whether to forward. Per ENVELOPE.md §4.4.
	senderServerEncPub, _, err := demoseed.DomainEncryption(seed, senderDomain)
	if err != nil {
		t.Fatalf("derive sender server encryption: %v", err)
	}
	senderServerEncFP := keys.Compute(senderServerEncPub)

	// Recipient's home server domain encryption key. B needs this to
	// unwrap K_brief so it can deliver the envelope into bob's inbox.
	// Per ENVELOPE.md §4.4, senders MUST fetch the recipient server's
	// domain key at send time in addition to the recipient client key.
	recipServerEncPub, _, err := demoseed.DomainEncryption(seed, domainOf(to))
	if err != nil {
		t.Fatalf("derive recipient server encryption: %v", err)
	}
	recipServerEncFP := keys.Compute(recipServerEncPub)

	in := &envelope.ComposeInput{
		Suite: suite,
		Postmark: envelope.Postmark{
			ID:         "01JTESTXDOMAINPOSTMARK00000001",
			SessionID:  sess.ID,
			FromDomain: senderDomain,
			ToDomain:   domainOf(to),
			Expires:    time.Now().UTC().Add(time.Hour),
		},
		Brief: brief.Brief{
			MessageID: "01JTESTXDOMAINMESSAGE000000001",
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
			{Fingerprint: senderServerEncFP, PublicKey: senderServerEncPub},
			{Fingerprint: recipServerEncFP, PublicKey: recipServerEncPub},
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
		t.Fatalf("response type = %q", resp.Type)
	}
	return resp.Results
}

// fetchInboxCrossDomain opens a session to srvB as `identity`, runs
// SEMP_FETCH, and returns the decrypted envelopes.
func fetchInboxCrossDomain(t *testing.T, suite crypto.Suite, srvB *testServer, seed, recipDomain, identity string) []receivedEnvelope {
	t.Helper()
	store := newClientStore(t, seed, recipDomain, identity, srvB.store)
	wsTransport := ws.NewWithConfig(ws.Config{AllowInsecure: true})
	dialCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := wsTransport.Dial(dialCtx, srvB.wsURL)
	if err != nil {
		t.Fatalf("dial B: %v", err)
	}
	defer conn.Close()

	identityFP := keys.Compute(mustIdentityPub(seed, identity))
	cli := handshake.NewClient(handshake.ClientConfig{
		Suite:         suite,
		Store:         store,
		Identity:      identity,
		IdentityKeyID: identityFP,
		ServerDomain:  recipDomain,
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
		t.Fatalf("send fetch: %v", err)
	}
	respRaw, err := conn.Recv(hsCtx)
	if err != nil {
		t.Fatalf("recv fetch: %v", err)
	}
	var resp delivery.FetchResponse
	if err := json.Unmarshal(respRaw, &resp); err != nil {
		t.Fatalf("parse fetch: %v", err)
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
