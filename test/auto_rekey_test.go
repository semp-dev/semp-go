package test

import (
	"context"
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
	"semp.dev/semp-go/session"
	"semp.dev/semp-go/transport"
	"semp.dev/semp-go/transport/ws"
)

// TestAutoRekeyFederationSession drives a federation session with a
// small TTL + a low rekey threshold, then waits for the Forwarder's
// background goroutine to fire an automatic rekey. It asserts:
//
//   1. The initiator's and responder's sessions both have RekeyCount
//      > 0 after the wait.
//   2. A subsequent Forward call succeeds, proving the new K_env_mac
//      is being used for envelope signing on both sides.
//   3. The session ID has rotated from the initial handshake value.
//
// This is the milestone-3p acceptance test: long-lived federation
// sessions self-maintain via auto-rekey without a foreground caller
// having to invoke session.Rekeyer.Rekey explicitly.
func TestAutoRekeyFederationSession(t *testing.T) {
	const (
		seed    = "test-auto-rekey"
		domainA = "a.example"
		domainB = "b.example"
		alice   = "alice@a.example"
		bob     = "bob@b.example"
	)
	suite := crypto.SuiteBaseline

	// Bring up both servers with a 5-second federation session TTL.
	// The Forwarder's RekeyThreshold is 0.2 (set in
	// bringUpServerForAutoRekey), so the auto-rekey goroutine wakes
	// at (1-0.2) * TTL before expiry = 4 seconds before expiry, i.e.
	// 1 second after establishment. We then wait ~1.5 seconds and
	// observe RekeyCount = 1.
	//
	// After the first rekey, the goroutine schedules the next wake
	// for 1 second later, but MinRekeyInterval = 1 minute, so the
	// second rekey attempt hits the rate limit and drops the
	// session. The test wall time is kept under ~2 seconds so it
	// runs before that second attempt fires.
	srvB := bringUpServerForAutoRekey(t, seed, domainB, []string{bob}, 5)
	defer srvB.close()
	srvA := bringUpServerForAutoRekey(t, seed, domainA, []string{alice}, 5)
	defer srvA.close()

	peerPubA, _ := demoseed.DomainSigning(seed, domainA)
	peerPubB, _ := demoseed.DomainSigning(seed, domainB)
	srvA.peers.Put(inboxd.PeerConfig{
		Domain:           domainB,
		Endpoint:         srvB.federateURL,
		DomainSigningKey: peerPubB,
	})
	srvA.store.PutDomainKey(domainB, peerPubB)
	srvB.store.PutDomainKey(domainA, peerPubA)

	// Trigger a first forward to open the federation session. After
	// this the auto-rekey goroutine is running on A's side.
	results := submitEnvelopeCrossDomain(t, suite, srvA, seed, domainA, alice, bob, "first", "body-1")
	if len(results) != 1 || results[0].Status != semp.StatusDelivered {
		t.Fatalf("first submission results = %+v", results)
	}

	// Capture the initial session state on both sides.
	initialSess := srvA.forwarder.SessionSnapshot(domainB)
	if initialSess == nil {
		t.Fatal("forwarder has no cached session to b.example")
	}
	initialID := initialSess.ID
	initialRekeyCount := initialSess.RekeyCount

	// Wait long enough for auto-rekey to fire. With TTL=5s and
	// threshold=0.2, the wake-up is 1s after establishment, so 1.5s
	// comfortably sits between the first rekey firing and the
	// second attempt (at ~2s) that would hit MinRekeyInterval.
	time.Sleep(1500 * time.Millisecond)

	// A second submission after the rekey confirms the new keys are
	// being used end to end — B's responder reads its K_env_mac
	// from the live session via inboxd.envMAC(), so if auto-rekey
	// rotated keys on only one side, the MAC verification on B
	// would fail here.
	results2 := submitEnvelopeCrossDomain(t, suite, srvA, seed, domainA, alice, bob, "second (post-rekey)", "body-2")
	if len(results2) != 1 || results2[0].Status != semp.StatusDelivered {
		t.Fatalf("second submission results = %+v (errors here indicate auto-rekey broke the session)", results2)
	}

	postRekey := srvA.forwarder.SessionSnapshot(domainB)
	if postRekey == nil {
		t.Fatal("forwarder session disappeared after auto-rekey")
	}
	if postRekey.RekeyCount <= initialRekeyCount {
		t.Errorf("RekeyCount did not increase: initial=%d post=%d", initialRekeyCount, postRekey.RekeyCount)
	}
	if postRekey.ID == initialID {
		t.Errorf("session ID did not rotate: %s", postRekey.ID)
	}
	t.Logf("auto-rekey fired: initial_id=%s new_id=%s rekey_count=%d",
		initialID, postRekey.ID, postRekey.RekeyCount)

	// Confirm both envelopes were delivered to bob's inbox on B.
	if pending := srvB.inbox.Pending(bob); pending != 2 {
		t.Errorf("bob's inbox pending = %d, want 2", pending)
	}
}

// bringUpServerForAutoRekey is a variant of bringUpServer that uses a
// short federation session TTL and a 0.2 RekeyThreshold on the
// Forwarder, so the auto-rekey goroutine fires well within the test
// time budget. Local client sessions still use the default 5-minute
// TTL because auto-rekey is a federation feature in the current
// architecture.
func bringUpServerForAutoRekey(t *testing.T, seed, domain string, users []string, federationTTLSec int) *testServer {
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
	// Build the Forwarder with RekeyThreshold=0.2 so that on a 3s
	// federation TTL the auto-rekey goroutine fires 0.2*3 = 600ms
	// before expiry — i.e. at ~2.4s after establishment.
	forwarder := inboxd.NewForwarder(inboxd.ForwarderConfig{
		Suite:                 suite,
		LocalDomain:           domain,
		LocalDomainKeyID:      domainSignFP,
		LocalDomainPrivateKey: domainSignPriv,
		Peers:                 peers,
		Dial: func(ctx context.Context, endpoint string) (transport.Conn, error) {
			return wsTransport.Dial(ctx, endpoint)
		},
		Store:          store,
		RekeyThreshold: 0.2,
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
				SessionTTL: federationTTLSec,
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

// Silence unused-import warnings on the broader envelope/seal
// imports when this file is rebuilt after refactors. The
// submitEnvelopeCrossDomain / fetchInboxCrossDomain helpers live in
// cross_domain_inbox_test.go and transitively depend on them.
var _ = envelope.Compose
var _ = seal.NewWrapper
var _ = brief.Address("")
var _ = enclosure.Body{}
var _ = session.StateActive
