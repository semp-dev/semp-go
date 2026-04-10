package test

import (
	"context"
	"testing"
	"time"

	"github.com/semp-dev/semp-go/crypto"
	"github.com/semp-dev/semp-go/delivery/inboxd"
	"github.com/semp-dev/semp-go/handshake"
	"github.com/semp-dev/semp-go/internal/demoseed"
	"github.com/semp-dev/semp-go/keys"
	"github.com/semp-dev/semp-go/transport/ws"
)

// TestSEMPKeysLocalFetch drives a single-domain SEMP_KEYS lookup end to
// end: alice opens a session with her home server, issues a SEMP_KEYS
// request for bob (on the same domain), and verifies the response
// carries bob's encryption key AND the server's domain encryption key
// under include_domain_keys. This is the happy path for CLIENT.md §5.4
// when both sender and recipient live on the same home server.
func TestSEMPKeysLocalFetch(t *testing.T) {
	const (
		seed   = "test-keys-local"
		domain = "example.com"
		alice  = "alice@example.com"
		bob    = "bob@example.com"
	)
	suite := crypto.SuiteBaseline

	srv := bringUpServer(t, seed, domain, []string{alice, bob})
	defer srv.close()

	// Dial /v1/ws and run the handshake as alice.
	wsTransport := ws.NewWithConfig(ws.Config{AllowInsecure: true})
	dialCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := wsTransport.Dial(dialCtx, srv.wsURL)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	store := newClientStore(t, seed, domain, alice, srv.store)
	identityFP := keys.Compute(mustIdentityPub(seed, alice))
	cli := handshake.NewClient(handshake.ClientConfig{
		Suite:         suite,
		Store:         store,
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

	// Send SEMP_KEYS for bob.
	fetcher := keys.NewFetcher(conn)
	req := keys.NewRequest("test-req-1", []string{bob})
	resp, err := fetcher.FetchKeys(hsCtx, req)
	if err != nil {
		t.Fatalf("FetchKeys: %v", err)
	}
	if len(resp.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(resp.Results))
	}
	result := resp.Results[0]
	if result.Address != bob {
		t.Errorf("result address = %s, want %s", result.Address, bob)
	}
	if result.Status != keys.StatusFound {
		t.Fatalf("result status = %s, want %s", result.Status, keys.StatusFound)
	}
	if result.Domain != domain {
		t.Errorf("result domain = %s, want %s", result.Domain, domain)
	}
	if result.DomainEncKey == nil {
		t.Error("DomainEncKey is nil; expected the server to include it when include_domain_keys is true")
	}
	// The encryption key we got back MUST match the one demoseed
	// would produce, since that's what the server published during
	// bringUpServer.
	wantEnc, _, err := demoseed.Encryption(seed, bob)
	if err != nil {
		t.Fatalf("derive expected encryption: %v", err)
	}
	wantEncFP := keys.Compute(wantEnc)
	var gotEncFP keys.Fingerprint
	for _, rec := range result.UserKeys {
		if rec.Type == keys.TypeEncryption {
			gotEncFP = rec.KeyID
			break
		}
	}
	if gotEncFP != wantEncFP {
		t.Errorf("encryption key fingerprint mismatch: got %s want %s", gotEncFP, wantEncFP)
	}
}

// TestSEMPKeysCrossDomainFetch drives a cross-domain SEMP_KEYS lookup
// end to end: alice is on server A, bob is on server B, and alice asks
// A for bob's keys. A forwards the request to B via its cached
// federation session and relays B's response back to alice.
//
// This exercises the full round trip: the handshake on /v1/ws, the
// SEMP_KEYS request, the federation handshake (lazy) between A and B,
// the SEMP_KEYS request over the federation session, B's local lookup,
// the federation response back to A, and A's response back to alice.
func TestSEMPKeysCrossDomainFetch(t *testing.T) {
	const (
		seed    = "test-keys-xdomain"
		domainA = "a.example"
		domainB = "b.example"
		alice   = "alice@a.example"
		bob     = "bob@b.example"
	)
	suite := crypto.SuiteBaseline

	srvB := bringUpServer(t, seed, domainB, []string{bob})
	defer srvB.close()
	srvA := bringUpServer(t, seed, domainA, []string{alice})
	defer srvA.close()

	// Register B as a peer of A, and publish each domain's signing
	// key in the other's store so the federation handshake can run.
	peerPubB, _ := demoseed.DomainSigning(seed, domainB)
	peerPubA, _ := demoseed.DomainSigning(seed, domainA)
	srvA.peers.Put(inboxd.PeerConfig{
		Domain:           domainB,
		Endpoint:         srvB.federateURL,
		DomainSigningKey: peerPubB,
	})
	srvA.store.PutDomainKey(domainB, peerPubB)
	srvB.store.PutDomainKey(domainA, peerPubA)

	// Dial A and run the handshake as alice.
	wsTransport := ws.NewWithConfig(ws.Config{AllowInsecure: true})
	dialCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := wsTransport.Dial(dialCtx, srvA.wsURL)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	store := newClientStore(t, seed, domainA, alice, srvA.store)
	identityFP := keys.Compute(mustIdentityPub(seed, alice))
	cli := handshake.NewClient(handshake.ClientConfig{
		Suite:         suite,
		Store:         store,
		Identity:      alice,
		IdentityKeyID: identityFP,
		ServerDomain:  domainA,
	})
	defer cli.Erase()
	hsCtx, hsCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer hsCancel()
	if _, err := handshake.RunClient(hsCtx, conn, cli); err != nil {
		t.Fatalf("RunClient: %v", err)
	}

	// Ask A for bob's keys. A should forward via its federation
	// session to B, which serves the lookup from its own store.
	fetcher := keys.NewFetcher(conn)
	req := keys.NewRequest("test-req-xd-1", []string{bob})
	resp, err := fetcher.FetchKeys(hsCtx, req)
	if err != nil {
		t.Fatalf("FetchKeys: %v", err)
	}
	if len(resp.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(resp.Results))
	}
	result := resp.Results[0]
	if result.Status != keys.StatusFound {
		t.Fatalf("result status = %s, want %s", result.Status, keys.StatusFound)
	}
	if result.Domain != domainB {
		t.Errorf("result domain = %s, want %s", result.Domain, domainB)
	}
	if result.DomainEncKey == nil {
		t.Error("expected cross-domain result to carry B's domain encryption key")
	}
	wantEnc, _, err := demoseed.Encryption(seed, bob)
	if err != nil {
		t.Fatalf("derive expected encryption: %v", err)
	}
	wantEncFP := keys.Compute(wantEnc)
	var gotEncFP keys.Fingerprint
	for _, rec := range result.UserKeys {
		if rec.Type == keys.TypeEncryption {
			gotEncFP = rec.KeyID
			break
		}
	}
	if gotEncFP != wantEncFP {
		t.Errorf("encryption key fingerprint mismatch: got %s want %s", gotEncFP, wantEncFP)
	}
}

// TestSEMPKeysNotFound confirms that a lookup for an unknown user on an
// unknown domain returns StatusNotFound (not StatusError) when the
// server has no forwarder and no local record.
func TestSEMPKeysNotFound(t *testing.T) {
	const (
		seed   = "test-keys-notfound"
		domain = "example.com"
		alice  = "alice@example.com"
	)
	suite := crypto.SuiteBaseline

	srv := bringUpServer(t, seed, domain, []string{alice})
	defer srv.close()

	wsTransport := ws.NewWithConfig(ws.Config{AllowInsecure: true})
	dialCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := wsTransport.Dial(dialCtx, srv.wsURL)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	store := newClientStore(t, seed, domain, alice, srv.store)
	identityFP := keys.Compute(mustIdentityPub(seed, alice))
	cli := handshake.NewClient(handshake.ClientConfig{
		Suite:         suite,
		Store:         store,
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

	// Local user that doesn't exist → StatusNotFound.
	fetcher := keys.NewFetcher(conn)
	req := keys.NewRequest("test-notfound-local", []string{"ghost@example.com"})
	resp, err := fetcher.FetchKeys(hsCtx, req)
	if err != nil {
		t.Fatalf("FetchKeys: %v", err)
	}
	if len(resp.Results) != 1 || resp.Results[0].Status != keys.StatusNotFound {
		t.Errorf("expected local not_found, got %+v", resp.Results)
	}

	// Unknown remote domain (server has no forwarder for it) →
	// StatusNotFound as well.
	req2 := keys.NewRequest("test-notfound-remote", []string{"ghost@unknown.example"})
	resp2, err := fetcher.FetchKeys(hsCtx, req2)
	if err != nil {
		t.Fatalf("FetchKeys: %v", err)
	}
	if len(resp2.Results) != 1 || resp2.Results[0].Status != keys.StatusNotFound {
		t.Errorf("expected remote not_found, got %+v", resp2.Results)
	}
}
