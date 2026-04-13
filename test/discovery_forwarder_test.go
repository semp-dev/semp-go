package test

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	semp "semp.dev/semp-go"
	"semp.dev/semp-go/crypto"
	"semp.dev/semp-go/delivery/inboxd"
	"semp.dev/semp-go/discovery"
	"semp.dev/semp-go/internal/demoseed"
)

// fakeDNS is a minimal discovery.DNSLookup for tests that only need
// domain→MX or domain→SRV answers driven by in-memory tables.
type fakeDNS struct {
	srv map[string][]*net.SRV
	mx  map[string][]*net.MX
	txt map[string][]string
}

func (f *fakeDNS) LookupSRV(_ context.Context, _, _, name string) (string, []*net.SRV, error) {
	return "", f.srv[name], nil
}
func (f *fakeDNS) LookupTXT(_ context.Context, name string) ([]string, error) {
	return f.txt[name], nil
}
func (f *fakeDNS) LookupMX(_ context.Context, name string) ([]*net.MX, error) {
	return f.mx[name], nil
}

// TestForwarderResolvesPeerViaDiscovery stands up two in-process
// federation servers and drives a cross-domain envelope forward where
// Server A's Forwarder has NO static endpoint for Server B. The
// Forwarder's Resolver walks the well-known URI path of the discovery
// flow, extracts the federation endpoint via a custom
// FederationEndpointFunc, and opens a federation session that
// successfully delivers an envelope into bob's inbox on Server B.
//
// This pins the milestone-3z behavior: the demo binaries no longer
// need a static -peers entry per destination; a Resolver + signing
// key is sufficient.
func TestForwarderResolvesPeerViaDiscovery(t *testing.T) {
	const (
		seed    = "test-discovery-forwarder"
		domainA = "a.example"
		domainB = "b.example"
		alice   = "alice@a.example"
		bob     = "bob@b.example"
	)
	suite := crypto.SuiteBaseline

	// Bring up servers with the standard fixture. Both have their
	// /v1/federate endpoint wired up via httptest, but we will
	// disable the direct -peers wiring on srvA and rely on
	// discovery instead.
	srvB := bringUpServer(t, seed, domainB, []string{bob})
	defer srvB.close()
	srvA := bringUpServer(t, seed, domainA, []string{alice})
	defer srvA.close()

	// Cross-publish each domain's signing key so federation
	// handshake signatures verify on both sides. This mirrors
	// what a production operator with a pinned key list would do.
	peerPubA, _ := demoseed.DomainSigning(seed, domainA)
	peerPubB, _ := demoseed.DomainSigning(seed, domainB)
	srvA.store.PutDomainKey(domainB, peerPubB)
	srvB.store.PutDomainKey(domainA, peerPubA)

	// Register b.example in srvA's PeerRegistry with a signing key
	// but NO endpoint. The Forwarder will have to resolve the
	// endpoint via the Resolver.
	srvA.peers.Put(inboxd.PeerConfig{
		Domain:           domainB,
		DomainSigningKey: peerPubB,
		// Endpoint intentionally left empty.
	})

	// Stand up a well-known URI HTTP server that returns a
	// Configuration pointing at srvB's federation endpoint.
	wkMux := http.NewServeMux()
	wkMux.HandleFunc(discovery.WellKnownPath, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(discovery.Configuration{
			Version: "1.0.0",
			Domain:  domainB,
			Endpoints: discovery.ConfigEndpoints{
				Client:     map[string]string{"ws": srvB.federateURL},
				Federation: map[string]string{"ws": srvB.federateURL},
				Register:   "http://localhost/v1/register",
				Keys:       "http://localhost/.well-known/semp/keys/",
				DomainKeys: "http://localhost/.well-known/semp/domain-keys",
			},
			Suites: []string{"x25519-chacha20-poly1305"},
			Limits: discovery.ConfigLimits{MaxEnvelopeSize: 26214400},
		})
	})
	wkServer := httptest.NewServer(wkMux)
	defer wkServer.Close()

	// Build a Resolver that routes any lookup for b.example to the
	// httptest well-known server and returns no DNS records
	// (forcing the fall-through to well-known URI).
	resolver := discovery.NewResolver(discovery.ResolverConfig{
		Cache: discovery.NewMemCache(),
		DNS:   &fakeDNS{},
		WellKnownURLFunc: func(domain string) string {
			if domain == domainB {
				return wkServer.URL + discovery.WellKnownPath
			}
			return "http://invalid.invalid" + discovery.WellKnownPath
		},
	})

	// Attach the Resolver to srvA's Forwarder. Also pass a
	// FederationEndpointFunc that returns the endpoint URL from
	// the configuration verbatim — the well-known URI already
	// publishes the federation-specific URL for this test.
	srvA.forwarder.Resolver = resolver
	srvA.forwarder.FederationEndpointFunc = func(result *discovery.Result) (string, error) {
		if result == nil || result.Configuration == nil {
			return "", nil
		}
		if ep, ok := result.Configuration.Endpoints.Federation["ws"]; ok {
				return ep, nil
			}
			if ep, ok := result.Configuration.Endpoints.Client["ws"]; ok {
				return ep, nil
			}
			return "", nil
	}

	// Also publish bob's encryption key in A's store so alice's
	// client can wrap K_brief for bob during composition. A real
	// sender would fetch this via SEMP_KEYS.
	bobEncPub, _, err := demoseed.Encryption(seed, bob)
	if err != nil {
		t.Fatalf("derive bob enc: %v", err)
	}
	srvA.store.PutUserKey(bob, "encryption", "x25519-chacha20-poly1305", bobEncPub)

	// Submit an envelope alice→bob. srvA's Forwarder will see an
	// empty-endpoint PeerConfig for b.example, consult the
	// Resolver, hit the httptest well-known URI, extract the
	// federation endpoint, open a session, and forward the
	// envelope.
	results := submitEnvelopeCrossDomain(t, suite, srvA, seed, domainA, alice, bob, "discovery-driven", "resolved via well-known URI")
	if len(results) != 1 {
		t.Fatalf("expected 1 submission result, got %d", len(results))
	}
	if results[0].Status != semp.StatusDelivered {
		t.Fatalf("submission status = %s, want delivered (reason=%s)",
			results[0].Status, results[0].Reason)
	}
	if results[0].Recipient != bob {
		t.Errorf("submission recipient = %s, want %s", results[0].Recipient, bob)
	}

	// Confirm the envelope landed in bob's inbox on Server B.
	if pending := srvB.inbox.Pending(bob); pending != 1 {
		t.Errorf("server B inbox pending = %d, want 1", pending)
	}

	// Confirm the Forwarder cached the resolved endpoint back into
	// the peer registry for next time.
	cachedPeer, ok := srvA.peers.Lookup(domainB)
	if !ok {
		t.Fatal("peer registry lost the resolved peer config")
	}
	if cachedPeer.Endpoint == "" {
		t.Error("resolved endpoint was not cached back into the registry")
	}
	if !strings.HasPrefix(cachedPeer.Endpoint, "ws://") && !strings.HasPrefix(cachedPeer.Endpoint, "wss://") {
		t.Errorf("cached endpoint = %q, want ws/wss scheme", cachedPeer.Endpoint)
	}
}

// TestForwarderFailsWithoutResolverOrEndpoint confirms that a peer
// with an empty Endpoint and no Resolver configured produces a clean
// error rather than a nil-pointer panic.
func TestForwarderFailsWithoutResolverOrEndpoint(t *testing.T) {
	const (
		seed    = "test-discovery-missing"
		domainA = "a.example"
		domainB = "b.example"
		alice   = "alice@a.example"
		bob     = "bob@b.example"
	)
	suite := crypto.SuiteBaseline

	srvA := bringUpServer(t, seed, domainA, []string{alice})
	defer srvA.close()

	peerPubB, _ := demoseed.DomainSigning(seed, domainB)
	srvA.peers.Put(inboxd.PeerConfig{
		Domain:           domainB,
		DomainSigningKey: peerPubB,
		// No Endpoint, and srvA.forwarder has no Resolver.
	})

	// Publish bob's encryption key so envelope composition works.
	bobEncPub, _, err := demoseed.Encryption(seed, bob)
	if err != nil {
		t.Fatalf("derive bob enc: %v", err)
	}
	srvA.store.PutUserKey(bob, "encryption", "x25519-chacha20-poly1305", bobEncPub)

	results := submitEnvelopeCrossDomain(t, suite, srvA, seed, domainA, alice, bob, "should fail", "no resolver")
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Status != semp.StatusRejected {
		t.Errorf("status = %s, want rejected", results[0].Status)
	}
	if !strings.Contains(strings.ToLower(results[0].Reason), "resolver") {
		t.Errorf("reason %q should mention the missing Resolver", results[0].Reason)
	}
}

// TestDefaultFederationEndpointFunc covers the default endpoint
// picker. The discovery.Result must carry a Configuration with a
// ws endpoint; otherwise the func returns an error.
func TestDefaultFederationEndpointFunc(t *testing.T) {
	// Happy path: federation ws endpoint present.
	result := &discovery.Result{
		Address: "example.com",
		Status:  semp.DiscoverySEMP,
		Configuration: &discovery.Configuration{
			Version: "1.0.0",
			Domain:  "example.com",
			Endpoints: discovery.ConfigEndpoints{
				Client:     map[string]string{"ws": "wss://semp.example.com/v1/ws"},
				Federation: map[string]string{"ws": "wss://semp.example.com/v1/federate"},
				Register:   "https://semp.example.com/v1/register",
				Keys:       "https://semp.example.com/.well-known/semp/keys/",
				DomainKeys: "https://semp.example.com/.well-known/semp/domain-keys",
			},
			Suites: []string{"x25519-chacha20-poly1305"},
			Limits: discovery.ConfigLimits{MaxEnvelopeSize: 26214400},
		},
	}
	ep, err := inboxd.DefaultFederationEndpointFunc(result)
	if err != nil {
		t.Fatalf("DefaultFederationEndpointFunc: %v", err)
	}
	if ep != "wss://semp.example.com/v1/federate" {
		t.Errorf("endpoint = %q, want wss://semp.example.com/v1/federate", ep)
	}

	// No Configuration, but Server set: should fall back to h2.
	bare := &discovery.Result{Address: "example.com", Status: semp.DiscoverySEMP, Server: "semp.example.com"}
	ep, err = inboxd.DefaultFederationEndpointFunc(bare)
	if err != nil {
		t.Fatalf("DefaultFederationEndpointFunc with Server: %v", err)
	}
	if ep != "https://semp.example.com/v1/h2" {
		t.Errorf("endpoint = %q, want https://semp.example.com/v1/h2", ep)
	}

	// No Configuration and no Server: should error.
	empty := &discovery.Result{Address: "example.com", Status: semp.DiscoverySEMP}
	if _, err := inboxd.DefaultFederationEndpointFunc(empty); err == nil {
		t.Error("DefaultFederationEndpointFunc accepted a result with no endpoint")
	}

	// Nil input: should error.
	if _, err := inboxd.DefaultFederationEndpointFunc(nil); err == nil {
		t.Error("DefaultFederationEndpointFunc accepted a nil result")
	}
}
