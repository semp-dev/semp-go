package discovery_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	semp "semp.dev/semp-go"
	"semp.dev/semp-go/crypto"
	"semp.dev/semp-go/discovery"
	"semp.dev/semp-go/keys"
)

// TestParseTXTCapabilities covers the happy path plus the
// extensibility rule: unknown parameters are kept, not rejected.
func TestParseTXTCapabilities(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
		check   func(t *testing.T, c *discovery.TXTCapabilities)
	}{
		{
			name:  "full capability record",
			input: "v=semp1;pq=ready;c=ws,h2,quic;f=groups,threads,reactions",
			check: func(t *testing.T, c *discovery.TXTCapabilities) {
				if c.Version != "semp1" {
					t.Errorf("Version = %q, want semp1", c.Version)
				}
				if c.PostQuantum != "ready" {
					t.Errorf("PostQuantum = %q, want ready", c.PostQuantum)
				}
				if got := strings.Join(c.Transports, ","); got != "ws,h2,quic" {
					t.Errorf("Transports = %q, want ws,h2,quic", got)
				}
				if got := strings.Join(c.Features, ","); got != "groups,threads,reactions" {
					t.Errorf("Features = %q, want groups,threads,reactions", got)
				}
			},
		},
		{
			name:  "minimal record",
			input: "v=semp1",
			check: func(t *testing.T, c *discovery.TXTCapabilities) {
				if c.Version != "semp1" {
					t.Errorf("Version = %q, want semp1", c.Version)
				}
				if len(c.Transports) != 0 {
					t.Errorf("Transports should be empty, got %v", c.Transports)
				}
			},
		},
		{
			name:  "unknown parameters preserved",
			input: "v=semp1;custom=foo;another=bar",
			check: func(t *testing.T, c *discovery.TXTCapabilities) {
				if c.Unknown["custom"] != "foo" {
					t.Errorf("Unknown[custom] = %q, want foo", c.Unknown["custom"])
				}
				if c.Unknown["another"] != "bar" {
					t.Errorf("Unknown[another] = %q, want bar", c.Unknown["another"])
				}
			},
		},
		{
			name:  "auth methods comma list",
			input: "v=semp1;auth=identity_key,token,mfa",
			check: func(t *testing.T, c *discovery.TXTCapabilities) {
				if len(c.AuthMethods) != 3 {
					t.Errorf("AuthMethods count = %d, want 3", len(c.AuthMethods))
				}
			},
		},
		{
			name:    "missing version",
			input:   "pq=ready;c=ws",
			wantErr: true,
		},
		{
			name:    "wrong version",
			input:   "v=semp2",
			wantErr: true,
		},
		{
			name:    "empty",
			input:   "",
			wantErr: true,
		},
		{
			name:  "whitespace around values is trimmed",
			input: " v=semp1 ; pq = ready ; c = ws , h2 ",
			check: func(t *testing.T, c *discovery.TXTCapabilities) {
				if c.Version != "semp1" {
					t.Errorf("Version = %q, want semp1 (whitespace-tolerant parse)", c.Version)
				}
				if got := strings.Join(c.Transports, ","); got != "ws,h2" {
					t.Errorf("Transports = %q, want ws,h2", got)
				}
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := discovery.ParseTXTCapabilities(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.check != nil {
				tc.check(t, got)
			}
		})
	}
}

// TestMemCacheTTL exercises Get / Put / Invalidate semantics,
// including expiration. Uses a monotonic sleep between Put and the
// second Get to let the TTL elapse.
func TestMemCacheTTL(t *testing.T) {
	cache := discovery.NewMemCache()
	ctx := context.Background()

	// Empty cache.
	if _, ok := cache.Get(ctx, "alice@example.com"); ok {
		t.Error("empty cache returned a hit")
	}

	// Put + immediate Get.
	result := &discovery.Result{Address: "alice@example.com", Status: semp.DiscoverySEMP, TTL: 1}
	if err := cache.Put(ctx, "alice@example.com", result, 50*time.Millisecond); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, ok := cache.Get(ctx, "alice@example.com")
	if !ok {
		t.Fatal("Get returned no hit immediately after Put")
	}
	if got.Status != semp.DiscoverySEMP {
		t.Errorf("Status = %s, want semp", got.Status)
	}

	// Case-insensitive key.
	if _, ok := cache.Get(ctx, "ALICE@EXAMPLE.COM"); !ok {
		t.Error("cache should be case-insensitive")
	}

	// Mutation of the returned copy must not affect the cached entry.
	got.Status = semp.DiscoveryNotFound
	re, _ := cache.Get(ctx, "alice@example.com")
	if re.Status != semp.DiscoverySEMP {
		t.Errorf("mutating returned copy leaked into cache: status = %s", re.Status)
	}

	// Invalidate.
	if err := cache.Invalidate(ctx, "alice@example.com"); err != nil {
		t.Fatalf("Invalidate: %v", err)
	}
	if _, ok := cache.Get(ctx, "alice@example.com"); ok {
		t.Error("Invalidate did not remove the entry")
	}

	// TTL expiration.
	if err := cache.Put(ctx, "bob@example.com", result, 10*time.Millisecond); err != nil {
		t.Fatalf("Put: %v", err)
	}
	time.Sleep(25 * time.Millisecond)
	if _, ok := cache.Get(ctx, "bob@example.com"); ok {
		t.Error("Get returned an expired entry")
	}
}

// fakeDNS is a tiny DNSLookup mock used by resolver tests. Only the
// methods referenced by the test are populated.
type fakeDNS struct {
	srvRecords map[string][]*net.SRV
	txtRecords map[string][]string
	mxRecords  map[string][]*net.MX
	srvErr     map[string]error
	txtErr     map[string]error
	mxErr      map[string]error
}

func (f *fakeDNS) LookupSRV(_ context.Context, _, _, name string) (string, []*net.SRV, error) {
	// net.DefaultResolver uses "_semp._tcp." + name; our impl calls
	// with service="semp" proto="tcp" name=domain so we key by
	// domain here.
	if err, ok := f.srvErr[name]; ok {
		return "", nil, err
	}
	return "", f.srvRecords[name], nil
}

func (f *fakeDNS) LookupTXT(_ context.Context, name string) ([]string, error) {
	if err, ok := f.txtErr[name]; ok {
		return nil, err
	}
	return f.txtRecords[name], nil
}

func (f *fakeDNS) LookupMX(_ context.Context, name string) ([]*net.MX, error) {
	if err, ok := f.mxErr[name]; ok {
		return nil, err
	}
	return f.mxRecords[name], nil
}

// TestResolverDNSFirst drives the resolver with a mock DNS that
// advertises SEMP via SRV+TXT. The resolver should return semp
// without touching the well-known URL or MX.
func TestResolverDNSFirst(t *testing.T) {
	dns := &fakeDNS{
		srvRecords: map[string][]*net.SRV{
			"example.com": {{Target: "semp.example.com.", Port: 443, Priority: 10, Weight: 10}},
		},
		txtRecords: map[string][]string{
			"_semp._tcp.example.com": {"v=semp1;pq=ready;c=ws,h2;f=groups"},
		},
	}
	cache := discovery.NewMemCache()
	r := discovery.NewResolver(discovery.ResolverConfig{
		Cache: cache,
		DNS:   dns,
		WellKnownURLFunc: func(domain string) string {
			t.Errorf("well-known URL fetched for %s; DNS should have been sufficient", domain)
			return "http://invalid.invalid"
		},
	})
	result, err := r.Resolve(context.Background(), "alice@example.com")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if result.Status != semp.DiscoverySEMP {
		t.Errorf("Status = %s, want semp", result.Status)
	}
	if result.Server != "semp.example.com" {
		t.Errorf("Server = %s, want semp.example.com", result.Server)
	}
	if len(result.Transports) == 0 {
		t.Error("Transports should be populated from TXT capability record")
	}

	// Second call should hit the cache — confirm by nil-ing out the
	// DNS mock and checking we still get the cached hit.
	r2 := discovery.NewResolver(discovery.ResolverConfig{
		Cache: cache, // share cache from previous resolver
		DNS:   &fakeDNS{},
	})
	cached, err := r2.Resolve(context.Background(), "alice@example.com")
	if err != nil {
		t.Fatalf("cached Resolve: %v", err)
	}
	if cached.Server != "semp.example.com" {
		t.Errorf("cached Server = %s, want semp.example.com", cached.Server)
	}
}

// TestResolverWellKnownFallback confirms that when DNS returns no
// SEMP records, the resolver falls through to the well-known URI
// and returns status=semp based on its endpoints.
func TestResolverWellKnownFallback(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != discovery.WellKnownPath {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(discovery.Configuration{
			Version:     "1.0.0",
			Endpoints:   map[string]string{"ws": "wss://wk.example.com/v1/ws"},
			Features:    []string{"groups"},
			PostQuantum: "ready",
		})
	}))
	defer ts.Close()

	dns := &fakeDNS{} // no DNS records
	r := discovery.NewResolver(discovery.ResolverConfig{
		Cache:            discovery.NewMemCache(),
		DNS:              dns,
		WellKnownURLFunc: func(domain string) string { return ts.URL + discovery.WellKnownPath },
	})
	result, err := r.Resolve(context.Background(), "alice@example.com")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if result.Status != semp.DiscoverySEMP {
		t.Errorf("Status = %s, want semp", result.Status)
	}
	if result.Server != "wk.example.com" {
		t.Errorf("Server = %s, want wk.example.com", result.Server)
	}
	if len(result.Transports) == 0 {
		t.Error("Transports should come from well-known endpoints")
	}
}

// TestResolverMXFallback confirms that when BOTH DNS SEMP records and
// the well-known URI fail, the resolver consults MX records and
// returns status=legacy.
func TestResolverMXFallback(t *testing.T) {
	// httptest that always returns 404 — simulates a domain with no
	// well-known URI.
	ts := httptest.NewServer(http.NotFoundHandler())
	defer ts.Close()

	dns := &fakeDNS{
		mxRecords: map[string][]*net.MX{
			"example.com": {{Host: "mail.example.com.", Pref: 10}},
		},
	}
	r := discovery.NewResolver(discovery.ResolverConfig{
		Cache:            discovery.NewMemCache(),
		DNS:              dns,
		WellKnownURLFunc: func(domain string) string { return ts.URL + "/.well-known/semp/configuration" },
	})
	result, err := r.Resolve(context.Background(), "alice@example.com")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if result.Status != semp.DiscoveryLegacy {
		t.Errorf("Status = %s, want legacy", result.Status)
	}
	if result.Server != "mail.example.com" {
		t.Errorf("Server = %s, want mail.example.com", result.Server)
	}
}

// TestResolverNotFound confirms the terminal fall-through: no DNS,
// no well-known, no MX → not_found.
func TestResolverNotFound(t *testing.T) {
	ts := httptest.NewServer(http.NotFoundHandler())
	defer ts.Close()

	dns := &fakeDNS{
		// Explicit errors so Lookup* returns "not found" rather
		// than an empty slice (empty slice is a nil-error result
		// that the real net.Resolver would actually use).
		mxErr: map[string]error{"example.com": fmt.Errorf("NXDOMAIN")},
	}
	r := discovery.NewResolver(discovery.ResolverConfig{
		Cache:            discovery.NewMemCache(),
		DNS:              dns,
		WellKnownURLFunc: func(domain string) string { return ts.URL + "/.well-known/semp/configuration" },
	})
	result, err := r.Resolve(context.Background(), "alice@example.com")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if result.Status != semp.DiscoveryNotFound {
		t.Errorf("Status = %s, want not_found", result.Status)
	}
}

// TestFetchConfigurationRejectsBadContentType confirms that a 200
// response with a non-JSON Content-Type is rejected. Many HTTP
// caching proxies serve .well-known paths as text/html on errors;
// the resolver should not parse those as configurations.
func TestFetchConfigurationRejectsBadContentType(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html>nope</html>"))
	}))
	defer ts.Close()

	_, err := discovery.FetchConfigurationWith(context.Background(), http.DefaultClient, ts.URL)
	if err == nil {
		t.Error("FetchConfigurationWith accepted a text/html response")
	}
}

// TestSignResponseRoundTrip exercises SignResponse/VerifyResponse.
func TestSignResponseRoundTrip(t *testing.T) {
	suite := crypto.SuiteBaseline
	signer := suite.Signer()
	pub, priv, err := signer.GenerateKeyPair()
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	fp := keys.Compute(pub)

	resp := &discovery.Response{
		Type:      discovery.MessageType,
		Step:      discovery.StepResponse,
		Version:   "1.0.0",
		ID:        "test-req-1",
		Timestamp: time.Date(2026, 4, 10, 12, 0, 0, 0, time.UTC),
		Results: []discovery.Result{
			{
				Address: "alice@example.com",
				Status:  semp.DiscoverySEMP,
				Server:  "semp.example.com",
				TTL:     3600,
			},
		},
	}

	if err := discovery.SignResponse(signer, priv, fp, resp); err != nil {
		t.Fatalf("SignResponse: %v", err)
	}
	if resp.Signature.Value == "" {
		t.Fatal("Signature.Value not populated")
	}
	if resp.Signature.KeyID != fp {
		t.Errorf("Signature.KeyID = %s, want %s", resp.Signature.KeyID, fp)
	}

	// Untampered verify succeeds.
	if err := discovery.VerifyResponse(signer, resp, pub); err != nil {
		t.Errorf("VerifyResponse on untampered: %v", err)
	}

	// Tampering with a result address MUST break verification.
	tampered := *resp
	tampered.Results = []discovery.Result{
		{Address: "mallory@example.com", Status: semp.DiscoverySEMP, TTL: 3600},
	}
	if err := discovery.VerifyResponse(signer, &tampered, pub); err == nil {
		t.Error("VerifyResponse accepted a tampered results array")
	}

	// Wrong public key rejected.
	wrongPub, _, _ := signer.GenerateKeyPair()
	if err := discovery.VerifyResponse(signer, resp, wrongPub); err == nil {
		t.Error("VerifyResponse accepted the wrong public key")
	}
}

// TestSignResponseVerifiesSignatureKeyIDAndAlgorithm confirms that
// changing the signature metadata (not just the signed result
// material) ALSO breaks verification. An attacker who swaps
// signature.algorithm or signature.key_id must not succeed.
func TestSignResponseVerifiesSignatureKeyIDAndAlgorithm(t *testing.T) {
	suite := crypto.SuiteBaseline
	signer := suite.Signer()
	pub, priv, _ := signer.GenerateKeyPair()
	fp := keys.Compute(pub)

	resp := &discovery.Response{
		Type:      discovery.MessageType,
		Step:      discovery.StepResponse,
		Version:   "1.0.0",
		ID:        "test-req-2",
		Timestamp: time.Now().UTC(),
		Results: []discovery.Result{
			{Address: "bob@example.com", Status: semp.DiscoverySEMP, TTL: 3600},
		},
	}
	if err := discovery.SignResponse(signer, priv, fp, resp); err != nil {
		t.Fatalf("SignResponse: %v", err)
	}

	// Clone and flip KeyID.
	tampered := *resp
	tampered.Signature.KeyID = "mallory-fp"
	if err := discovery.VerifyResponse(signer, &tampered, pub); err == nil {
		t.Error("VerifyResponse accepted a swapped signature.key_id")
	}

	// Flip algorithm.
	tampered2 := *resp
	tampered2.Signature.Algorithm = "rsa"
	if err := discovery.VerifyResponse(signer, &tampered2, pub); err == nil {
		t.Error("VerifyResponse accepted a swapped signature.algorithm")
	}
}
