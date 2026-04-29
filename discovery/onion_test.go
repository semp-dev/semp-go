package discovery_test

import (
	"context"
	"strings"
	"testing"

	semp "semp.dev/semp-go"
	"semp.dev/semp-go/discovery"
)

// v3Label is a valid-shaped 56-character base32 v3 onion identifier
// for the tests below. The bits do not encode a real onion service;
// we only test the library's structural validation.
const v3Label = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx"

func TestIsOnionDomain(t *testing.T) {
	if !discovery.IsOnionDomain("example.onion") {
		t.Error("IsOnionDomain('example.onion') = false, want true")
	}
	if !discovery.IsOnionDomain("Example.Onion") {
		t.Error("IsOnionDomain is not case-insensitive")
	}
	if discovery.IsOnionDomain("example.com") {
		t.Error("IsOnionDomain('example.com') = true, want false")
	}
}

func TestValidateOnionDomainAcceptsV3(t *testing.T) {
	if err := discovery.ValidateOnionDomain(v3Label + ".onion"); err != nil {
		t.Errorf("ValidateOnionDomain v3: %v", err)
	}
	// Sub-labels before the v3 label are permitted.
	if err := discovery.ValidateOnionDomain("sub." + v3Label + ".onion"); err != nil {
		t.Errorf("ValidateOnionDomain sub.v3: %v", err)
	}
}

func TestValidateOnionDomainRejectsV2(t *testing.T) {
	// v2 onion labels are 16 characters.
	v2 := "abcdefghijklmnop"
	err := discovery.ValidateOnionDomain(v2 + ".onion")
	if err == nil {
		t.Error("ValidateOnionDomain on v2: want error")
	}
	if err != nil && !strings.Contains(err.Error(), "version-2") {
		t.Errorf("error %q should mention version-2", err)
	}
}

func TestValidateOnionDomainRejectsNonOnion(t *testing.T) {
	err := discovery.ValidateOnionDomain("example.com")
	if err == nil || !strings.Contains(err.Error(), "not an .onion") {
		t.Errorf("ValidateOnionDomain on non-onion: got %v, want 'not an .onion'", err)
	}
}

func TestValidateOnionDomainRejectsWrongLength(t *testing.T) {
	wrong := "abcdefg"
	err := discovery.ValidateOnionDomain(wrong + ".onion")
	if err == nil {
		t.Error("ValidateOnionDomain on short label: want error")
	}
}

func TestValidateOnionDomainRejectsInvalidAlphabet(t *testing.T) {
	// Replace one char with something outside base32.
	bad := strings.Repeat("a", 55) + "!"
	err := discovery.ValidateOnionDomain(bad + ".onion")
	if err == nil {
		t.Error("ValidateOnionDomain on invalid alphabet: want error")
	}
}

// TestResolveOnionUnreachableReturnsServerUnavailable confirms that
// when a .onion well-known fetch fails (no Tor connectivity, service
// down, etc.), the resolver returns DiscoveryServerUnavailable rather
// than DiscoveryNotFound. Per DISCOVERY.md §2.5.2 the failure MUST
// surface as server_unavailable to the sending user (recoverable per
// DELIVERY.md §2.3); a not_found return would be non-recoverable and
// the sender would stop retrying when the recipient may simply be
// transiently unreachable.
func TestResolveOnionUnreachableReturnsServerUnavailable(t *testing.T) {
	r := discovery.NewResolver(discovery.ResolverConfig{
		Cache: discovery.NewMemCache(),
		// Point WellKnownURLFunc at a URL that will not connect; the
		// default http.Client times out quickly enough for the test.
		// We use a non-routable address so the fetch fails fast.
		WellKnownURLFunc: func(domain string) string {
			return "http://127.0.0.1:1/.well-known/semp/configuration"
		},
	})
	addr := "alice@" + v3Label + ".onion"
	result, err := r.Resolve(context.Background(), addr)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if result.Status != semp.DiscoveryServerUnavailable {
		t.Errorf("Status = %q, want %q", result.Status, semp.DiscoveryServerUnavailable)
	}
	if result.Status.ToReasonCode() != semp.ReasonServerUnavailable {
		t.Errorf("ToReasonCode = %q, want %q", result.Status.ToReasonCode(), semp.ReasonServerUnavailable)
	}
	// server_unavailable is transient; re-resolving MUST attempt the
	// fetch again rather than returning a cached unreachable verdict.
	result2, err := r.Resolve(context.Background(), addr)
	if err != nil {
		t.Fatalf("Resolve (second): %v", err)
	}
	if result2.Status != semp.DiscoveryServerUnavailable {
		t.Errorf("Second Status = %q, want still %q (no caching of transient state)",
			result2.Status, semp.DiscoveryServerUnavailable)
	}
}
