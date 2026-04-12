package brief_test

import (
	"strings"
	"testing"

	"semp.dev/semp-go/brief"
)

// TestAddressValidateAccepts exercises a range of valid addresses the
// spec explicitly permits, including internationalized UTF-8 local
// parts and domains (FAQ §1.11).
func TestAddressValidateAccepts(t *testing.T) {
	valid := []string{
		"alice@example.com",
		"a@b.co",
		"user.with.dots@sub.example.co.uk",
		"user+tag@example.com", // plus-addressing is server policy (FAQ §1.10)
		"user-name@example-domain.com",
		"ユーザー@example.jp",
		"user@例え.jp",
		"1@2.io",
		"UPPER@CASE.COM",
	}
	for _, s := range valid {
		if err := brief.Address(s).Validate(); err != nil {
			t.Errorf("Validate(%q) = %v, want nil", s, err)
		}
	}
}

// TestAddressValidateRejects confirms every structural failure path
// from ENVELOPE.md §5 produces a descriptive error.
func TestAddressValidateRejects(t *testing.T) {
	tests := []struct {
		name    string
		addr    string
		wantSub string // substring the error MUST contain
	}{
		{"empty", "", "empty address"},
		{"no at", "alice.example.com", "missing '@'"},
		{"double at", "alice@@example.com", "multiple '@'"},
		{"leading at", "@example.com", "empty local"},
		{"trailing at", "alice@", "empty domain"},
		{"nul byte", "alice\x00@example.com", "control character"},
		{"lf injection", "alice\n@example.com", "control character"},
		{"cr injection", "alice\r@example.com", "control character"},
		{"tab in local", "alice\t@example.com", "control character"},
		{"domain leading dot", "alice@.example.com", "leading or trailing dot"},
		{"domain trailing dot", "alice@example.com.", "leading or trailing dot"},
		{"domain empty label", "alice@example..com", "empty label"},
		{"domain leading hyphen", "alice@-example.com", "hyphen"},
		{"domain trailing hyphen", "alice@example-.com", "hyphen"},
		{"space in domain", "alice@exa mple.com", "disallowed character"},
		{"at in domain", "alice@exa@mple.com", "multiple '@'"},
		{"oversize address", "a@" + strings.Repeat("x", 400), "exceeds"},
		{"oversize local part", strings.Repeat("a", brief.MaxLocalPartLength+1) + "@example.com", "local part exceeds"},
		{"oversize domain", "alice@" + strings.Repeat("x", brief.MaxDomainLength+1), "exceeds"},
		{"oversize label", "alice@" + strings.Repeat("x", brief.MaxDomainLabelLength+1) + ".com", "exceeds"},
		{"invalid utf8", "alice@\xff\xfe.com", "valid UTF-8"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := brief.Address(tc.addr).Validate()
			if err == nil {
				t.Fatalf("Validate(%q) = nil, want error", tc.addr)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("Validate(%q) = %v; want substring %q", tc.addr, err, tc.wantSub)
			}
		})
	}
}

// TestAddressLocalDomainExisting is a regression check: the
// Local/Domain accessors still operate on raw bytes without
// validation, matching the contract the fuzz targets rely on.
func TestAddressLocalDomainExisting(t *testing.T) {
	cases := []struct {
		raw, local, domain string
	}{
		{"alice@example.com", "alice", "example.com"},
		{"", "", ""},
		{"no-at-here", "no-at-here", ""},
		{"alice@@example.com", "alice@", "example.com"},    // last @ wins
		{"a@b@c", "a@b", "c"},                              // last @ wins
	}
	for _, tc := range cases {
		a := brief.Address(tc.raw)
		if got := a.Local(); got != tc.local {
			t.Errorf("Local(%q) = %q, want %q", tc.raw, got, tc.local)
		}
		if got := a.Domain(); got != tc.domain {
			t.Errorf("Domain(%q) = %q, want %q", tc.raw, got, tc.domain)
		}
		if got := a.String(); got != tc.raw {
			t.Errorf("String(%q) = %q, want identity", tc.raw, got)
		}
	}
}

// TestAddressValidateMaxBoundary tests the exact-boundary cases for
// each length limit. Just under the limit is accepted; the limit
// itself is still valid; exactly one byte over is rejected.
func TestAddressValidateMaxBoundary(t *testing.T) {
	// Local part at exactly MaxLocalPartLength bytes.
	atLimit := strings.Repeat("a", brief.MaxLocalPartLength) + "@example.com"
	if err := brief.Address(atLimit).Validate(); err != nil {
		t.Errorf("local part at limit: Validate = %v, want nil", err)
	}

	// Domain at exactly MaxDomainLength is trickier because each
	// label is capped at 63 bytes. Build "63.63.63.61" = 63+1+63+1+63+1+61 = 253.
	label63 := strings.Repeat("x", 63)
	label61 := strings.Repeat("y", 61)
	domainAtLimit := label63 + "." + label63 + "." + label63 + "." + label61
	if len(domainAtLimit) != brief.MaxDomainLength {
		t.Fatalf("test constructed domain of length %d, want %d",
			len(domainAtLimit), brief.MaxDomainLength)
	}
	if err := brief.Address("a@" + domainAtLimit).Validate(); err != nil {
		t.Errorf("domain at limit: Validate = %v, want nil", err)
	}
}
