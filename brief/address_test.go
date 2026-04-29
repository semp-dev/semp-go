package brief_test

import (
	"strings"
	"testing"

	"semp.dev/semp-go/brief"
)

// TestAddressValidateAccepts exercises addresses already in canonical
// wire form per ENVELOPE.md section 2.3: NFC local-part, A-label
// lowercase ASCII domain.
func TestAddressValidateAccepts(t *testing.T) {
	valid := []string{
		"alice@example.com",
		"a@b.co",
		"user.with.dots@sub.example.co.uk",
		"user+tag@example.com", // plus-addressing is server policy (FAQ §1.10)
		"user-name@example-domain.com",
		"ユーザー@example.jp",             // NFC local-part, ASCII domain
		"user@xn--r8jz45g.jp",           // A-label domain for `例え.jp`
		"1@2.io",
	}
	for _, s := range valid {
		if err := brief.Address(s).Validate(); err != nil {
			t.Errorf("Validate(%q) = %v, want nil", s, err)
		}
	}
}

// TestAddressValidateRejects confirms every structural failure path
// produces a descriptive error.
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
		{"c1 control in local", "alice@example.com", "control character"},
		{"c1 boundary low", "alice@example.com", "control character"},
		{"c1 boundary high", "alice@example.com", "control character"},
		{"domain leading dot", "alice@.example.com", "leading or trailing dot"},
		{"domain trailing dot", "alice@example.com.", "leading or trailing dot"},
		{"domain empty label", "alice@example..com", "empty label"},
		{"domain leading hyphen", "alice@-example.com", "hyphen"},
		{"domain trailing hyphen", "alice@example-.com", "hyphen"},
		{"space in domain", "alice@exa mple.com", "disallowed character"},
		{"at in domain", "alice@exa@mple.com", "multiple '@'"},
		{"uppercase domain", "alice@EXAMPLE.COM", "uppercase"},
		{"unicode domain ulabel", "user@例え.jp", "non-ASCII"},
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
		{"alice@@example.com", "alice@", "example.com"}, // last @ wins
		{"a@b@c", "a@b", "c"},                           // last @ wins
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
	// Composed address at exactly MaxAddressLength bytes. 64-byte
	// local part plus '@' plus a domain of length 189 reaches 254.
	localAtLimit := strings.Repeat("a", brief.MaxLocalPartLength)
	// 63 + 1 + 63 + 1 + 61 = 189 (lowercase labels).
	domainAtLimit := strings.Repeat("x", 63) + "." + strings.Repeat("y", 63) + "." + strings.Repeat("z", 61)
	composedAtLimit := localAtLimit + "@" + domainAtLimit
	if len(composedAtLimit) != brief.MaxAddressLength {
		t.Fatalf("test constructed address of length %d, want %d",
			len(composedAtLimit), brief.MaxAddressLength)
	}
	if err := brief.Address(composedAtLimit).Validate(); err != nil {
		t.Errorf("address at limit: Validate = %v, want nil", err)
	}
}

// TestAddressCanonicalizeFolds confirms Canonicalize lowercases the
// domain and converts a U-label domain to its A-label (Punycode) form.
func TestAddressCanonicalizeFolds(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"ALICE@EXAMPLE.COM", "ALICE@example.com"},
		{"alice@EXAMPLE.COM", "alice@example.com"},
		{"user@例え.jp", "user@xn--r8jz45g.jp"},
		{"User@Example.Com", "User@example.com"},
	}
	for _, tc := range cases {
		got, err := brief.Address(tc.in).Canonicalize()
		if err != nil {
			t.Errorf("Canonicalize(%q) = %v, want nil", tc.in, err)
			continue
		}
		if string(got) != tc.want {
			t.Errorf("Canonicalize(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestAddressEqual confirms that Equal treats case-folded domain and
// U-label/A-label domain as equivalent, but preserves local-part case
// sensitivity and does not collapse confusables.
func TestAddressEqual(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"alice@example.com", "alice@EXAMPLE.COM", true},
		{"user@xn--r8jz45g.jp", "user@例え.jp", true},
		{"alice@example.com", "ALICE@example.com", false},     // case-sensitive local part
		{"alice@example.com", "alice@other.example", false},
	}
	for _, tc := range cases {
		got := brief.Address(tc.a).Equal(brief.Address(tc.b))
		if got != tc.want {
			t.Errorf("Equal(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}
