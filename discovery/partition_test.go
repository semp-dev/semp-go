package discovery_test

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	"semp.dev/semp-go/discovery"
)

// partFakeDNS is a test double for DNSLookup that returns
// pre-configured SRV records. Keyed by "_<service>._<proto>.<domain>".
// Separate from the fakeDNS in discovery_test.go to avoid
// redeclaration in the shared _test package.
type partFakeDNS struct {
	srvRecords map[string][]*net.SRV
}

func (f *partFakeDNS) LookupSRV(_ context.Context, service, proto, name string) (string, []*net.SRV, error) {
	key := "_" + service + "._" + proto + "." + name
	recs, ok := f.srvRecords[key]
	if !ok {
		return "", nil, errors.New("no such SRV record: " + key)
	}
	return "", recs, nil
}

func (f *partFakeDNS) LookupTXT(context.Context, string) ([]string, error) {
	return nil, errors.New("not implemented")
}

func (f *partFakeDNS) LookupMX(context.Context, string) ([]*net.MX, error) {
	return nil, errors.New("not implemented")
}

// partSRV builds a *net.SRV test helper.
func partSRV(target string, priority uint16) *net.SRV {
	return &net.SRV{Target: target + ".", Priority: priority, Weight: 10, Port: 443}
}

// --- DefaultAlphaRanges ---

// TestDefaultAlphaRanges4Servers confirms 4 servers cover a-z with
// no gaps or overlaps. The exact split depends on the remainder
// distribution (26/4 = 6 r 2), so ranges get 7,7,6,6 letters.
func TestDefaultAlphaRanges4Servers(t *testing.T) {
	ranges := discovery.DefaultAlphaRanges(4)
	if len(ranges) != 4 {
		t.Fatalf("len = %d, want 4", len(ranges))
	}
	// First range starts at 'a'.
	if ranges[0].StartChar != 'a' {
		t.Errorf("first range starts at %c, want a", ranges[0].StartChar)
	}
	// Last range ends at 'z'.
	if ranges[len(ranges)-1].EndChar != 'z' {
		t.Errorf("last range ends at %c, want z", ranges[len(ranges)-1].EndChar)
	}
	// No gaps: each range starts where the previous one ended + 1.
	for i := 1; i < len(ranges); i++ {
		if ranges[i].StartChar != ranges[i-1].EndChar+1 {
			t.Errorf("gap between range %d (%c) and range %d (%c)",
				i-1, ranges[i-1].EndChar, i, ranges[i].StartChar)
		}
	}
	// Total coverage = 26 characters.
	total := 0
	for _, r := range ranges {
		total += int(r.EndChar-r.StartChar) + 1
	}
	if total != 26 {
		t.Errorf("total characters covered = %d, want 26", total)
	}
}

// TestDefaultAlphaRanges1Server gives the entire alphabet to one.
func TestDefaultAlphaRanges1Server(t *testing.T) {
	ranges := discovery.DefaultAlphaRanges(1)
	if len(ranges) != 1 {
		t.Fatalf("len = %d, want 1", len(ranges))
	}
	if ranges[0].StartChar != 'a' || ranges[0].EndChar != 'z' {
		t.Errorf("range = %c-%c, want a-z", ranges[0].StartChar, ranges[0].EndChar)
	}
}

// TestDefaultAlphaRanges26Servers gives one letter per server.
func TestDefaultAlphaRanges26Servers(t *testing.T) {
	ranges := discovery.DefaultAlphaRanges(26)
	if len(ranges) != 26 {
		t.Fatalf("len = %d, want 26", len(ranges))
	}
	for i, r := range ranges {
		want := byte('a') + byte(i)
		if r.StartChar != want || r.EndChar != want {
			t.Errorf("range[%d] = %c-%c, want %c-%c", i, r.StartChar, r.EndChar, want, want)
		}
	}
}

// TestDefaultAlphaRangesZero returns nil.
func TestDefaultAlphaRangesZero(t *testing.T) {
	if ranges := discovery.DefaultAlphaRanges(0); ranges != nil {
		t.Errorf("expected nil for 0 servers, got %v", ranges)
	}
}

// --- ResolvePartition: StrategyAlpha ---

// TestResolvePartitionAlphaPreResolved exercises the fast path
// (AlphaRanges are already populated with server hostnames).
func TestResolvePartitionAlphaPreResolved(t *testing.T) {
	config := &discovery.PartitionConfig{
		Strategy: discovery.StrategyAlpha,
		Domain:   "example.com",
		AlphaRanges: []discovery.AlphaRange{
			{StartChar: 'a', EndChar: 'g', Server: "semp-1.example.com"},
			{StartChar: 'h', EndChar: 'n', Server: "semp-2.example.com"},
			{StartChar: 'o', EndChar: 's', Server: "semp-3.example.com"},
			{StartChar: 't', EndChar: 'z', Server: "semp-4.example.com"},
		},
	}
	resolver := &discovery.PartitionResolver{}
	tests := []struct {
		address string
		want    string
	}{
		{"alice@example.com", "semp-1.example.com"},
		{"nancy@example.com", "semp-2.example.com"},
		{"oscar@example.com", "semp-3.example.com"},
		{"zach@example.com", "semp-4.example.com"},
		{"123user@example.com", "semp-4.example.com"},  // non-alpha → last range
	}
	for _, tc := range tests {
		got, err := discovery.ResolvePartition(context.Background(), resolver, config, tc.address)
		if err != nil {
			t.Errorf("ResolvePartition(%q): %v", tc.address, err)
			continue
		}
		if got != tc.want {
			t.Errorf("ResolvePartition(%q) = %q, want %q", tc.address, got, tc.want)
		}
	}
}

// TestResolvePartitionAlphaDNS exercises the DNS path (no
// AlphaRanges pre-populated; SRV records are resolved on the fly).
func TestResolvePartitionAlphaDNS(t *testing.T) {
	dns := &partFakeDNS{srvRecords: map[string][]*net.SRV{
		"_semp-partition-a-g._tcp.example.com": {partSRV("semp-1.example.com", 10)},
		"_semp-partition-h-m._tcp.example.com": {partSRV("semp-2.example.com", 10)},
		"_semp-partition-n-s._tcp.example.com": {partSRV("semp-3.example.com", 10)},
		"_semp-partition-t-z._tcp.example.com": {partSRV("semp-4.example.com", 10)},
	}}
	config := &discovery.PartitionConfig{
		Strategy: discovery.StrategyAlpha,
		Domain:   "example.com",
		Servers:  4,
	}
	resolver := &discovery.PartitionResolver{DNS: dns}
	got, err := discovery.ResolvePartition(context.Background(), resolver, config, "alice@example.com")
	if err != nil {
		t.Fatalf("ResolvePartition: %v", err)
	}
	if got != "semp-1.example.com" {
		t.Errorf("got %q, want semp-1.example.com", got)
	}
}

// --- ResolvePartition: StrategyHash ---

// TestResolvePartitionHashDeterministic confirms the same address
// always maps to the same server index, and that the index is in
// [0, N).
func TestResolvePartitionHashDeterministic(t *testing.T) {
	dns := &partFakeDNS{srvRecords: map[string][]*net.SRV{}}
	for i := 0; i < 8; i++ {
		key := "_semp-partition-" + itoa(i) + "._tcp.example.com"
		dns.srvRecords[key] = []*net.SRV{partSRV("semp-"+itoa(i)+".example.com", 10)}
	}
	config := &discovery.PartitionConfig{
		Strategy:  discovery.StrategyHash,
		Domain:    "example.com",
		Servers:   8,
		Algorithm: "sha256",
	}
	resolver := &discovery.PartitionResolver{DNS: dns}
	// Run twice — must produce the same result.
	got1, err := discovery.ResolvePartition(context.Background(), resolver, config, "alice@example.com")
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	got2, err := discovery.ResolvePartition(context.Background(), resolver, config, "alice@example.com")
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if got1 != got2 {
		t.Errorf("non-deterministic: %q != %q", got1, got2)
	}
	// And different addresses may map to different servers (not
	// guaranteed but overwhelmingly likely with 8 servers).
	got3, err := discovery.ResolvePartition(context.Background(), resolver, config, "bob@example.com")
	if err != nil {
		t.Fatalf("bob: %v", err)
	}
	_ = got3 // no assertion — just confirm no error
}

// TestResolvePartitionHashZeroServers returns error.
func TestResolvePartitionHashZeroServers(t *testing.T) {
	resolver := &discovery.PartitionResolver{DNS: &partFakeDNS{}}
	config := &discovery.PartitionConfig{
		Strategy: discovery.StrategyHash,
		Domain:   "example.com",
		Servers:  0,
	}
	_, err := discovery.ResolvePartition(context.Background(), resolver, config, "alice@example.com")
	if err == nil {
		t.Fatal("expected error for 0 servers")
	}
}

// --- ResolvePartition: StrategyLookup ---

// TestResolvePartitionLookup exercises the callback path.
func TestResolvePartitionLookup(t *testing.T) {
	resolver := &discovery.PartitionResolver{
		LookupFunc: func(_ context.Context, address string) (string, error) {
			if strings.HasPrefix(address, "alice@") {
				return "semp-east.example.com", nil
			}
			return "semp-west.example.com", nil
		},
	}
	config := &discovery.PartitionConfig{
		Strategy: discovery.StrategyLookup,
		Domain:   "example.com",
	}
	got, err := discovery.ResolvePartition(context.Background(), resolver, config, "alice@example.com")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if got != "semp-east.example.com" {
		t.Errorf("got %q, want semp-east.example.com", got)
	}
}

// TestResolvePartitionLookupMissingFunc returns error.
func TestResolvePartitionLookupMissingFunc(t *testing.T) {
	resolver := &discovery.PartitionResolver{}
	config := &discovery.PartitionConfig{Strategy: discovery.StrategyLookup, Domain: "example.com"}
	_, err := discovery.ResolvePartition(context.Background(), resolver, config, "alice@example.com")
	if err == nil {
		t.Fatal("expected error for missing LookupFunc")
	}
}

// --- ResolvePartition: error paths ---

// TestResolvePartitionNilConfig returns error.
func TestResolvePartitionNilConfig(t *testing.T) {
	resolver := &discovery.PartitionResolver{}
	_, err := discovery.ResolvePartition(context.Background(), resolver, nil, "alice@example.com")
	if err == nil {
		t.Fatal("expected error for nil config")
	}
}

// TestResolvePartitionEmptyAddress returns error.
func TestResolvePartitionEmptyAddress(t *testing.T) {
	resolver := &discovery.PartitionResolver{}
	config := &discovery.PartitionConfig{Strategy: discovery.StrategyHash, Domain: "example.com", Servers: 1}
	_, err := discovery.ResolvePartition(context.Background(), resolver, config, "")
	if err == nil {
		t.Fatal("expected error for empty address")
	}
}

// TestResolvePartitionUnknownStrategy returns error.
func TestResolvePartitionUnknownStrategy(t *testing.T) {
	resolver := &discovery.PartitionResolver{}
	config := &discovery.PartitionConfig{Strategy: "future-mode", Domain: "example.com"}
	_, err := discovery.ResolvePartition(context.Background(), resolver, config, "alice@example.com")
	if err == nil {
		t.Fatal("expected error for unknown strategy")
	}
}

// --- ParsePartitionTXT ---

// TestParsePartitionTXTHashExample parses the spec example from §2.4.
func TestParsePartitionTXTHashExample(t *testing.T) {
	cfg, err := discovery.ParsePartitionTXT("example.com",
		"v=semp1;strategy=hash;servers=8;algorithm=sha256")
	if err != nil {
		t.Fatalf("ParsePartitionTXT: %v", err)
	}
	if cfg.Version != "semp1" {
		t.Errorf("Version = %q, want semp1", cfg.Version)
	}
	if cfg.Strategy != discovery.StrategyHash {
		t.Errorf("Strategy = %q, want hash", cfg.Strategy)
	}
	if cfg.Servers != 8 {
		t.Errorf("Servers = %d, want 8", cfg.Servers)
	}
	if cfg.Algorithm != "sha256" {
		t.Errorf("Algorithm = %q, want sha256", cfg.Algorithm)
	}
	if cfg.Domain != "example.com" {
		t.Errorf("Domain = %q, want example.com", cfg.Domain)
	}
}

// TestParsePartitionTXTAlpha parses an alpha strategy record.
func TestParsePartitionTXTAlpha(t *testing.T) {
	cfg, err := discovery.ParsePartitionTXT("example.com",
		"v=semp1;strategy=alpha;servers=4")
	if err != nil {
		t.Fatalf("ParsePartitionTXT: %v", err)
	}
	if cfg.Strategy != discovery.StrategyAlpha {
		t.Errorf("Strategy = %q, want alpha", cfg.Strategy)
	}
	if cfg.Servers != 4 {
		t.Errorf("Servers = %d, want 4", cfg.Servers)
	}
}

// TestParsePartitionTXTRejectsMissingVersion returns error.
func TestParsePartitionTXTRejectsMissingVersion(t *testing.T) {
	_, err := discovery.ParsePartitionTXT("example.com", "strategy=hash;servers=4")
	if err == nil {
		t.Fatal("expected error for missing version")
	}
}

// TestParsePartitionTXTRejectsMissingStrategy returns error.
func TestParsePartitionTXTRejectsMissingStrategy(t *testing.T) {
	_, err := discovery.ParsePartitionTXT("example.com", "v=semp1;servers=4")
	if err == nil {
		t.Fatal("expected error for missing strategy")
	}
}

// TestParsePartitionTXTRejectsEmpty returns error.
func TestParsePartitionTXTRejectsEmpty(t *testing.T) {
	_, err := discovery.ParsePartitionTXT("example.com", "")
	if err == nil {
		t.Fatal("expected error for empty TXT")
	}
}

// TestParsePartitionTXTRejectsBadServers returns error for non-digit.
func TestParsePartitionTXTRejectsBadServers(t *testing.T) {
	_, err := discovery.ParsePartitionTXT("example.com",
		"v=semp1;strategy=hash;servers=abc")
	if err == nil {
		t.Fatal("expected error for non-numeric servers")
	}
}

// TestParsePartitionTXTIgnoresUnknownKeys confirms forward compat.
func TestParsePartitionTXTIgnoresUnknownKeys(t *testing.T) {
	cfg, err := discovery.ParsePartitionTXT("example.com",
		"v=semp1;strategy=hash;servers=2;future_key=value")
	if err != nil {
		t.Fatalf("ParsePartitionTXT: %v", err)
	}
	if cfg.Servers != 2 {
		t.Errorf("Servers = %d, want 2", cfg.Servers)
	}
}

// itoa is a dependency-free int-to-string for test helpers.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	s := ""
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	return s
}
