package discovery

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

// PartitionStrategy is the user-partitioning strategy advertised by
// a large domain via the _semp-partition.<domain> TXT record
// (DISCOVERY.md §2.4).
type PartitionStrategy string

// Defined strategies.
const (
	// StrategyAlpha partitions by the first character of the local
	// part of the address. Each alphabetical range maps to a
	// specific server via _semp-partition-<range>.<domain> SRV
	// records. Non-alphabetic first characters (digits, symbols,
	// UTF-8) are assigned to the last range.
	StrategyAlpha PartitionStrategy = "alpha"

	// StrategyHash maps users to servers by computing
	// SHA-256(address) mod N, where N is the number of servers.
	// The index maps to _semp-partition-<index>.<domain> SRV
	// records.
	StrategyHash PartitionStrategy = "hash"

	// StrategyLookup queries a designated partition server to
	// resolve which delivery server handles the target user.
	// The partition server is published at
	// _semp-partition-lookup.<domain> SRV.
	StrategyLookup PartitionStrategy = "lookup"
)

// PartitionConfig is the parsed _semp-partition.<domain> TXT record.
type PartitionConfig struct {
	// Version is the SEMP partition protocol version. Always
	// "semp1" for the initial spec revision.
	Version string

	// Strategy is the partitioning approach this domain uses.
	Strategy PartitionStrategy

	// Servers is the number of partition servers. Used only by
	// StrategyHash to compute the mod divisor.
	Servers int

	// Algorithm is the hash algorithm for StrategyHash. Defaults
	// to "sha256" if empty. Future revisions may add others.
	Algorithm string

	// Domain is the domain this partition config applies to.
	// Set by the caller that parsed the TXT record.
	Domain string

	// AlphaRanges, if non-nil, overrides the default 26-letter
	// mapping for StrategyAlpha. Each entry maps a contiguous
	// range of first-characters to a server hostname. The default
	// mapping splits a–z into roughly equal groups of Servers
	// size and resolves via _semp-partition-<range>.<domain> SRV.
	// This field is provided for callers that pre-resolve the
	// SRV records; if nil, ResolvePartition falls back to the
	// DNS SRV lookup pattern.
	AlphaRanges []AlphaRange
}

// AlphaRange maps a first-character range to a server hostname.
// StartChar and EndChar are inclusive lowercase ASCII letters.
type AlphaRange struct {
	StartChar byte
	EndChar   byte
	Server    string
}

// DefaultAlphaRanges constructs the even-split default ranges used
// by the spec's §2.4 example: 4 ranges covering a-f, g-m, n-s, t-z
// when servers=4. Generalized to any server count ≥ 1.
func DefaultAlphaRanges(servers int) []AlphaRange {
	if servers <= 0 {
		return nil
	}
	if servers > 26 {
		servers = 26
	}
	ranges := make([]AlphaRange, 0, servers)
	charsPerServer := 26 / servers
	remainder := 26 % servers
	start := byte('a')
	for i := 0; i < servers; i++ {
		width := charsPerServer
		if i < remainder {
			width++
		}
		end := start + byte(width) - 1
		if end > 'z' {
			end = 'z'
		}
		ranges = append(ranges, AlphaRange{
			StartChar: start,
			EndChar:   end,
		})
		start = end + 1
	}
	return ranges
}

// PartitionLookupFunc is the callback used by StrategyLookup. It
// queries the partition lookup server and returns the hostname of
// the delivery server that handles address. An error means the
// lookup failed and the caller should treat the delivery as
// unroutable for this attempt.
//
// The caller is responsible for connecting to the partition lookup
// server (published at _semp-partition-lookup.<domain> SRV) and
// translating the query/response into this function signature. The
// discovery package does not prescribe the wire format of the
// lookup query — DISCOVERY.md §2.4 says "the partition server
// address is published as a separate SRV record" and leaves the
// query protocol to the implementation.
type PartitionLookupFunc func(ctx context.Context, address string) (server string, err error)

// PartitionResolver groups the resources needed by ResolvePartition.
type PartitionResolver struct {
	// DNS is the DNS lookup backend. Required for StrategyAlpha
	// and StrategyHash (to resolve _semp-partition-<X>.<domain>
	// SRV records). Unused by StrategyLookup (which delegates to
	// LookupFunc instead).
	DNS DNSLookup

	// LookupFunc is the callback for StrategyLookup. Required when
	// config.Strategy == StrategyLookup. Ignored otherwise.
	LookupFunc PartitionLookupFunc
}

// ResolvePartition returns the SEMP server hostname that handles
// the given user address according to config. The three strategies
// from DISCOVERY.md §2.4:
//
//   - StrategyAlpha: extract the first character of the local part,
//     map it to the range that contains it, and return the server
//     for that range. If config.AlphaRanges is nil, resolve via
//     _semp-partition-<start>-<end>.<domain> SRV.
//   - StrategyHash: compute SHA-256(address) mod config.Servers to
//     get an index, then resolve via
//     _semp-partition-<index>.<domain> SRV.
//   - StrategyLookup: delegate to resolver.LookupFunc.
//
// Returns an error if the strategy is unknown, the config is
// invalid (e.g. StrategyHash with Servers=0), or a DNS lookup
// fails.
func ResolvePartition(ctx context.Context, resolver *PartitionResolver, config *PartitionConfig, address string) (string, error) {
	if config == nil {
		return "", errors.New("discovery: nil partition config")
	}
	if address == "" {
		return "", errors.New("discovery: empty address")
	}
	if resolver == nil {
		return "", errors.New("discovery: nil partition resolver")
	}
	switch config.Strategy {
	case StrategyAlpha:
		return resolveAlpha(ctx, resolver, config, address)
	case StrategyHash:
		return resolveHash(ctx, resolver, config, address)
	case StrategyLookup:
		return resolveLookup(ctx, resolver, config, address)
	default:
		return "", fmt.Errorf("discovery: unknown partition strategy %q", config.Strategy)
	}
}

// resolveAlpha implements StrategyAlpha.
func resolveAlpha(ctx context.Context, resolver *PartitionResolver, config *PartitionConfig, address string) (string, error) {
	local := localPart(address)
	if local == "" {
		return "", errors.New("discovery: address has no local part")
	}
	firstChar := firstLowerChar(local)

	// Fast path: pre-resolved AlphaRanges.
	if len(config.AlphaRanges) > 0 {
		for _, r := range config.AlphaRanges {
			if firstChar >= r.StartChar && firstChar <= r.EndChar {
				return r.Server, nil
			}
		}
		// Fallback: non-alphabetic first character → last range.
		return config.AlphaRanges[len(config.AlphaRanges)-1].Server, nil
	}

	// DNS path: construct ranges from DefaultAlphaRanges and
	// resolve each range's SRV record.
	ranges := DefaultAlphaRanges(config.Servers)
	if len(ranges) == 0 {
		return "", errors.New("discovery: alpha partition requires at least one server")
	}
	matchedRange := ranges[len(ranges)-1] // default to last
	for _, r := range ranges {
		if firstChar >= r.StartChar && firstChar <= r.EndChar {
			matchedRange = r
			break
		}
	}
	srvName := fmt.Sprintf("%c-%c", matchedRange.StartChar, matchedRange.EndChar)
	return resolveSRV(ctx, resolver.DNS, config.Domain, "semp-partition-"+srvName)
}

// resolveHash implements StrategyHash.
func resolveHash(ctx context.Context, resolver *PartitionResolver, config *PartitionConfig, address string) (string, error) {
	if config.Servers <= 0 {
		return "", errors.New("discovery: hash partition requires Servers > 0")
	}
	// SHA-256(address) mod N per DISCOVERY.md §2.4.
	sum := sha256.Sum256([]byte(strings.ToLower(address)))
	// Use the first 8 bytes as a big-endian uint64 for the mod
	// operation. 8 bytes of SHA-256 gives a 64-bit space — more
	// than sufficient for any realistic server count.
	idx := binary.BigEndian.Uint64(sum[:8]) % uint64(config.Servers)
	return resolveSRV(ctx, resolver.DNS, config.Domain, fmt.Sprintf("semp-partition-%d", idx))
}

// resolveLookup implements StrategyLookup.
func resolveLookup(ctx context.Context, resolver *PartitionResolver, _ *PartitionConfig, address string) (string, error) {
	if resolver.LookupFunc == nil {
		return "", errors.New("discovery: StrategyLookup requires a LookupFunc")
	}
	return resolver.LookupFunc(ctx, address)
}

// resolveSRV resolves a single _<service>._tcp.<domain> SRV record
// and returns the target hostname. If multiple targets are returned,
// the highest-priority (lowest Priority value) is preferred.
func resolveSRV(ctx context.Context, dns DNSLookup, domain, service string) (string, error) {
	if dns == nil {
		return "", errors.New("discovery: DNS lookup not configured")
	}
	_, addrs, err := dns.LookupSRV(ctx, service, "tcp", domain)
	if err != nil {
		return "", fmt.Errorf("discovery: SRV lookup _%s._tcp.%s: %w", service, domain, err)
	}
	if len(addrs) == 0 {
		return "", fmt.Errorf("discovery: no SRV records for _%s._tcp.%s", service, domain)
	}
	// Pick the best-priority target.
	best := addrs[0]
	for _, a := range addrs[1:] {
		if a.Priority < best.Priority {
			best = a
		}
	}
	return strings.TrimSuffix(best.Target, "."), nil
}

// localPart extracts the part before the last '@' in address.
func localPart(address string) string {
	i := strings.LastIndexByte(address, '@')
	if i < 0 {
		return address
	}
	return address[:i]
}

// firstLowerChar returns the first character of s lowercased if it
// is a valid UTF-8 rune in [a-z] after lowercasing, or '~' (the
// highest printable ASCII, which sorts after z) as a fallback for
// non-alphabetic first characters. The tilde ensures non-alpha
// users land in the last range.
func firstLowerChar(s string) byte {
	if len(s) == 0 {
		return '~'
	}
	r, _ := utf8.DecodeRuneInString(s)
	if r == utf8.RuneError {
		return '~'
	}
	c := byte(r)
	if c >= 'A' && c <= 'Z' {
		c += 'a' - 'A'
	}
	if c >= 'a' && c <= 'z' {
		return c
	}
	return '~'
}

// ParsePartitionTXT parses a _semp-partition.<domain> TXT record value
// into a PartitionConfig. The format follows the same semicolon-
// separated key=value convention as the discovery TXT record:
//
//	"v=semp1;strategy=hash;servers=8;algorithm=sha256"
//
// Unknown keys are silently ignored for forward compatibility.
func ParsePartitionTXT(domain, txt string) (*PartitionConfig, error) {
	if strings.TrimSpace(txt) == "" {
		return nil, errors.New("discovery: empty partition TXT record")
	}
	cfg := &PartitionConfig{Domain: domain}
	parts := strings.Split(txt, ";")
	for _, kv := range parts {
		kv = strings.TrimSpace(kv)
		eq := strings.IndexByte(kv, '=')
		if eq < 0 {
			continue
		}
		key := strings.TrimSpace(kv[:eq])
		val := strings.TrimSpace(kv[eq+1:])
		switch key {
		case "v":
			cfg.Version = val
		case "strategy":
			cfg.Strategy = PartitionStrategy(val)
		case "servers":
			n := 0
			for _, c := range val {
				if c < '0' || c > '9' {
					return nil, fmt.Errorf("discovery: invalid servers count %q", val)
				}
				n = n*10 + int(c-'0')
			}
			cfg.Servers = n
		case "algorithm":
			cfg.Algorithm = val
		}
	}
	if cfg.Version == "" {
		return nil, errors.New("discovery: partition TXT missing version (v=)")
	}
	if cfg.Strategy == "" {
		return nil, errors.New("discovery: partition TXT missing strategy")
	}
	return cfg, nil
}
