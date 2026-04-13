package discovery

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
)

// SRVRecord is a parsed _semp._tcp.<domain> SRV record (DISCOVERY.md §2.1).
type SRVRecord struct {
	Priority uint16
	Weight   uint16
	Port     uint16
	Target   string
}

// TXTCapabilities is the parsed companion TXT record (DISCOVERY.md §2.2).
//
//	"v=semp1;s=pq-kyber768-x25519,x25519-chacha20-poly1305;c=ws,h2,quic;mes=26214400"
type TXTCapabilities struct {
	Version    string   // v=semp1
	Suites     []string // s=pq-kyber768-x25519,x25519-chacha20-poly1305
	Transports []string // c=ws,h2,quic
	// Unknown parameters MUST be ignored rather than treated as errors
	// (DISCOVERY.md §2.2). They are preserved here for diagnostics.
	Unknown map[string]string
}

// DNSLookup is the narrow interface the Resolver uses for DNS lookups.
// The default implementation wraps net.DefaultResolver; tests inject
// their own mock so they don't depend on real DNS.
type DNSLookup interface {
	LookupSRV(ctx context.Context, service, proto, name string) (cname string, addrs []*net.SRV, err error)
	LookupTXT(ctx context.Context, name string) ([]string, error)
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)
}

// DefaultDNSLookup returns a DNSLookup backed by net.DefaultResolver.
func DefaultDNSLookup() DNSLookup {
	return defaultDNSLookup{}
}

type defaultDNSLookup struct{}

func (defaultDNSLookup) LookupSRV(ctx context.Context, service, proto, name string) (string, []*net.SRV, error) {
	return net.DefaultResolver.LookupSRV(ctx, service, proto, name)
}

func (defaultDNSLookup) LookupTXT(ctx context.Context, name string) ([]string, error) {
	return net.DefaultResolver.LookupTXT(ctx, name)
}

func (defaultDNSLookup) LookupMX(ctx context.Context, name string) ([]*net.MX, error) {
	return net.DefaultResolver.LookupMX(ctx, name)
}

// LookupSRV queries DNS for the _semp._tcp.<domain> SRV records and
// returns them converted to our SRVRecord type. Records are returned
// in the order delivered by the resolver; callers interested in
// weighted selection should sort by Priority and then apply weighted
// random selection per RFC 2782.
func LookupSRV(ctx context.Context, domain string) ([]SRVRecord, error) {
	return LookupSRVWith(ctx, DefaultDNSLookup(), domain)
}

// LookupSRVWith is the injectable variant of LookupSRV. It lets
// callers (including tests) supply their own DNSLookup implementation.
func LookupSRVWith(ctx context.Context, lookup DNSLookup, domain string) ([]SRVRecord, error) {
	if lookup == nil {
		return nil, errors.New("discovery: nil DNS lookup")
	}
	_, recs, err := lookup.LookupSRV(ctx, "semp", "tcp", domain)
	if err != nil {
		return nil, fmt.Errorf("discovery: SRV lookup for _semp._tcp.%s: %w", domain, err)
	}
	out := make([]SRVRecord, 0, len(recs))
	for _, r := range recs {
		if r == nil {
			continue
		}
		out = append(out, SRVRecord{
			Priority: r.Priority,
			Weight:   r.Weight,
			Port:     r.Port,
			// net.SRV.Target has a trailing dot; trim it so the
			// result is a plain hostname.
			Target: strings.TrimSuffix(r.Target, "."),
		})
	}
	return out, nil
}

// LookupTXT queries DNS for the _semp._tcp.<domain> TXT capability
// record and returns the parsed result. Multiple TXT records at the
// same name are supported: the first record whose v= parameter is
// "semp1" wins. A record without "v=semp1" is skipped rather than
// treated as an error, which lets domains co-publish SEMP and other
// capability records at the same name.
func LookupTXT(ctx context.Context, domain string) (*TXTCapabilities, error) {
	return LookupTXTWith(ctx, DefaultDNSLookup(), domain)
}

// LookupTXTWith is the injectable variant of LookupTXT.
func LookupTXTWith(ctx context.Context, lookup DNSLookup, domain string) (*TXTCapabilities, error) {
	if lookup == nil {
		return nil, errors.New("discovery: nil DNS lookup")
	}
	name := "_semp._tcp." + domain
	txts, err := lookup.LookupTXT(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("discovery: TXT lookup for %s: %w", name, err)
	}
	for _, raw := range txts {
		cap, err := ParseTXTCapabilities(raw)
		if err != nil {
			// Malformed or not a SEMP record — try the next TXT
			// record at this name.
			continue
		}
		if cap.Version == "" || cap.Version == "semp1" {
			return cap, nil
		}
	}
	return nil, fmt.Errorf("discovery: no SEMP TXT capability record at %s", name)
}

// ParseTXTCapabilities parses a single TXT record string like
//
//	v=semp1;pq=ready;c=ws,h2,quic;f=groups,threads
//
// into a TXTCapabilities value. Unknown parameters are collected
// into the Unknown map rather than rejected, per the spec's
// extensibility rule (DISCOVERY.md §2.2). A record that does not
// start with v=semp1 returns an error so callers can try the next
// TXT record at the same name.
func ParseTXTCapabilities(s string) (*TXTCapabilities, error) {
	if s == "" {
		return nil, errors.New("discovery: empty TXT record")
	}
	cap := &TXTCapabilities{Unknown: map[string]string{}}
	for _, kv := range strings.Split(s, ";") {
		kv = strings.TrimSpace(kv)
		if kv == "" {
			continue
		}
		eq := strings.IndexByte(kv, '=')
		if eq < 0 {
			continue // malformed entry; ignore
		}
		key := strings.TrimSpace(kv[:eq])
		val := strings.TrimSpace(kv[eq+1:])
		switch key {
		case "v":
			cap.Version = val
		case "s":
			cap.Suites = splitCSV(val)
		case "c":
			cap.Transports = splitCSV(val)
		default:
			cap.Unknown[key] = val
		}
	}
	if cap.Version == "" {
		return nil, errors.New("discovery: TXT record missing v= parameter")
	}
	if cap.Version != "semp1" {
		return nil, fmt.Errorf("discovery: TXT record v=%q is not semp1", cap.Version)
	}
	return cap, nil
}

// splitCSV splits s on commas and trims whitespace from each element.
// Empty elements are dropped so "a,,b" yields {"a", "b"}.
func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
