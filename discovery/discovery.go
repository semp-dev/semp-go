package discovery

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	semp "github.com/semp-dev/semp-go"
	"github.com/semp-dev/semp-go/extensions"
	"github.com/semp-dev/semp-go/keys"
)

// MessageType is the wire-level type discriminator for discovery messages.
const MessageType = "SEMP_DISCOVERY"

// Steps for discovery messages.
const (
	StepRequest  = "request"
	StepResponse = "response"
)

// Request is the SEMP_DISCOVERY request body (DISCOVERY.md §4.1).
type Request struct {
	Type       string         `json:"type"`
	Step       string         `json:"step"`
	Version    string         `json:"version"`
	ID         string         `json:"id"`
	Timestamp  time.Time      `json:"timestamp"`
	Addresses  []string       `json:"addresses"`
	Extensions extensions.Map `json:"extensions,omitempty"`
}

// Response is the SEMP_DISCOVERY response body (DISCOVERY.md §4.3).
type Response struct {
	Type       string                    `json:"type"`
	Step       string                    `json:"step"`
	Version    string                    `json:"version"`
	ID         string                    `json:"id"`
	Timestamp  time.Time                 `json:"timestamp"`
	Results    []Result                  `json:"results"`
	Signature  keys.PublicationSignature `json:"signature"`
	Extensions extensions.Map            `json:"extensions,omitempty"`
}

// Result is one entry in a discovery response (DISCOVERY.md §4.5).
type Result struct {
	Address    string               `json:"address"`
	Status     semp.DiscoveryStatus `json:"status"`
	Transports []string             `json:"transports,omitempty"`
	Features   []string             `json:"features,omitempty"`
	Server     string               `json:"server,omitempty"`
	TTL        int                  `json:"ttl"`
}

// Resolver is the high-level discovery interface a sending server uses to
// determine how to deliver to a recipient address. It encapsulates DNS
// lookup, well-known URI fetch, the SEMP_DISCOVERY exchange, MX fallback,
// and result caching.
type Resolver interface {
	// Resolve returns the discovery result for a single recipient address.
	Resolve(ctx context.Context, address string) (*Result, error)

	// ResolveBatch resolves multiple addresses in a single call. Senders
	// SHOULD batch where possible to reduce intent leakage (DISCOVERY.md §4.1).
	ResolveBatch(ctx context.Context, addresses []string) ([]*Result, error)
}

// ResolverConfig groups the inputs to NewResolver.
type ResolverConfig struct {
	// Cache is the discovery result cache. Required.
	Cache Cache

	// DNS is the DNS lookup implementation. Zero means "use the
	// default" (net.DefaultResolver). Tests inject a mock here.
	DNS DNSLookup

	// HTTPClient is the HTTP client used for well-known URI fetches.
	// Zero means "use the default" (10-second timeout).
	HTTPClient *http.Client

	// WellKnownURLFunc produces the URL to GET for a given domain.
	// Zero means "use the canonical https://<domain>/.well-known/semp/configuration".
	// Tests use this to point at an httptest server.
	WellKnownURLFunc func(domain string) string
}

// NewResolver constructs the default Resolver.
func NewResolver(cfg ResolverConfig) Resolver {
	if cfg.Cache == nil {
		cfg.Cache = NewMemCache()
	}
	if cfg.DNS == nil {
		cfg.DNS = DefaultDNSLookup()
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	if cfg.WellKnownURLFunc == nil {
		cfg.WellKnownURLFunc = func(domain string) string {
			return "https://" + domain + WellKnownPath
		}
	}
	return &defaultResolver{cfg: cfg}
}

type defaultResolver struct {
	cfg ResolverConfig
}

// Resolve implements the DISCOVERY.md §5.1 standard flow for a single
// address:
//
//  1. Cache lookup — if present and within TTL, return.
//  2. DNS SRV + TXT for _semp._tcp.<domain>. If SRV records exist
//     AND the TXT record advertises v=semp1, return status=semp.
//  3. Well-known URI GET. If it returns a valid configuration,
//     return status=semp with the endpoint host as the server field.
//  4. MX lookup. If records exist, return status=legacy. Otherwise
//     return status=not_found.
//
// The result is cached for the TTL declared on the returned Result
// (or DefaultTTLSEMP / DefaultTTLLegacy / DefaultTTLNotFound if the
// Result carries no explicit TTL).
func (r *defaultResolver) Resolve(ctx context.Context, address string) (*Result, error) {
	if address == "" {
		return nil, errors.New("discovery: empty address")
	}
	if cached, ok := r.cfg.Cache.Get(ctx, address); ok {
		return cached, nil
	}
	domain := domainPartOf(address)
	if domain == "" {
		return nil, fmt.Errorf("discovery: address %q has no domain", address)
	}

	// Step 1: DNS SRV + TXT.
	if result := r.tryDNS(ctx, address, domain); result != nil {
		r.cacheResult(ctx, address, result)
		return result, nil
	}

	// Step 2: well-known URI.
	if result := r.tryWellKnown(ctx, address, domain); result != nil {
		r.cacheResult(ctx, address, result)
		return result, nil
	}

	// Step 3: MX fallback.
	result := r.tryMX(ctx, address, domain)
	r.cacheResult(ctx, address, result)
	return result, nil
}

// ResolveBatch resolves each address sequentially. A future
// implementation could parallelize and/or batch per-domain lookups.
func (r *defaultResolver) ResolveBatch(ctx context.Context, addresses []string) ([]*Result, error) {
	out := make([]*Result, 0, len(addresses))
	for _, addr := range addresses {
		result, err := r.Resolve(ctx, addr)
		if err != nil {
			return nil, fmt.Errorf("discovery: resolve %s: %w", addr, err)
		}
		out = append(out, result)
	}
	return out, nil
}

// tryDNS attempts the SRV + TXT path. Returns nil when DNS returns
// no SEMP records (which is the normal fall-through case); returns
// a populated Result on success.
func (r *defaultResolver) tryDNS(ctx context.Context, address, domain string) *Result {
	srv, err := LookupSRVWith(ctx, r.cfg.DNS, domain)
	if err != nil || len(srv) == 0 {
		return nil
	}
	// Pick the lowest-priority SRV record. For ties, the resolver's
	// order is good enough; weighted random selection is a follow-up.
	best := srv[0]
	for _, rec := range srv[1:] {
		if rec.Priority < best.Priority {
			best = rec
		}
	}
	cap, _ := LookupTXTWith(ctx, r.cfg.DNS, domain)
	result := &Result{
		Address: address,
		Status:  semp.DiscoverySEMP,
		Server:  best.Target,
		TTL:     int(DefaultTTLSEMP.Seconds()),
	}
	if cap != nil {
		result.Transports = cap.Transports
		result.Features = cap.Features
	}
	return result
}

// tryWellKnown attempts the well-known URI fetch. Returns nil on
// any failure so the caller falls through to MX.
func (r *defaultResolver) tryWellKnown(ctx context.Context, address, domain string) *Result {
	url := r.cfg.WellKnownURLFunc(domain)
	cfg, err := FetchConfigurationWith(ctx, r.cfg.HTTPClient, url)
	if err != nil {
		return nil
	}
	transports := make([]string, 0, len(cfg.Endpoints))
	var server string
	for id, ep := range cfg.Endpoints {
		transports = append(transports, id)
		if server == "" {
			server = hostOfURL(ep)
		}
	}
	return &Result{
		Address:    address,
		Status:     semp.DiscoverySEMP,
		Transports: transports,
		Features:   cfg.Features,
		Server:     server,
		TTL:        int(DefaultTTLSEMP.Seconds()),
	}
}

// tryMX is the fallback: if the domain has MX records we return
// status=legacy, otherwise status=not_found. tryMX never returns nil.
func (r *defaultResolver) tryMX(ctx context.Context, address, domain string) *Result {
	mxs, err := LookupMXWith(ctx, r.cfg.DNS, domain)
	if err == nil && len(mxs) > 0 {
		return &Result{
			Address:    address,
			Status:     semp.DiscoveryLegacy,
			Transports: []string{"smtp"},
			Server:     mxs[0],
			TTL:        int(DefaultTTLLegacy.Seconds()),
		}
	}
	return &Result{
		Address: address,
		Status:  semp.DiscoveryNotFound,
		TTL:     int(DefaultTTLNotFound.Seconds()),
	}
}

// cacheResult stores the result with an appropriate TTL.
func (r *defaultResolver) cacheResult(ctx context.Context, address string, result *Result) {
	if result == nil {
		return
	}
	ttl := time.Duration(result.TTL) * time.Second
	if ttl <= 0 {
		switch result.Status {
		case semp.DiscoverySEMP:
			ttl = DefaultTTLSEMP
		case semp.DiscoveryLegacy:
			ttl = DefaultTTLLegacy
		default:
			ttl = DefaultTTLNotFound
		}
	}
	_ = r.cfg.Cache.Put(ctx, address, result, ttl)
}

// domainPartOf returns the domain suffix of an email-style address,
// or the empty string if the address has no '@'.
func domainPartOf(address string) string {
	at := strings.LastIndexByte(address, '@')
	if at < 0 {
		return ""
	}
	return address[at+1:]
}

// hostOfURL extracts the host portion of a URL like
// "wss://semp.example.com/v1/ws" → "semp.example.com". Returns the
// original string when parsing fails.
func hostOfURL(u string) string {
	s := u
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	if i := strings.IndexByte(s, ':'); i >= 0 {
		s = s[:i]
	}
	return s
}
