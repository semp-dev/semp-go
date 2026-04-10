package discovery

import (
	"context"
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
	Type       string                       `json:"type"`
	Step       string                       `json:"step"`
	Version    string                       `json:"version"`
	ID         string                       `json:"id"`
	Timestamp  time.Time                    `json:"timestamp"`
	Results    []Result                     `json:"results"`
	Signature  keys.PublicationSignature    `json:"signature"`
	Extensions extensions.Map               `json:"extensions,omitempty"`
}

// Result is one entry in a discovery response (DISCOVERY.md §4.5).
type Result struct {
	Address    string              `json:"address"`
	Status     semp.DiscoveryStatus `json:"status"`
	Transports []string            `json:"transports,omitempty"`
	Features   []string            `json:"features,omitempty"`
	Server     string              `json:"server,omitempty"`
	TTL        int                 `json:"ttl"`
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

// NewResolver constructs the default Resolver: DNS first, well-known URI
// fallback, MX-only check on no-SEMP, with the supplied Cache.
//
// TODO(DISCOVERY.md §5.1): implement.
func NewResolver(cache Cache) Resolver {
	_ = cache
	return nil
}
