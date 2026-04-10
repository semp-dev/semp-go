package discovery

import "context"

// WellKnownPath is the canonical path for SEMP capability discovery via
// HTTPS (DISCOVERY.md §3).
const WellKnownPath = "/.well-known/semp/configuration"

// Configuration is the parsed body of the well-known configuration URI
// (DISCOVERY.md §3.1).
type Configuration struct {
	Version        string            `json:"version"`
	Endpoints      map[string]string `json:"endpoints"`
	Features       []string          `json:"features"`
	PostQuantum    string            `json:"post_quantum"`
	AuthMethods    []string          `json:"auth_methods,omitempty"`
	MaxMessageSize int64             `json:"max_message_size,omitempty"`
	MaxAttachments int               `json:"max_attachments,omitempty"`
	Extensions     map[string]any    `json:"extensions,omitempty"`
}

// FetchConfiguration GETs https://<domain>/.well-known/semp/configuration
// and parses the JSON body. The URI MUST be served over HTTPS; servers
// MUST NOT serve it over plain HTTP (DISCOVERY.md §3).
//
// TODO(DISCOVERY.md §3): implement using net/http.
func FetchConfiguration(ctx context.Context, domain string) (*Configuration, error) {
	_, _ = ctx, domain
	return nil, nil
}
