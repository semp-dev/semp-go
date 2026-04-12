package discovery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// WellKnownPath is the canonical path for SEMP capability discovery via
// HTTPS (DISCOVERY.md §3).
const WellKnownPath = "/.well-known/semp/configuration"

// WellKnownMaxBytes caps the well-known response body we'll accept
// from a remote server. 64 KiB is large enough for any reasonable
// capability document (including rich extension maps) without letting
// a hostile server feed us gigabytes.
const WellKnownMaxBytes int64 = 64 * 1024

// Configuration is the parsed body of the well-known configuration URI
// (DISCOVERY.md §3.1).
type Configuration struct {
	Version        string            `json:"version"`
	Endpoints      map[string]string `json:"endpoints"`
	Features       []string          `json:"features"`
	PostQuantum    string            `json:"post_quantum"`
	AuthMethods    []string          `json:"auth_methods,omitempty"`
	MaxEnvelopeSize int64             `json:"max_envelope_size,omitempty"`
	MaxAttachments int               `json:"max_attachments,omitempty"`
	Extensions     map[string]any    `json:"extensions,omitempty"`
}

// FetchConfiguration GETs https://<domain>/.well-known/semp/configuration
// and parses the JSON body. The URI MUST be served over HTTPS; servers
// MUST NOT serve it over plain HTTP (DISCOVERY.md §3).
//
// Uses http.DefaultClient with a 10-second timeout. For tests or
// deployments that need a custom HTTP client (e.g. httptest's
// server, a proxy, or a pinned cert pool), use FetchConfigurationWith.
func FetchConfiguration(ctx context.Context, domain string) (*Configuration, error) {
	return FetchConfigurationWith(ctx, &http.Client{Timeout: 10 * time.Second}, "https://"+domain+WellKnownPath)
}

// FetchConfigurationWith is the injectable variant of
// FetchConfiguration. The `url` argument lets tests point at an
// httptest server regardless of the usual https:// requirement.
//
// The URL's scheme is NOT enforced here — production code should
// only ever pass an https:// URL, but tests need to pass http:// to
// httptest-spun servers.
func FetchConfigurationWith(ctx context.Context, client *http.Client, url string) (*Configuration, error) {
	if client == nil {
		return nil, errors.New("discovery: nil HTTP client")
	}
	if url == "" {
		return nil, errors.New("discovery: empty well-known URL")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("discovery: build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("discovery: fetch %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("discovery: well-known URI %s returned %d", url, resp.StatusCode)
	}
	// Permissive on content-type — some servers return application/octet-stream
	// for .json paths. We still require JSON on the wire, but we don't
	// reject the response for Content-Type alone.
	ct := resp.Header.Get("Content-Type")
	if ct != "" && !strings.Contains(ct, "json") && !strings.Contains(ct, "octet-stream") {
		return nil, fmt.Errorf("discovery: well-known URI unexpected content-type %q", ct)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, WellKnownMaxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("discovery: read body: %w", err)
	}
	if int64(len(body)) > WellKnownMaxBytes {
		return nil, fmt.Errorf("discovery: well-known URI body exceeds %d bytes", WellKnownMaxBytes)
	}
	var cfg Configuration
	if err := json.Unmarshal(body, &cfg); err != nil {
		return nil, fmt.Errorf("discovery: parse configuration: %w", err)
	}
	if cfg.Version == "" {
		return nil, errors.New("discovery: configuration missing version")
	}
	if len(cfg.Endpoints) == 0 {
		return nil, errors.New("discovery: configuration missing endpoints")
	}
	return &cfg, nil
}
