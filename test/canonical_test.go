package test

import (
	"encoding/json"
	"testing"

	"github.com/semp-dev/semp-go/internal/canonical"
)

// TestCanonicalEnvelopeMinimal validates the canonical envelope serializer
// against VECTORS.md §3.1.
//
// The input envelope contains a non-empty seal.signature and seal.session_mac
// (which the elider must replace with empty strings) and a postmark.hop_count
// of 2 (which the elider must remove). All keys at every nesting level must
// be sorted lexicographically. The expected output is a single canonical JSON
// byte sequence with no whitespace.
func TestCanonicalEnvelopeMinimal(t *testing.T) {
	const input = `{
		"type": "SEMP_ENVELOPE",
		"version": "1.0.0",
		"postmark": {
			"id": "01J4K7P2XVEM3Q8YNZHBRC5T06",
			"session_id": "01J4K7Q0ABCDEFGHJKLMNPQRST",
			"from_domain": "sender.example",
			"to_domain": "recipient.example",
			"expires": "2025-06-10T21:00:00Z",
			"hop_count": 2,
			"extensions": {}
		},
		"seal": {
			"algorithm": "pq-kyber768-x25519",
			"key_id": "abc123def456",
			"signature": "existing-signature-value",
			"session_mac": "existing-mac-value",
			"brief_recipients": {},
			"enclosure_recipients": {},
			"extensions": {}
		},
		"brief": "ZW5jcnlwdGVkLWJyaWVm",
		"enclosure": "ZW5jcnlwdGVkLWVuY2xvc3VyZQ=="
	}`

	const want = `{"brief":"ZW5jcnlwdGVkLWJyaWVm","enclosure":"ZW5jcnlwdGVkLWVuY2xvc3VyZQ==","postmark":{"expires":"2025-06-10T21:00:00Z","extensions":{},"from_domain":"sender.example","id":"01J4K7P2XVEM3Q8YNZHBRC5T06","session_id":"01J4K7Q0ABCDEFGHJKLMNPQRST","to_domain":"recipient.example"},"seal":{"algorithm":"pq-kyber768-x25519","brief_recipients":{},"enclosure_recipients":{},"extensions":{},"key_id":"abc123def456","session_mac":"","signature":""},"type":"SEMP_ENVELOPE","version":"1.0.0"}`

	got := canonicalize(t, input)
	if got != want {
		t.Errorf("canonical mismatch\n  got:  %s\n  want: %s", got, want)
	}
}

// TestCanonicalEnvelopeWithExtensions validates VECTORS.md §3.2: an envelope
// carrying extension entries inside postmark.extensions and populated
// recipient maps inside the seal. Both the extension keys and the recipient
// map keys must be sorted lexicographically.
func TestCanonicalEnvelopeWithExtensions(t *testing.T) {
	const input = `{
		"type": "SEMP_ENVELOPE",
		"version": "1.0.0",
		"postmark": {
			"id": "01JTEST00000000000000000000",
			"session_id": "01JTEST11111111111111111111",
			"from_domain": "alpha.example",
			"to_domain": "beta.example",
			"expires": "2025-07-01T12:00:00Z",
			"extensions": {
				"vendor.example.com/priority": "high",
				"another.example.com/class": "transactional"
			}
		},
		"seal": {
			"algorithm": "x25519-chacha20-poly1305",
			"key_id": "key-fingerprint-xyz",
			"signature": "to-be-replaced",
			"session_mac": "to-be-replaced",
			"brief_recipients": {
				"server-key-fp": "wrapped-K_brief-for-server",
				"client-key-fp": "wrapped-K_brief-for-client"
			},
			"enclosure_recipients": {
				"client-key-fp": "wrapped-K_enclosure-for-client"
			},
			"extensions": {}
		},
		"brief": "YnJpZWYtZGF0YQ==",
		"enclosure": "ZW5jbG9zdXJlLWRhdGE="
	}`

	const want = `{"brief":"YnJpZWYtZGF0YQ==","enclosure":"ZW5jbG9zdXJlLWRhdGE=","postmark":{"expires":"2025-07-01T12:00:00Z","extensions":{"another.example.com/class":"transactional","vendor.example.com/priority":"high"},"from_domain":"alpha.example","id":"01JTEST00000000000000000000","session_id":"01JTEST11111111111111111111","to_domain":"beta.example"},"seal":{"algorithm":"x25519-chacha20-poly1305","brief_recipients":{"client-key-fp":"wrapped-K_brief-for-client","server-key-fp":"wrapped-K_brief-for-server"},"enclosure_recipients":{"client-key-fp":"wrapped-K_enclosure-for-client"},"extensions":{},"key_id":"key-fingerprint-xyz","session_mac":"","signature":""},"type":"SEMP_ENVELOPE","version":"1.0.0"}`

	got := canonicalize(t, input)
	if got != want {
		t.Errorf("canonical mismatch\n  got:  %s\n  want: %s", got, want)
	}
}

// canonicalize parses raw as JSON and runs it through MarshalWithElision
// using the EnvelopeElider, returning the canonical bytes as a string.
func canonicalize(t *testing.T, raw string) string {
	t.Helper()
	var v any
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		t.Fatalf("parse input: %v", err)
	}
	out, err := canonical.MarshalWithElision(v, canonical.EnvelopeElider())
	if err != nil {
		t.Fatalf("MarshalWithElision: %v", err)
	}
	return string(out)
}
