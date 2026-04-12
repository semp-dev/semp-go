package extensions_test

import (
	"errors"
	"strings"
	"testing"

	"semp.dev/semp-go/extensions"
)

// -----------------------------------------------------------------------------
// ValidateKey
// -----------------------------------------------------------------------------

// TestValidateKeyAcceptsAllNamespaces confirms each namespace prefix
// permitted by EXTENSIONS.md §2.3 is accepted.
func TestValidateKeyAcceptsAllNamespaces(t *testing.T) {
	valid := []string{
		"semp.dev/priority",
		"semp.dev/message-expiry",
		"semp.dev/mls-group",
		"x-experimental-feature",
		"x-adhoc",
		"vendor.example.com/feature",
		"vendor.example.com/very-long-feature-name",
		"vendor.example.co.uk/feature",
		"vendor.sub.example.com/nested-feature",
	}
	for _, k := range valid {
		if err := extensions.ValidateKey(k); err != nil {
			t.Errorf("ValidateKey(%q) = %v, want nil", k, err)
		}
	}
}

// TestValidateKeyRejects exercises every structural failure path in
// EXTENSIONS.md §2.3.
func TestValidateKeyRejects(t *testing.T) {
	tests := []struct {
		name    string
		key     string
		wantSub string
	}{
		{"empty", "", "empty extension key"},
		{"whitespace", "semp.dev/foo bar", "whitespace"},
		{"tab", "semp.dev/foo\tbar", "whitespace"},
		{"newline", "semp.dev/foo\nbar", "whitespace"},
		{"control byte", "semp.dev/foo\x00bar", "control character"},
		{"oversize", "semp.dev/" + strings.Repeat("a", 200), "exceeds"},
		{"invalid utf8", "semp.dev/\xff\xfe", "not valid UTF-8"},
		{"no prefix", "random-key", "does not match any known namespace"},
		{"empty semp.dev name", "semp.dev/", "missing name component"},
		{"semp.dev nested", "semp.dev/foo/bar", "extra '/'"},
		{"empty x-", "x-", "missing name component"},
		{"x- with slash", "x-foo/bar", "disallowed '/'"},
		{"empty vendor name", "example.com/", "missing name component"},
		{"no dot vendor", "vendor/foo", "must contain at least one dot"},
		{"localhost-ish", "localhost/foo", "must contain at least one dot"},
		{"vendor leading dot", ".example.com/foo", "leading or trailing dot"},
		{"vendor trailing dot", "example.com./foo", "leading or trailing dot"},
		{"vendor empty label", "example..com/foo", "empty label"},
		{"vendor leading hyphen label", "-example.com/foo", "leading or trailing hyphen"},
		{"vendor trailing hyphen label", "example-.com/foo", "leading or trailing hyphen"},
		{"vendor nested name", "example.com/foo/bar", "extra '/'"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := extensions.ValidateKey(tc.key)
			if err == nil {
				t.Fatalf("ValidateKey(%q) = nil, want error", tc.key)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("ValidateKey(%q) = %v, want substring %q", tc.key, err, tc.wantSub)
			}
		})
	}
}

// -----------------------------------------------------------------------------
// Registry
// -----------------------------------------------------------------------------

// TestRegistryRegisterLookup exercises the happy path.
func TestRegistryRegisterLookup(t *testing.T) {
	r := extensions.NewRegistry()
	entry := extensions.RegistryEntry{
		Identifier: "semp.dev/test-extension",
		Status:     extensions.StatusStandard,
		Layers:     []extensions.Layer{extensions.LayerBrief},
		Introduced: "1.0.0",
	}
	if err := r.Register(entry); err != nil {
		t.Fatalf("Register: %v", err)
	}
	got, ok := r.Lookup("semp.dev/test-extension")
	if !ok {
		t.Fatal("Lookup returned false for registered entry")
	}
	if got.Status != extensions.StatusStandard {
		t.Errorf("Status = %s, want standard", got.Status)
	}
	if !got.SupportsLayer(extensions.LayerBrief) {
		t.Error("SupportsLayer(brief) = false, want true")
	}
	if got.SupportsLayer(extensions.LayerPostmark) {
		t.Error("SupportsLayer(postmark) = true, want false")
	}
}

// TestRegistryRejectsInvalidKey confirms Register validates the
// identifier before storing.
func TestRegistryRejectsInvalidKey(t *testing.T) {
	r := extensions.NewRegistry()
	err := r.Register(extensions.RegistryEntry{
		Identifier: "not a valid key",
		Status:     extensions.StatusStandard,
	})
	if err == nil {
		t.Error("Register should reject invalid key")
	}
}

// TestRegistryLen + Identifiers exercise the size + listing helpers.
func TestRegistryLenIdentifiers(t *testing.T) {
	r := extensions.NewRegistry()
	if r.Len() != 0 {
		t.Errorf("empty Len = %d, want 0", r.Len())
	}
	ids := []string{
		"semp.dev/one",
		"semp.dev/two",
		"semp.dev/three",
	}
	for _, id := range ids {
		_ = r.Register(extensions.RegistryEntry{Identifier: id, Status: extensions.StatusProposed})
	}
	if r.Len() != 3 {
		t.Errorf("Len = %d, want 3", r.Len())
	}
	got := r.Identifiers()
	if len(got) != 3 {
		t.Errorf("Identifiers length = %d, want 3", len(got))
	}
}

// TestRegistryNilSafe confirms methods on a nil *Registry are no-ops
// that don't panic.
func TestRegistryNilSafe(t *testing.T) {
	var r *extensions.Registry
	if r.Len() != 0 {
		t.Error("nil Len should be 0")
	}
	if _, ok := r.Lookup("semp.dev/foo"); ok {
		t.Error("nil Lookup should return false")
	}
	if got := r.Identifiers(); got != nil {
		t.Error("nil Identifiers should be nil")
	}
}

// -----------------------------------------------------------------------------
// DefaultRegistry
// -----------------------------------------------------------------------------

// TestDefaultRegistryPopulated confirms the package-level registry
// ships with every extension named in EXTENSIONS.md §9.
func TestDefaultRegistryPopulated(t *testing.T) {
	wantIDs := []string{
		"semp.dev/mls-group",
		"semp.dev/read-receipts",
		"semp.dev/message-edit",
		"semp.dev/message-expiry",
		"semp.dev/reactions",
		"semp.dev/priority",
		"semp.dev/content-negotiation",
	}
	for _, id := range wantIDs {
		entry, ok := extensions.DefaultRegistry.Lookup(id)
		if !ok {
			t.Errorf("DefaultRegistry missing %q", id)
			continue
		}
		if entry.Status != extensions.StatusProposed {
			t.Errorf("%s status = %s, want proposed", id, entry.Status)
		}
		if len(entry.Layers) == 0 {
			t.Errorf("%s has no Layers set", id)
		}
	}
}

// TestDefaultRegistryEntryLayers spot-checks the layer assignments
// against the EXTENSIONS.md §9 candidate table.
func TestDefaultRegistryEntryLayers(t *testing.T) {
	tests := []struct {
		id    string
		layer extensions.Layer
	}{
		{"semp.dev/priority", extensions.LayerPostmark},
		{"semp.dev/read-receipts", extensions.LayerBrief},
		{"semp.dev/reactions", extensions.LayerEnclosure},
		{"semp.dev/message-expiry", extensions.LayerBrief},
	}
	for _, tc := range tests {
		t.Run(tc.id, func(t *testing.T) {
			entry, ok := extensions.DefaultRegistry.Lookup(tc.id)
			if !ok {
				t.Fatalf("missing %s", tc.id)
			}
			if !entry.SupportsLayer(tc.layer) {
				t.Errorf("%s does not support %s", tc.id, tc.layer)
			}
		})
	}
}

// -----------------------------------------------------------------------------
// SupportsLayer edge cases
// -----------------------------------------------------------------------------

// TestSupportsLayerNilEntry ensures the method is nil-safe.
func TestSupportsLayerNilEntry(t *testing.T) {
	var e *extensions.RegistryEntry
	if e.SupportsLayer(extensions.LayerBrief) {
		t.Error("nil entry should never support any layer")
	}
}

// TestValidateKeyDoesNotPanicOnWeirdness feeds ValidateKey a handful
// of pathological inputs to confirm no panics.
func TestValidateKeyDoesNotPanicOnWeirdness(t *testing.T) {
	inputs := []string{
		"semp.dev/\r\n",
		"\x00",
		strings.Repeat("/", 64),
		"semp.dev/\xff",
		"vendor./foo",
	}
	for _, in := range inputs {
		// We just want to make sure ValidateKey returns (nil or
		// error) without panicking — errors.New is a no-op.
		_ = errors.New(in)
		_ = extensions.ValidateKey(in)
	}
}
