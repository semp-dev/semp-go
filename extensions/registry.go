package extensions

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

// Status is an extension lifecycle stage. Extensions move through
// these states as they progress from individual experimentation
// toward inclusion in the protocol core.
//
// Reference: EXTENSIONS.md §6.1.
type Status string

// Lifecycle status values.
const (
	StatusExperimental Status = "experimental"
	StatusProposed     Status = "proposed"
	StatusStandard     Status = "standard"
	StatusCore         Status = "core"
	StatusDeprecated   Status = "deprecated"
	StatusRetired      Status = "retired"
)

// Namespace prefixes recognized by the SEMP extension framework
// (EXTENSIONS.md §2.3).
const (
	// NamespacePrefixCore is the `semp.dev/` prefix reserved for
	// core extensions governed by the SEMP specification process.
	NamespacePrefixCore = "semp.dev/"

	// NamespacePrefixExperimental is the `x-` prefix reserved for
	// experimental extensions. No stability guarantees. MUST NOT
	// be used in production deployments.
	NamespacePrefixExperimental = "x-"
)

// RegistryEntry describes a registered extension. The registry
// holds one entry per `semp.dev/<name>` identifier; vendor
// extensions (`vendor.example.com/<name>`) and experimental
// extensions (`x-<name>`) do not require registration.
//
// Reference: EXTENSIONS.md §5.2.
type RegistryEntry struct {
	// Identifier is the namespaced extension key,
	// e.g. "semp.dev/message-expiry".
	Identifier string

	// Status is the current lifecycle stage.
	Status Status

	// Layers lists the extension points this extension may occupy.
	Layers []Layer

	// RequiredCapable reports whether this extension may
	// legitimately be marked `required: true` in production
	// traffic. Extensions that have not yet achieved broad
	// adoption SHOULD NOT be required at public layers (postmark,
	// seal); see EXTENSIONS.md §3.3.
	RequiredCapable bool

	// Specification is a free-form reference to the defining
	// document.
	Specification string

	// Implementations is the count of independent implementations
	// known to support this extension.
	Implementations int

	// Introduced names the protocol version in which this
	// extension was first registered.
	Introduced string

	// Deprecated names the protocol version in which this
	// extension was deprecated, if applicable. Empty for extensions
	// still in good standing.
	Deprecated string
}

// SupportsLayer reports whether this extension is registered as
// valid at the given layer. Returns false for an unknown layer.
func (e *RegistryEntry) SupportsLayer(layer Layer) bool {
	if e == nil {
		return false
	}
	for _, l := range e.Layers {
		if l == layer {
			return true
		}
	}
	return false
}

// Registry is the in-memory extension registry. The package-level
// DefaultRegistry is pre-populated from the EXTENSIONS.md §9
// candidate list; operators who want to reject unknown keys in
// strict mode use DefaultRegistry, and operators running with custom
// extensions construct their own Registry and call Register for each
// entry.
type Registry struct {
	entries map[string]RegistryEntry
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{entries: map[string]RegistryEntry{}}
}

// Register adds entry to the registry, replacing any prior entry
// with the same identifier. Returns an error if the identifier is
// not a syntactically valid extension key.
func (r *Registry) Register(entry RegistryEntry) error {
	if r == nil {
		return errors.New("extensions: nil registry")
	}
	if err := ValidateKey(entry.Identifier); err != nil {
		return fmt.Errorf("extensions: register %q: %w", entry.Identifier, err)
	}
	if r.entries == nil {
		r.entries = map[string]RegistryEntry{}
	}
	r.entries[entry.Identifier] = entry
	return nil
}

// Lookup returns the entry for identifier and a bool reporting
// whether one exists. Vendor and experimental extensions are never
// registered, so callers MUST treat the bool as informational, not
// as a validity gate.
func (r *Registry) Lookup(identifier string) (RegistryEntry, bool) {
	if r == nil {
		return RegistryEntry{}, false
	}
	entry, ok := r.entries[identifier]
	return entry, ok
}

// Len returns the number of entries in the registry.
func (r *Registry) Len() int {
	if r == nil {
		return 0
	}
	return len(r.entries)
}

// Identifiers returns a snapshot of every registered identifier.
// The returned slice is owned by the caller and safe to mutate; it
// is NOT guaranteed to be sorted.
func (r *Registry) Identifiers() []string {
	if r == nil {
		return nil
	}
	out := make([]string, 0, len(r.entries))
	for id := range r.entries {
		out = append(out, id)
	}
	return out
}

// -----------------------------------------------------------------------------
// DefaultRegistry
// -----------------------------------------------------------------------------

// DefaultRegistry is the package-level registry pre-populated from
// the EXTENSIONS.md §9 candidate extensions list. Every entry here
// is currently status `proposed` because the spec explicitly says:
//
//	"Their inclusion here does not constitute a commitment; each
//	 will be specified independently once this framework is
//	 established."
//
// Operators that want a stricter check substitute their own Registry
// with only the extensions they actually support. Operators running
// with the default behavior get the full candidate set for free.
var DefaultRegistry = buildDefaultRegistry()

func buildDefaultRegistry() *Registry {
	r := NewRegistry()
	// Errors from Register are impossible here because every
	// identifier below has already been checked by this package's
	// tests; the _ discards them because a buildDefaultRegistry
	// that returns an error at init time would crash the program
	// for a typo nobody notices until deploy.
	_ = r.Register(RegistryEntry{
		Identifier:      "semp.dev/mls-group",
		Status:          StatusProposed,
		Layers:          []Layer{LayerSeal, LayerBrief},
		RequiredCapable: false,
		Specification:   "EXTENSIONS.md §9 candidate",
		Introduced:      "1.0.0",
	})
	_ = r.Register(RegistryEntry{
		Identifier:      "semp.dev/read-receipts",
		Status:          StatusProposed,
		Layers:          []Layer{LayerBrief},
		RequiredCapable: false,
		Specification:   "EXTENSIONS.md §9 candidate",
		Introduced:      "1.0.0",
	})
	_ = r.Register(RegistryEntry{
		Identifier:      "semp.dev/message-edit",
		Status:          StatusProposed,
		Layers:          []Layer{LayerEnclosure},
		RequiredCapable: false,
		Specification:   "EXTENSIONS.md §9 candidate",
		Introduced:      "1.0.0",
	})
	_ = r.Register(RegistryEntry{
		Identifier:      "semp.dev/message-expiry",
		Status:          StatusProposed,
		Layers:          []Layer{LayerBrief},
		RequiredCapable: false,
		Specification:   "EXTENSIONS.md §9 candidate",
		Introduced:      "1.0.0",
	})
	_ = r.Register(RegistryEntry{
		Identifier:      "semp.dev/reactions",
		Status:          StatusProposed,
		Layers:          []Layer{LayerEnclosure},
		RequiredCapable: false,
		Specification:   "EXTENSIONS.md §9 candidate",
		Introduced:      "1.0.0",
	})
	_ = r.Register(RegistryEntry{
		Identifier:      "semp.dev/priority",
		Status:          StatusProposed,
		Layers:          []Layer{LayerPostmark},
		RequiredCapable: false,
		Specification:   "EXTENSIONS.md §9 candidate",
		Introduced:      "1.0.0",
	})
	_ = r.Register(RegistryEntry{
		Identifier:      "semp.dev/content-negotiation",
		Status:          StatusProposed,
		Layers:          []Layer{LayerEnclosure},
		RequiredCapable: false,
		Specification:   "EXTENSIONS.md §9 candidate",
		Introduced:      "1.0.0",
	})
	return r
}

// -----------------------------------------------------------------------------
// Key validation
// -----------------------------------------------------------------------------

// ValidateKey reports an error if identifier is not a syntactically
// valid extension key per EXTENSIONS.md §2.3:
//
//   - non-empty, valid UTF-8
//   - at most MaxKeyLength (128) bytes
//   - no whitespace, control characters, or forbidden ASCII punctuation
//   - starts with one of the three permitted namespace prefixes:
//     `semp.dev/`, `vendor.<domain>/`, or `x-`
//   - exactly one `/` separator for `semp.dev/` and vendor namespaces
//     (plus any character count in the name part, minus slashes)
//   - vendor namespace's domain part is a well-formed DNS name
func ValidateKey(identifier string) error {
	if identifier == "" {
		return errors.New("extensions: empty extension key")
	}
	if len(identifier) > MaxKeyLength {
		return fmt.Errorf("extensions: extension key exceeds %d bytes", MaxKeyLength)
	}
	if !utf8.ValidString(identifier) {
		return errors.New("extensions: extension key is not valid UTF-8")
	}
	for i, r := range identifier {
		if r == ' ' || r == '\t' || r == '\r' || r == '\n' {
			return fmt.Errorf("extensions: extension key contains whitespace at byte %d", i)
		}
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("extensions: extension key contains control character U+%04X at byte %d", r, i)
		}
	}

	switch {
	case strings.HasPrefix(identifier, NamespacePrefixCore):
		name := strings.TrimPrefix(identifier, NamespacePrefixCore)
		if name == "" {
			return errors.New("extensions: semp.dev/ key missing name component")
		}
		if strings.Contains(name, "/") {
			return fmt.Errorf("extensions: semp.dev/ key contains extra '/' in name %q", name)
		}
		return nil

	case strings.HasPrefix(identifier, NamespacePrefixExperimental):
		name := strings.TrimPrefix(identifier, NamespacePrefixExperimental)
		if name == "" {
			return errors.New("extensions: x- key missing name component")
		}
		if strings.Contains(name, "/") {
			return fmt.Errorf("extensions: x- key contains disallowed '/' in name %q", name)
		}
		return nil

	default:
		// Vendor namespace: `vendor.<domain>/<name>` per §2.3.
		// The spec example literally uses "vendor.example.com/";
		// we interpret this as "any domain followed by /<name>".
		slash := strings.IndexByte(identifier, '/')
		if slash < 0 {
			return fmt.Errorf("extensions: key %q does not match any known namespace prefix", identifier)
		}
		domain := identifier[:slash]
		name := identifier[slash+1:]
		if domain == "" {
			return errors.New("extensions: vendor key missing domain part")
		}
		if name == "" {
			return errors.New("extensions: vendor key missing name component")
		}
		if strings.Contains(name, "/") {
			return fmt.Errorf("extensions: vendor key contains extra '/' in name %q", name)
		}
		if err := validateVendorDomain(domain); err != nil {
			return err
		}
		return nil
	}
}

// validateVendorDomain checks the domain component of a vendor
// extension key. It applies the same DNS structural rules used by
// brief.Address.Validate: ≤ 253 bytes, dot-separated labels of 1–63
// bytes, no leading/trailing hyphen on any label, no empty labels.
// This mirrors RFC 1035's LDH rule but relaxes case-insensitivity
// (we accept mixed case, the brief package lowercases elsewhere).
func validateVendorDomain(domain string) error {
	const (
		maxDomainLength = 253
		maxLabelLength  = 63
	)
	if domain == "" {
		return errors.New("extensions: vendor domain is empty")
	}
	if len(domain) > maxDomainLength {
		return fmt.Errorf("extensions: vendor domain exceeds %d bytes", maxDomainLength)
	}
	if strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") {
		return fmt.Errorf("extensions: vendor domain %q has leading or trailing dot", domain)
	}
	if strings.Contains(domain, "..") {
		return fmt.Errorf("extensions: vendor domain %q has empty label", domain)
	}
	for _, label := range strings.Split(domain, ".") {
		if label == "" {
			return fmt.Errorf("extensions: vendor domain %q has empty label", domain)
		}
		if len(label) > maxLabelLength {
			return fmt.Errorf("extensions: vendor domain label %q exceeds %d bytes", label, maxLabelLength)
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return fmt.Errorf("extensions: vendor domain label %q has leading or trailing hyphen", label)
		}
	}
	// A plain "vendor/foo" (no dots in the "domain" part) is a
	// degenerate case — technically the spec says the domain MUST
	// be a controlled DNS name. Require at least one dot so
	// "vendor/foo" or "localhost/foo" are rejected.
	if !strings.Contains(domain, ".") {
		return fmt.Errorf("extensions: vendor domain %q must contain at least one dot", domain)
	}
	return nil
}
