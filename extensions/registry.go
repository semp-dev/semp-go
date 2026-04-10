package extensions

// Status is an extension lifecycle stage. Extensions move through these
// states as they progress from individual experimentation toward inclusion
// in the protocol core.
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

// RegistryEntry describes a registered extension. The registry holds one
// entry per `semp.org/<name>` identifier; vendor extensions
// (`vendor.example.com/<name>`) and experimental extensions (`x-<name>`) do
// not require registration.
//
// Reference: EXTENSIONS.md §5.2.
type RegistryEntry struct {
	// Identifier is the namespaced extension key, e.g. "semp.org/message-expiry".
	Identifier string

	// Status is the current lifecycle stage.
	Status Status

	// Layers lists the extension points this extension may occupy.
	Layers []Layer

	// RequiredCapable reports whether this extension may legitimately be
	// marked `required: true` in production traffic. Extensions that have
	// not yet achieved broad adoption SHOULD NOT be required at public
	// layers (postmark, seal); see EXTENSIONS.md §3.3.
	RequiredCapable bool

	// Specification is a free-form reference to the defining document.
	Specification string

	// Implementations is the count of independent implementations known to
	// support this extension.
	Implementations int

	// Introduced names the protocol version in which this extension was
	// first registered.
	Introduced string

	// Deprecated names the protocol version in which this extension was
	// deprecated, if applicable. Empty for extensions still in good standing.
	Deprecated string
}

// Registry is the in-memory extension registry. The skeleton holds an empty
// registry; production builds load entries from a generated table or from
// configuration.
//
// TODO(EXTENSIONS.md §5): populate from a code-generated table at build time
// or load from a YAML manifest at startup.
type Registry struct {
	entries map[string]RegistryEntry
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{entries: map[string]RegistryEntry{}}
}

// Lookup returns the entry for identifier and a bool reporting whether one
// exists. Vendor and experimental extensions are never registered, so
// callers MUST treat the bool as informational, not as a validity gate.
func (r *Registry) Lookup(identifier string) (RegistryEntry, bool) {
	if r == nil {
		return RegistryEntry{}, false
	}
	entry, ok := r.entries[identifier]
	return entry, ok
}

// Register adds entry to the registry, replacing any prior entry with the
// same identifier.
func (r *Registry) Register(entry RegistryEntry) {
	if r.entries == nil {
		r.entries = map[string]RegistryEntry{}
	}
	r.entries[entry.Identifier] = entry
}

// ValidateKey reports an error if identifier is not a syntactically valid
// extension key per EXTENSIONS.md §2.3:
//
//   - one of the three permitted namespace prefixes (semp.org/, vendor
//     domain followed by /, or x-),
//   - no whitespace, no path separators beyond the single namespace slash,
//     no control characters,
//   - length up to MaxKeyLength UTF-8 bytes.
//
// TODO(EXTENSIONS.md §2.3): implement strict validation including the
// vendor-domain syntax check.
func ValidateKey(identifier string) error {
	_ = identifier
	return nil
}
