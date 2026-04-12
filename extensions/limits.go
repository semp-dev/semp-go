package extensions

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	semp "semp.dev/semp-go"
)

// Layer identifies which extension point an `extensions` object
// belongs to. Each layer has its own size limit and visibility rules.
//
// Reference: EXTENSIONS.md §1, §4.1.
type Layer string

// Layer values.
const (
	LayerPostmark   Layer = "postmark"    // public, all routing servers
	LayerSeal       Layer = "seal"        // public, all routing servers
	LayerBrief      Layer = "brief"       // recipient server and client
	LayerEnclosure  Layer = "enclosure"   // recipient client only
	LayerHandshake  Layer = "handshake"   // handshake participants
	LayerDiscovery  Layer = "discovery"   // any querying server
	LayerBlockEntry Layer = "block_entry" // local server only
)

// Per-layer maximum size of the serialized JSON `extensions` object,
// in bytes. These are the exact values from EXTENSIONS.md §4.1;
// servers MUST NOT enforce stricter limits below these without
// breaking interoperability.
const (
	MaxBytesPostmark  = 4 * 1024  // 4 KB  — parsed by every routing server
	MaxBytesSeal      = 4 * 1024  // 4 KB  — parsed by every routing server
	MaxBytesBrief     = 16 * 1024 // 16 KB — parsed by recipient server + client
	MaxBytesEnclosure = 64 * 1024 // 64 KB — parsed by recipient client only

	// MaxBytesHandshake is the default limit applied to
	// `init.extensions` and `response.extensions` objects. The spec
	// does not set an explicit limit for the handshake layer; we
	// reuse the brief ceiling (16 KB) because handshake extensions
	// are parsed by both handshake participants and capability
	// negotiation blocks can legitimately carry multiple feature
	// flags.
	MaxBytesHandshake = 16 * 1024

	// MaxBytesDiscovery is the default limit applied to
	// `configuration.extensions` objects. Same rationale as
	// MaxBytesHandshake: the spec does not set an explicit limit
	// and discovery is fetched by any querying server, so 16 KB
	// is a reasonable ceiling that accommodates feature catalogs.
	MaxBytesDiscovery = 16 * 1024

	// MaxBytesBlockEntry is the default limit for block-list
	// entry extensions. These never leave the local server
	// (DELIVERY.md §4.2) so the limit exists solely as an
	// abuse-prevention ceiling against oversized stored state.
	MaxBytesBlockEntry = 16 * 1024
)

// MaxKeyLength is the maximum permitted length of an extension key
// in UTF-8 bytes (EXTENSIONS.md §2.3).
const MaxKeyLength = 128

// MaxBytesFor returns the maximum permitted serialized size of an
// `extensions` object at the given layer. An unknown layer is
// treated as the most permissive value (MaxBytesEnclosure) so new
// layer identifiers don't accidentally cause false positives —
// callers that want strict checking pass a known Layer constant.
func MaxBytesFor(layer Layer) int {
	switch layer {
	case LayerPostmark:
		return MaxBytesPostmark
	case LayerSeal:
		return MaxBytesSeal
	case LayerBrief:
		return MaxBytesBrief
	case LayerEnclosure:
		return MaxBytesEnclosure
	case LayerHandshake:
		return MaxBytesHandshake
	case LayerDiscovery:
		return MaxBytesDiscovery
	case LayerBlockEntry:
		return MaxBytesBlockEntry
	default:
		return MaxBytesEnclosure
	}
}

// -----------------------------------------------------------------------------
// Validation
// -----------------------------------------------------------------------------

// SizeError is returned by ValidateSize when an `extensions` object
// exceeds the per-layer ceiling. Carries the layer, actual byte
// count, and maximum so callers can surface rich diagnostic detail.
type SizeError struct {
	Layer Layer
	Size  int
	Max   int
}

func (e *SizeError) Error() string {
	return fmt.Sprintf("extensions: %s layer object is %d bytes, exceeds %d-byte limit",
		e.Layer, e.Size, e.Max)
}

// ReasonCode returns the SEMP reason code semp.ReasonExtensionSizeExceeded
// so callers that need to map this error to a wire-level rejection
// (per EXTENSIONS.md §4.2) don't have to duplicate the mapping.
func (e *SizeError) ReasonCode() semp.ReasonCode {
	return semp.ReasonExtensionSizeExceeded
}

// UnsupportedError is returned by Validate when an extension marked
// `required: true` does not appear in the registry the caller is
// validating against. Carries the offending key so the caller can
// populate the wire-level rejection's key field per EXTENSIONS.md
// §3.1.
type UnsupportedError struct {
	Key   string
	Layer Layer
}

func (e *UnsupportedError) Error() string {
	return fmt.Sprintf("extensions: %s layer required extension %q is not supported",
		e.Layer, e.Key)
}

// ReasonCode returns the SEMP reason code semp.ReasonExtensionUnsupported
// so callers can map this error to a wire-level rejection.
func (e *UnsupportedError) ReasonCode() semp.ReasonCode {
	return semp.ReasonExtensionUnsupported
}

// KeyError is returned by Validate when an extension key itself is
// malformed (wrong namespace prefix, disallowed characters, etc.).
// Wraps the underlying validation error from ValidateKey.
type KeyError struct {
	Key   string
	Layer Layer
	Err   error
}

func (e *KeyError) Error() string {
	return fmt.Sprintf("extensions: %s layer key %q: %v", e.Layer, e.Key, e.Err)
}

func (e *KeyError) Unwrap() error { return e.Err }

// ValidateSize reports an error if the serialized JSON form of m
// exceeds the maximum size for layer. The check matches
// EXTENSIONS.md §4.2 exactly: marshal to canonical JSON, compare
// byte length to the layer ceiling.
//
// An empty or nil map returns nil — the empty JSON object `{}` is
// 2 bytes and fits every layer. Malformed maps that json.Marshal
// rejects return the underlying error wrapped with context.
func ValidateSize(layer Layer, m Map) error {
	if len(m) == 0 {
		return nil
	}
	raw, err := marshalExtensions(m)
	if err != nil {
		return err
	}
	maxBytes := MaxBytesFor(layer)
	if len(raw) > maxBytes {
		return &SizeError{Layer: layer, Size: len(raw), Max: maxBytes}
	}
	return nil
}

// Validate performs full structural validation of m against the
// given registry and layer:
//
//  1. Every key passes ValidateKey.
//  2. Every required extension appears in registry (for core
//     semp.dev/ keys) — vendor and x- keys are allowed to be
//     required even when not in the registry because the registry
//     is authoritative only for the semp.dev/ namespace.
//  3. The serialized size fits the layer ceiling.
//
// A nil registry skips the registry check entirely (treating it as
// "accept any syntactically valid key"). A nil or empty map
// short-circuits to success.
//
// Errors are returned as *KeyError, *UnsupportedError, or
// *SizeError respectively so callers can match on type and surface
// the right wire-level reason code.
func Validate(registry *Registry, layer Layer, m Map) error {
	if len(m) == 0 {
		return nil
	}
	// Walk keys in sorted order so error reporting is deterministic
	// — otherwise two servers would report different "first failing
	// key" for the same malformed input, which complicates triage.
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, key := range keys {
		if err := ValidateKey(key); err != nil {
			return &KeyError{Key: key, Layer: layer, Err: err}
		}
		entry := m[key]
		if !entry.Required {
			continue
		}
		// Required extension: must be registered OR live in a
		// namespace the registry doesn't govern. Only semp.dev/
		// keys require registry presence. Vendor and x- keys
		// are at the operator's own risk.
		if registry != nil && strings.HasPrefix(key, NamespacePrefixCore) {
			if _, ok := registry.Lookup(key); !ok {
				return &UnsupportedError{Key: key, Layer: layer}
			}
		}
		// Optional: also verify the registered layer matches. A
		// registered extension MAY only be used at the layers
		// it was registered for; using it elsewhere is a spec
		// violation per EXTENSIONS.md §5.2 ("Layer(s): Which
		// extension points the extension occupies").
		if registry != nil && strings.HasPrefix(key, NamespacePrefixCore) {
			if entry, ok := registry.Lookup(key); ok {
				if !entry.SupportsLayer(layer) {
					return &UnsupportedError{Key: key, Layer: layer}
				}
			}
		}
	}
	return ValidateSize(layer, m)
}

// marshalExtensions returns the canonical-ish byte form used to
// measure `extensions` object size. We use encoding/json with sorted
// keys via an intermediate map[string]Entry — the actual canonical
// serializer in internal/canonical also sorts keys, so this
// measurement matches what the seal signer produces to within a few
// bytes (whitespace differences only). Since the per-layer ceilings
// have 4–64 KB of headroom over any realistic payload, the small
// difference is in the noise.
func marshalExtensions(m Map) ([]byte, error) {
	if len(m) == 0 {
		return []byte("{}"), nil
	}
	// Sort keys so the produced bytes are deterministic across
	// runs and platforms — encoding/json on a map does not
	// guarantee key order.
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	ordered := make([]struct {
		k string
		v Entry
	}, 0, len(keys))
	for _, k := range keys {
		ordered = append(ordered, struct {
			k string
			v Entry
		}{k: k, v: m[k]})
	}
	// Use encoding/json directly — we can't marshal the anonymous
	// slice into a JSON object, so reconstruct manually with a
	// small buffer.
	var out []byte
	out = append(out, '{')
	for i, kv := range ordered {
		if i > 0 {
			out = append(out, ',')
		}
		kBytes, err := json.Marshal(kv.k)
		if err != nil {
			return nil, fmt.Errorf("extensions: marshal key: %w", err)
		}
		out = append(out, kBytes...)
		out = append(out, ':')
		vBytes, err := json.Marshal(kv.v)
		if err != nil {
			return nil, fmt.Errorf("extensions: marshal value: %w", err)
		}
		out = append(out, vBytes...)
	}
	out = append(out, '}')
	return out, nil
}
