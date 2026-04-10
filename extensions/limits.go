package extensions

// Layer identifies which extension point an `extensions` object belongs to.
// Each layer has its own size limit and visibility rules.
//
// Reference: EXTENSIONS.md §1, §4.1.
type Layer string

// Layer values.
const (
	LayerPostmark    Layer = "postmark"    // public, all routing servers
	LayerSeal        Layer = "seal"        // public, all routing servers
	LayerBrief       Layer = "brief"       // recipient server and client
	LayerEnclosure   Layer = "enclosure"   // recipient client only
	LayerHandshake   Layer = "handshake"   // handshake participants
	LayerDiscovery   Layer = "discovery"   // any querying server
	LayerBlockEntry  Layer = "block_entry" // local server only
)

// Per-layer maximum size of the serialized JSON `extensions` object, in
// bytes. These are the upper bounds defined in EXTENSIONS.md §4.1; servers
// MUST NOT enforce stricter limits below these values without breaking
// interoperability.
const (
	MaxBytesPostmark  = 4 * 1024  // 4 KB  — parsed by every routing server
	MaxBytesSeal      = 4 * 1024  // 4 KB  — parsed by every routing server
	MaxBytesBrief     = 16 * 1024 // 16 KB — parsed by recipient server + client
	MaxBytesEnclosure = 64 * 1024 // 64 KB — parsed by recipient client only
)

// MaxBytesFor returns the maximum permitted serialized size of an
// `extensions` object at the given layer. Layers without an explicit limit
// in the spec (handshake, discovery, block_entry) return MaxBytesBrief as a
// reasonable default; the spec does not currently constrain them.
//
// TODO(EXTENSIONS.md §4.1): revisit handshake / discovery limits when those
// are added to the spec.
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
	default:
		return MaxBytesBrief
	}
}

// MaxKeyLength is the maximum permitted length of an extension key in
// UTF-8 bytes (EXTENSIONS.md §2.3).
const MaxKeyLength = 128
