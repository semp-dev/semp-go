package extensions

// Entry is a single extension entry as it appears on the wire. Every entry
// in any `extensions` object MUST conform to this shape (EXTENSIONS.md §2.1):
//
//	{
//	    "required": false,
//	    "data": { ... extension-specific payload ... }
//	}
//
// The `required` flag is the criticality signal (EXTENSIONS.md §3): if true
// and the recipient does not understand the extension, the recipient MUST
// reject the containing message with reason code `extension_unsupported` and
// surface the unrecognized key in the rejection.
type Entry struct {
	// Required marks this extension as critical. A recipient that does not
	// understand a required extension MUST reject the containing message.
	Required bool `json:"required"`

	// Data is the extension-specific payload. Its structure is defined by
	// the extension specification, not by this package. It is decoded into
	// a generic value here; consumers cast or re-decode as needed.
	Data any `json:"data"`
}

// Map is the standard wire-level container for an `extensions` object.
// Keys are namespaced extension identifiers (e.g. "semp.org/priority",
// "vendor.example.com/feature-name"). Iteration order is unspecified;
// canonicalization sorts keys lexicographically per ENVELOPE.md §4.3.
type Map map[string]Entry
