package enclosure

// Body is the multipart-capable body representation. Keys are MIME types
// (e.g. "text/plain", "text/html", "text/markdown"); values are the
// base64-encoded body bytes for that representation.
//
// When the enclosing Enclosure has ContentType "multipart/alternative",
// senders SHOULD always include a "text/plain" representation as a baseline
// (ENVELOPE.md §6.4). Receivers select the most capable format they support.
type Body map[string]string

// Get returns the body bytes for the given MIME type, or the empty string
// if no representation exists for that type.
func (b Body) Get(mimeType string) string {
	if b == nil {
		return ""
	}
	return b[mimeType]
}

// Set assigns the body bytes for the given MIME type.
func (b Body) Set(mimeType, content string) {
	if b == nil {
		return
	}
	b[mimeType] = content
}
