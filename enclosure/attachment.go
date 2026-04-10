package enclosure

// Attachment is one attached file in an enclosure (ENVELOPE.md §6.3).
type Attachment struct {
	// ID is a unique attachment identifier within this envelope.
	ID string `json:"id"`

	// Filename is the original filename of the attachment.
	Filename string `json:"filename"`

	// MimeType is the MIME type of the attachment content.
	MimeType string `json:"mime_type"`

	// Size is the byte length of the unencrypted attachment content.
	Size int64 `json:"size"`

	// Hash is a content integrity tag of the form "algorithm:hex", e.g.
	// "sha256:abc123...". Recipients MUST verify this hash against the
	// decrypted content per ENVELOPE.md §7.2 step 10.
	Hash string `json:"hash"`

	// Content is the base64-encoded encrypted attachment bytes.
	Content string `json:"content"`
}

// VerifyHash recomputes Hash over the (already decrypted) content bytes and
// compares it to the stored value. Returns nil if the hashes match.
//
// TODO(ENVELOPE.md §7.2 step 10): implement using crypto/sha256 once the
// real decryption pipeline is in place.
func (a *Attachment) VerifyHash(plaintext []byte) error {
	_ = plaintext
	return nil
}
