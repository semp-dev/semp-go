// Package largeattachment implements the semp.dev/large-attachment
// extension per ATTACHMENTS.md. Large attachments live as encrypted
// blobs at HTTPS URLs outside the envelope; the envelope's enclosure
// carries metadata (id, filename, mime_type, url, ciphertext_hash,
// aead_algorithm, aead_nonce) under the
// `semp.dev/large-attachment` extension key.
//
// Each attachment is encrypted under a key derived from K_enclosure
// via HKDF-Expand with info `"semp-attachment:" || attachment_id` so
// any recipient that can decrypt the enclosure can also decrypt
// every external attachment without additional key wrapping.
package largeattachment

// ExtensionKey is the literal extension identifier per ATTACHMENTS.md
// §1.2.
const ExtensionKey = "semp.dev/large-attachment"

// HKDFInfoPrefix is the byte-prefix mixed into HKDF-Expand to derive
// per-attachment keys per ATTACHMENTS.md §3.1. The full info input
// is HKDFInfoPrefix || attachment_id (UTF-8 bytes).
const HKDFInfoPrefix = "semp-attachment:"

// AEAD algorithm identifiers per ATTACHMENTS.md §3.2. The baseline
// envelope suite uses ChaCha20-Poly1305 (12-byte nonce); the PQ
// suite uses XChaCha20-Poly1305 (24-byte nonce).
const (
	AEADChaCha20Poly1305  = "chacha20-poly1305"
	AEADXChaCha20Poly1305 = "xchacha20-poly1305"
)

// HashAlgorithm names supported `ciphertext_hash` algorithms. The
// hash is encoded as `algorithm:hex` per ATTACHMENTS.md §2.3.
const (
	HashAlgorithmSHA256 = "sha256"
)

// Item is one entry in the large-attachment extension's items
// array per ATTACHMENTS.md §2.2.
type Item struct {
	// ID is the unique attachment identifier within the envelope
	// (also used as KDF input). ULID RECOMMENDED.
	ID string `json:"id"`

	// Filename is the original filename. MUST NOT contain path
	// separators per §2.3.
	Filename string `json:"filename"`

	// MimeType is the MIME type of the plaintext.
	MimeType string `json:"mime_type"`

	// PlaintextSize is the size in bytes of the plaintext. Recipient
	// clients use it to render a progress indicator.
	PlaintextSize int64 `json:"plaintext_size"`

	// URL is the HTTPS URL from which the ciphertext is fetched.
	URL string `json:"url"`

	// CiphertextHash is the digest of the ciphertext bytes at the
	// URL, encoded as `algorithm:hex` (e.g., "sha256:0123...").
	CiphertextHash string `json:"ciphertext_hash"`

	// AEADAlgorithm is the AEAD identifier used to encrypt the
	// ciphertext. MUST be consistent with the envelope's negotiated
	// suite per §3.2.
	AEADAlgorithm string `json:"aead_algorithm"`

	// AEADNonce is the base64-encoded nonce. Length is algorithm
	// defined.
	AEADNonce string `json:"aead_nonce"`

	// Extensions carries non-normative retrieval hints (bearer
	// tokens, range-support flags, etc.) per §2.3.
	Extensions map[string]any `json:"extensions,omitempty"`
}

// ExtensionData is the inner `data` shape of the
// semp.dev/large-attachment extension entry per §2.1.
type ExtensionData struct {
	Items []Item `json:"items"`
}
