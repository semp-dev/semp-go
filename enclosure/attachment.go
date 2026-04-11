package enclosure

import (
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"strings"
)

// Hash algorithm identifiers used in Attachment.Hash values. Every
// conformant SEMP implementation MUST support sha256 (the default).
// Additional algorithms are opt-in per-deployment; see ENVELOPE.md
// §6.3 which fixes the wire format as "algorithm:hex" but leaves the
// algorithm set open.
const (
	// HashAlgorithmSHA256 is the mandatory baseline hash algorithm
	// for attachment integrity verification.
	HashAlgorithmSHA256 = "sha256"

	// HashAlgorithmSHA512 is an optional stronger alternative.
	// Accepted by VerifyHash; ComputeHash / NewAttachment will use
	// it when the caller explicitly requests it.
	HashAlgorithmSHA512 = "sha512"

	// DefaultHashAlgorithm is the algorithm ComputeHash and
	// NewAttachment pick when the caller passes an empty string.
	DefaultHashAlgorithm = HashAlgorithmSHA256
)

// MaxAttachmentBytes caps attachments at 100 MiB by default. This is
// a sanity ceiling — the spec does not mandate a maximum — but it
// prevents a malicious sender from forcing a recipient to allocate
// gigabytes of memory to decode a single base64 blob. Callers that
// legitimately need larger attachments should pass their own limit
// via NewAttachment's size check or disable this by reading the
// content field directly.
const MaxAttachmentBytes int64 = 100 << 20 // 100 MiB

// Attachment is one attached file in an enclosure (ENVELOPE.md §6.3).
//
// The wire format matches the spec schema field-for-field:
//
//	{
//	    "id":        "01JAT...",
//	    "filename":  "report.pdf",
//	    "mime_type": "application/pdf",
//	    "size":      204800,
//	    "hash":      "sha256:abc123...",
//	    "content":   "base64-plaintext-attachment-bytes"
//	}
//
// The `content` field stores the plaintext attachment bytes,
// base64-encoded. The enclosure as a whole is then encrypted under
// K_enclosure when envelope.Compose marshals and seals it, so the
// attachment bytes travel encrypted on the wire even though the
// Attachment struct itself holds them in plaintext (base64) form.
// The `hash` field is computed over the PLAINTEXT bytes so that
// the recipient can verify integrity after the enclosure is
// decrypted, per ENVELOPE.md §7.2 step 10.
type Attachment struct {
	// ID is a unique attachment identifier within this envelope.
	// ULID RECOMMENDED.
	ID string `json:"id"`

	// Filename is the original filename of the attachment.
	Filename string `json:"filename"`

	// MimeType is the MIME type of the attachment content.
	MimeType string `json:"mime_type"`

	// Size is the byte length of the unencrypted attachment content.
	Size int64 `json:"size"`

	// Hash is a content integrity tag of the form "algorithm:hex",
	// e.g. "sha256:a1b2...". Recipients MUST verify this hash
	// against the decrypted content per ENVELOPE.md §7.2 step 10.
	Hash string `json:"hash"`

	// Content is the base64-encoded plaintext attachment bytes.
	// When the enclosing Enclosure is marshaled and encrypted under
	// K_enclosure by envelope.Compose, this field travels encrypted
	// on the wire.
	Content string `json:"content"`
}

// -----------------------------------------------------------------------------
// Hash helpers
// -----------------------------------------------------------------------------

// newHasher returns a fresh hash.Hash for the given algorithm, or an
// error if the algorithm is not supported.
func newHasher(algorithm string) (hash.Hash, error) {
	switch strings.ToLower(algorithm) {
	case "", HashAlgorithmSHA256:
		return sha256.New(), nil
	case HashAlgorithmSHA512:
		return sha512.New(), nil
	default:
		return nil, fmt.Errorf("enclosure: unsupported hash algorithm %q", algorithm)
	}
}

// canonicalAlgorithm normalizes an algorithm string to the form used
// in the wire hash tag. Empty strings become the default.
func canonicalAlgorithm(algorithm string) string {
	a := strings.ToLower(strings.TrimSpace(algorithm))
	if a == "" {
		return DefaultHashAlgorithm
	}
	return a
}

// ComputeHash returns a wire-format hash tag of the form
// "algorithm:hex" over plaintext. An empty or zero-value algorithm
// picks DefaultHashAlgorithm (sha256).
//
// This is the sender-side helper: construct an Attachment by
// combining ComputeHash over the plaintext bytes with a base64
// encoding of the same bytes into Content.
func ComputeHash(algorithm string, plaintext []byte) (string, error) {
	h, err := newHasher(algorithm)
	if err != nil {
		return "", err
	}
	_, _ = h.Write(plaintext)
	return canonicalAlgorithm(algorithm) + ":" + hex.EncodeToString(h.Sum(nil)), nil
}

// ComputeHashReader is the streaming equivalent of ComputeHash,
// intended for senders that read attachment bytes from disk and
// don't want to load the whole file into memory. It returns the
// wire-format hash tag plus the total number of bytes read from r
// (useful for populating Attachment.Size without an extra stat).
//
// The caller is responsible for positioning r at the start of the
// attachment content. ComputeHashReader reads until r returns
// io.EOF or any other error.
func ComputeHashReader(algorithm string, r io.Reader) (hashTag string, size int64, err error) {
	if r == nil {
		return "", 0, errors.New("enclosure: nil reader")
	}
	h, err := newHasher(algorithm)
	if err != nil {
		return "", 0, err
	}
	size, err = io.Copy(h, r)
	if err != nil {
		return "", size, fmt.Errorf("enclosure: read attachment: %w", err)
	}
	return canonicalAlgorithm(algorithm) + ":" + hex.EncodeToString(h.Sum(nil)), size, nil
}

// ParseHash splits a wire-format hash tag "algorithm:hex" into its
// algorithm and hex components. Returns an error if the format is
// malformed or if the algorithm is empty / hex is not a valid
// hexadecimal string.
func ParseHash(hashTag string) (algorithm, hexValue string, err error) {
	idx := strings.IndexByte(hashTag, ':')
	if idx < 0 {
		return "", "", fmt.Errorf("enclosure: hash %q missing algorithm prefix", hashTag)
	}
	algorithm = strings.ToLower(strings.TrimSpace(hashTag[:idx]))
	hexValue = strings.TrimSpace(hashTag[idx+1:])
	if algorithm == "" {
		return "", "", errors.New("enclosure: hash has empty algorithm")
	}
	if hexValue == "" {
		return "", "", errors.New("enclosure: hash has empty hex value")
	}
	if _, err := hex.DecodeString(hexValue); err != nil {
		return "", "", fmt.Errorf("enclosure: hash hex: %w", err)
	}
	return algorithm, hexValue, nil
}

// VerifyHash recomputes the attachment hash over plaintext using the
// algorithm named in a.Hash and compares it to the stored hex value
// in constant time. Returns nil on match, a descriptive error
// otherwise. This is the recipient-side primitive for ENVELOPE.md
// §7.2 step 10 ("Client verifies attachment hashes against decrypted
// attachment content").
//
// VerifyHash does not consult a.Content or a.Size — the caller is
// expected to have already decoded the base64 plaintext and pass
// those bytes directly. For a one-shot "decode + verify" helper, use
// the Plaintext method.
func (a *Attachment) VerifyHash(plaintext []byte) error {
	if a == nil {
		return errors.New("enclosure: nil attachment")
	}
	if a.Hash == "" {
		return errors.New("enclosure: attachment has no hash")
	}
	algorithm, expectedHex, err := ParseHash(a.Hash)
	if err != nil {
		return err
	}
	h, err := newHasher(algorithm)
	if err != nil {
		return err
	}
	_, _ = h.Write(plaintext)
	gotHex := hex.EncodeToString(h.Sum(nil))
	// Constant-time comparison so VerifyHash does not leak timing
	// information about where the hash diverges.
	if subtle.ConstantTimeCompare([]byte(gotHex), []byte(expectedHex)) != 1 {
		return fmt.Errorf("enclosure: attachment hash mismatch (algorithm=%s)", algorithm)
	}
	return nil
}

// -----------------------------------------------------------------------------
// Constructors + decoders
// -----------------------------------------------------------------------------

// NewAttachment assembles an Attachment from the given identifying
// fields and the plaintext content bytes. It:
//
//   - computes the content hash using DefaultHashAlgorithm (sha256)
//   - sets Size to len(plaintext)
//   - base64-encodes the plaintext into Content
//
// algorithm may be empty to pick DefaultHashAlgorithm. Callers that
// want a stronger hash algorithm pass HashAlgorithmSHA512.
//
// The returned Attachment is ready to be appended to an
// Enclosure.Attachments slice — envelope.Compose will marshal it
// alongside the rest of the enclosure and encrypt the whole JSON
// under K_enclosure.
func NewAttachment(id, filename, mimeType, algorithm string, plaintext []byte) (*Attachment, error) {
	if id == "" {
		return nil, errors.New("enclosure: attachment id is required")
	}
	if filename == "" {
		return nil, errors.New("enclosure: attachment filename is required")
	}
	if mimeType == "" {
		return nil, errors.New("enclosure: attachment mime_type is required")
	}
	if int64(len(plaintext)) > MaxAttachmentBytes {
		return nil, fmt.Errorf("enclosure: attachment plaintext exceeds %d bytes", MaxAttachmentBytes)
	}
	hashTag, err := ComputeHash(algorithm, plaintext)
	if err != nil {
		return nil, err
	}
	return &Attachment{
		ID:       id,
		Filename: filename,
		MimeType: mimeType,
		Size:     int64(len(plaintext)),
		Hash:     hashTag,
		Content:  base64.StdEncoding.EncodeToString(plaintext),
	}, nil
}

// Plaintext decodes a.Content (base64) into the raw plaintext bytes
// and verifies the result against a.Hash before returning it. This
// is the one-shot recipient-side helper that combines decoding and
// hash verification, implementing ENVELOPE.md §7.2 step 10 for a
// single attachment.
//
// The returned slice is freshly allocated and owned by the caller.
// A hash mismatch returns a non-nil error and a nil byte slice —
// the caller MUST NOT treat the failed payload as valid content.
//
// Plaintext enforces MaxAttachmentBytes after base64 decoding to
// bound memory usage on malicious inputs.
func (a *Attachment) Plaintext() ([]byte, error) {
	if a == nil {
		return nil, errors.New("enclosure: nil attachment")
	}
	if a.Content == "" {
		return nil, errors.New("enclosure: attachment has empty content")
	}
	plaintext, err := base64.StdEncoding.DecodeString(a.Content)
	if err != nil {
		return nil, fmt.Errorf("enclosure: decode attachment content: %w", err)
	}
	if int64(len(plaintext)) > MaxAttachmentBytes {
		return nil, fmt.Errorf("enclosure: attachment content exceeds %d bytes", MaxAttachmentBytes)
	}
	// Optional size cross-check: if the sender populated Size,
	// confirm it matches the decoded length before we spend cycles
	// on hashing.
	if a.Size != 0 && a.Size != int64(len(plaintext)) {
		return nil, fmt.Errorf("enclosure: attachment size mismatch: header=%d decoded=%d", a.Size, len(plaintext))
	}
	if err := a.VerifyHash(plaintext); err != nil {
		return nil, err
	}
	return plaintext, nil
}
