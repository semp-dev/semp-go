package largeattachment

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"

	"semp.dev/semp-go/crypto"
)

// DeriveAttachmentKey derives K_attachment from K_enclosure per
// ATTACHMENTS.md §3.1: HKDF-Expand(PRK = K_enclosure, info =
// "semp-attachment:" || attachment_id, L = length-of-K_enclosure).
//
// kEnclosure is used directly as the PRK (no Extract step) per the
// spec text "PRK = K_enclosure". outputLen MUST equal the AEAD's
// key length for the negotiated suite; the caller passes
// suite.AEAD().KeySize().
func DeriveAttachmentKey(kdf crypto.KDF, kEnclosure []byte, attachmentID string, outputLen int) ([]byte, error) {
	if kdf == nil {
		return nil, errors.New("largeattachment: nil KDF")
	}
	if len(kEnclosure) == 0 {
		return nil, errors.New("largeattachment: empty K_enclosure")
	}
	if attachmentID == "" {
		return nil, errors.New("largeattachment: empty attachment_id")
	}
	if outputLen <= 0 {
		return nil, fmt.Errorf("largeattachment: invalid output length %d", outputLen)
	}
	info := append([]byte(HKDFInfoPrefix), []byte(attachmentID)...)
	return kdf.Expand(kEnclosure, info, outputLen), nil
}

// AdditionalData returns the AEAD additional-data input bound into
// each attachment's ciphertext per ATTACHMENTS.md §3.2: the
// canonical UTF-8 JSON encoding of the item with `ciphertext_hash`,
// `aead_nonce`, and `extensions` set to empty values (`""`, `""`,
// `{}`).
//
// Binding the metadata into AEAD additional-data prevents an
// attacker from swapping `filename` or `mime_type` while leaving
// the ciphertext intact.
func AdditionalData(item Item) ([]byte, error) {
	clone := item
	clone.CiphertextHash = ""
	clone.AEADNonce = ""
	clone.Extensions = nil
	return json.Marshal(clone)
}

// CiphertextHash computes the §2.3 ciphertext_hash value for the
// given ciphertext bytes. Returns the spec's `algorithm:hex` form
// using SHA-256.
func CiphertextHash(ciphertext []byte) string {
	sum := sha256.Sum256(ciphertext)
	return HashAlgorithmSHA256 + ":" + hex.EncodeToString(sum[:])
}

// VerifyCiphertextHash reports whether item.CiphertextHash matches
// the SHA-256 of the supplied ciphertext bytes per ATTACHMENTS.md
// §6 step 3c. Returns nil when the hash matches; otherwise returns
// a typed error the caller surfaces as a §7.2 ciphertext-integrity
// failure.
func VerifyCiphertextHash(item Item, ciphertext []byte) error {
	if item.CiphertextHash == "" {
		return errors.New("largeattachment: item missing ciphertext_hash")
	}
	algo, hexDigest, ok := strings.Cut(item.CiphertextHash, ":")
	if !ok {
		return fmt.Errorf("largeattachment: ciphertext_hash %q missing algorithm prefix", item.CiphertextHash)
	}
	if algo != HashAlgorithmSHA256 {
		return fmt.Errorf("largeattachment: unsupported ciphertext_hash algorithm %q", algo)
	}
	want, err := hex.DecodeString(hexDigest)
	if err != nil {
		return fmt.Errorf("largeattachment: ciphertext_hash hex: %w", err)
	}
	got := sha256.Sum256(ciphertext)
	if !bytesEqual(want, got[:]) {
		return errors.New("largeattachment: ciphertext_hash mismatch")
	}
	return nil
}

// bytesEqual is a constant-time comparison wrapper. Defensive
// rather than strictly necessary (the hash is public), but keeps
// behavior uniform with other integrity checks in this codebase.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

// ValidateURL applies the §4.1 URL rules: scheme MUST be https,
// host MUST be a fully qualified domain name or an IPv6 literal in
// brackets, bare IPv4 literals MUST NOT be used.
func ValidateURL(raw string) error {
	if raw == "" {
		return errors.New("largeattachment: empty url")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("largeattachment: parse url: %w", err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("largeattachment: url scheme %q, want https", u.Scheme)
	}
	// u.Hostname() strips IPv6 brackets and the port; matches what
	// we want to inspect.
	host := u.Hostname()
	if host == "" {
		return errors.New("largeattachment: url has no host")
	}
	// IPv6 literals are permitted per §4.1. Detect by parsing as IP
	// and checking for ':'.
	if ip := net.ParseIP(host); ip != nil {
		if strings.Contains(host, ":") {
			// IPv6 literal in brackets. Allowed.
			return nil
		}
		// Bare IPv4 literal: forbidden.
		return fmt.Errorf("largeattachment: url host %q is a bare IPv4 literal; FQDN required", host)
	}
	// Otherwise treat as an FQDN. We do not enforce DNS resolution;
	// that is a runtime concern. The §4.1 "fully qualified" wording
	// implies at least one dot.
	if !strings.Contains(host, ".") {
		return fmt.Errorf("largeattachment: url host %q is not a fully qualified domain name", host)
	}
	return nil
}

// Validate reports whether item is structurally well-formed per
// ATTACHMENTS.md §2.3 and §4.1.
func (item Item) Validate() error {
	if item.ID == "" {
		return errors.New("largeattachment: item missing id")
	}
	if item.Filename == "" {
		return errors.New("largeattachment: item missing filename")
	}
	if strings.ContainsAny(item.Filename, "/\\") {
		return fmt.Errorf("largeattachment: filename %q contains path separator", item.Filename)
	}
	if item.MimeType == "" {
		return errors.New("largeattachment: item missing mime_type")
	}
	if item.PlaintextSize < 0 {
		return fmt.Errorf("largeattachment: plaintext_size %d MUST be >= 0", item.PlaintextSize)
	}
	if err := ValidateURL(item.URL); err != nil {
		return err
	}
	if item.CiphertextHash == "" {
		return errors.New("largeattachment: item missing ciphertext_hash")
	}
	if item.AEADAlgorithm == "" {
		return errors.New("largeattachment: item missing aead_algorithm")
	}
	if item.AEADNonce == "" {
		return errors.New("largeattachment: item missing aead_nonce")
	}
	return nil
}
