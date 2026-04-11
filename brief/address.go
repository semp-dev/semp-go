package brief

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

// Address is a SEMP user address. The wire format is `user@domain`,
// matching SMTP-style addressing. SEMP is UTF-8 native (FAQ §1.11), so
// the local part and domain may contain any valid UTF-8.
//
// The Address type is a string alias rather than a struct so that it
// marshals trivially to JSON without any custom MarshalJSON shim.
// Parsing helpers are provided as standalone functions.
type Address string

// String satisfies fmt.Stringer.
func (a Address) String() string { return string(a) }

// Local returns the local part of the address (everything before the
// final '@'). Returns the entire string if no '@' is present.
//
// Local operates on the raw bytes without validation — callers that
// need to reject malformed addresses should pair Local with Validate.
func (a Address) Local() string {
	s := string(a)
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '@' {
			return s[:i]
		}
	}
	return s
}

// Domain returns the domain part of the address (everything after
// the final '@'). Returns the empty string if no '@' is present.
func (a Address) Domain() string {
	s := string(a)
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '@' {
			return s[i+1:]
		}
	}
	return ""
}

// Address length bounds. These are deliberately permissive to
// accommodate internationalized addresses (FAQ §1.11) while still
// capping the worst case so an attacker cannot submit megabyte-long
// strings through an address field.
const (
	// MaxAddressLength is the maximum total length of an address in
	// bytes, matching the RFC 3696 §3 recommendation plus headroom
	// for UTF-8 encoded internationalized names.
	MaxAddressLength = 320

	// MaxLocalPartLength caps the local part. RFC 3696 recommends
	// 64 bytes for ASCII; we permit UTF-8 expansion up to 128 bytes
	// so a 32-character internationalized local part (up to 4 bytes
	// per codepoint) fits comfortably.
	MaxLocalPartLength = 128

	// MaxDomainLength is the classic DNS total-length ceiling.
	MaxDomainLength = 253

	// MaxDomainLabelLength is the classic DNS per-label ceiling.
	MaxDomainLabelLength = 63
)

// Validate reports an error if the address is not syntactically valid
// per the SEMP conformance rules in ENVELOPE.md §5 + FAQ §1.11:
//
//   - MUST be non-empty and valid UTF-8.
//   - MUST NOT exceed MaxAddressLength bytes.
//   - MUST NOT contain control characters (U+0000 – U+001F or U+007F),
//     which rules out NUL / CR / LF / TAB injection.
//   - MUST contain exactly one unquoted `@` separator. SEMP does not
//     inherit RFC 5321 quoted-local-part edge cases (FAQ §1.14).
//   - Local part MUST be non-empty and MUST NOT exceed
//     MaxLocalPartLength bytes.
//   - Domain part MUST be a well-formed DNS name: non-empty, at
//     most MaxDomainLength bytes, composed of dot-separated labels
//     each of which is non-empty, ≤ MaxDomainLabelLength bytes, and
//     neither starts nor ends with a hyphen.
//
// Validation is intentionally structural — it does not perform DNS
// resolution or any semantic check.
func (a Address) Validate() error {
	s := string(a)
	if s == "" {
		return errors.New("brief: empty address")
	}
	if len(s) > MaxAddressLength {
		return fmt.Errorf("brief: address exceeds %d bytes", MaxAddressLength)
	}
	if !utf8.ValidString(s) {
		return errors.New("brief: address is not valid UTF-8")
	}
	if err := rejectControlChars(s, "address"); err != nil {
		return err
	}

	// Exactly one '@'. SplitN with N=3 lets us detect both missing
	// and excess separators in a single pass.
	parts := strings.SplitN(s, "@", 3)
	if len(parts) == 1 {
		return errors.New("brief: address missing '@' separator")
	}
	if len(parts) == 3 {
		return errors.New("brief: address contains multiple '@' separators")
	}
	local, domain := parts[0], parts[1]

	if local == "" {
		return errors.New("brief: address has empty local part")
	}
	if len(local) > MaxLocalPartLength {
		return fmt.Errorf("brief: local part exceeds %d bytes", MaxLocalPartLength)
	}
	return validateDomain(domain)
}

// rejectControlChars returns an error if s contains any ASCII
// control character (U+0000 – U+001F or U+007F). Such characters
// open injection attack surfaces in downstream consumers that
// embed addresses in log lines, header fields, or SQL.
func rejectControlChars(s, field string) error {
	for i, r := range s {
		if r < 0x20 || r == 0x7F {
			return fmt.Errorf("brief: %s contains control character U+%04X at byte %d", field, r, i)
		}
	}
	return nil
}

// validateDomain applies the DNS structural rules from RFC 1035
// adapted for UTF-8 (internationalized labels are accepted as raw
// UTF-8 sequences per FAQ §1.11 — no punycode round-trip required).
func validateDomain(domain string) error {
	if domain == "" {
		return errors.New("brief: address has empty domain")
	}
	if len(domain) > MaxDomainLength {
		return fmt.Errorf("brief: domain exceeds %d bytes", MaxDomainLength)
	}
	if strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") {
		return errors.New("brief: domain has leading or trailing dot")
	}
	if strings.Contains(domain, "..") {
		return errors.New("brief: domain has empty label (consecutive dots)")
	}
	for _, label := range strings.Split(domain, ".") {
		if label == "" {
			// Defensive — covered by the checks above, but the
			// explicit guard protects against future refactors.
			return errors.New("brief: domain has empty label")
		}
		if len(label) > MaxDomainLabelLength {
			return fmt.Errorf("brief: domain label %q exceeds %d bytes", label, MaxDomainLabelLength)
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return fmt.Errorf("brief: domain label %q has leading or trailing hyphen", label)
		}
		for _, r := range label {
			if r == '@' || r == ' ' || r == '\t' {
				return fmt.Errorf("brief: domain label %q contains disallowed character", label)
			}
		}
	}
	return nil
}
