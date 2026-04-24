package brief

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/idna"
	"golang.org/x/text/unicode/norm"
)

// Address is a SEMP user address in canonical wire form: `local-part@domain`.
// The local-part is Normalization Form C (NFC) Unicode, case-sensitive on
// the wire. The domain is the A-label form per IDNA2008 (Punycode), ASCII
// only, case-insensitive (lower-case on the wire).
//
// ENVELOPE.md section 2.3 defines the canonicalization rules. Validate
// enforces them at ingress; Canonicalize converts possibly-denormalized
// input (for example, a U-label domain) to the canonical wire form.
//
// The Address type is a string alias so it marshals trivially to JSON
// without a custom MarshalJSON shim. Parsing and validation helpers are
// provided as methods.
type Address string

// String satisfies fmt.Stringer.
func (a Address) String() string { return string(a) }

// Local returns the local part of the address (everything before the
// final '@'). Returns the entire string if no '@' is present.
//
// Local operates on the raw bytes without validation. Callers that
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

// Address length bounds per ENVELOPE.md section 2.3.
const (
	// MaxAddressLength caps the composed address `local-part@domain`
	// in UTF-8 octets. Matches RFC 5321 section 4.5.3.1.3 and
	// ENVELOPE.md section 2.3.3.
	MaxAddressLength = 254

	// MaxLocalPartLength caps the local-part in UTF-8 octets.
	// Matches the RFC 5321 section 4.5.3.1.1 limit.
	MaxLocalPartLength = 64

	// MaxDomainLength is the DNS total-length ceiling (RFC 1035).
	MaxDomainLength = 253

	// MaxDomainLabelLength is the DNS per-label ceiling (RFC 1035).
	MaxDomainLabelLength = 63
)

// idnaProfile is the IDNA2008 lookup profile used for domain validation
// and A-label conversion. StrictDomainName rejects domain names that
// contain underscore or other characters not permitted by RFC 5891.
var idnaProfile = idna.New(
	idna.MapForLookup(),
	idna.Transitional(false),
	idna.StrictDomainName(true),
)

// Validate reports an error if the address is not in canonical wire
// form per ENVELOPE.md section 2.3:
//
//   - Non-empty, valid UTF-8, no control characters.
//   - Composed length ≤ MaxAddressLength.
//   - Exactly one '@' separator.
//   - Local-part non-empty, ≤ MaxLocalPartLength octets, already in NFC.
//   - Domain non-empty, ≤ MaxDomainLength octets, pure ASCII (A-label
//     form), lowercase, well-formed per DNS label rules.
//
// Callers that receive possibly-denormalized input (mixed-case domain,
// U-label domain, non-NFC local-part) should call Canonicalize before
// Validate.
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
	if !norm.NFC.IsNormalString(local) {
		return errors.New("brief: local part is not in Unicode Normalization Form C")
	}
	return validateDomain(domain)
}

// Canonicalize returns the address in canonical wire form:
//
//   - Local-part normalized to Unicode NFC.
//   - Domain converted to A-label (Punycode) per IDNA2008, folded to
//     lower case.
//
// Canonicalize does not validate the result against length or character
// limits; pair it with Validate on the returned value when ingesting
// untrusted input.
func (a Address) Canonicalize() (Address, error) {
	s := string(a)
	if s == "" {
		return "", errors.New("brief: empty address")
	}
	parts := strings.SplitN(s, "@", 3)
	if len(parts) == 1 {
		return "", errors.New("brief: address missing '@' separator")
	}
	if len(parts) == 3 {
		return "", errors.New("brief: address contains multiple '@' separators")
	}
	local, domain := parts[0], parts[1]

	local = norm.NFC.String(local)
	aLabel, err := idnaProfile.ToASCII(domain)
	if err != nil {
		return "", fmt.Errorf("brief: domain to A-label: %w", err)
	}
	return Address(local + "@" + strings.ToLower(aLabel)), nil
}

// Equal reports whether a and b denote the same address after
// canonicalization. Returns false if either side fails canonicalization.
//
// Equal does NOT collapse visually-similar (confusable) characters.
// Two addresses differing only in Cyrillic vs Latin 'a' are distinct.
// Confusables defense is a UI-layer concern per Unicode Technical
// Standard #39.
func (a Address) Equal(b Address) bool {
	aa, err := a.Canonicalize()
	if err != nil {
		return false
	}
	bb, err := b.Canonicalize()
	if err != nil {
		return false
	}
	return aa == bb
}

// rejectControlChars returns an error if s contains any ASCII control
// character (U+0000 through U+001F, or U+007F). Such characters open
// injection attack surfaces in downstream consumers.
func rejectControlChars(s, field string) error {
	for i, r := range s {
		if r < 0x20 || r == 0x7F {
			return fmt.Errorf("brief: %s contains control character U+%04X at byte %d", field, r, i)
		}
	}
	return nil
}

// validateDomain enforces ENVELOPE.md section 2.3.2: the domain on
// the wire is ASCII-only A-label form, lowercase, well-formed DNS
// labels, non-empty.
func validateDomain(domain string) error {
	if domain == "" {
		return errors.New("brief: address has empty domain")
	}
	if len(domain) > MaxDomainLength {
		return fmt.Errorf("brief: domain exceeds %d bytes", MaxDomainLength)
	}
	for i := 0; i < len(domain); i++ {
		c := domain[i]
		if c > 0x7F {
			return errors.New("brief: domain contains non-ASCII octet (A-label required on the wire)")
		}
		if c >= 'A' && c <= 'Z' {
			return errors.New("brief: domain contains uppercase letters (must be lowercase on the wire)")
		}
	}
	if strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") {
		return errors.New("brief: domain has leading or trailing dot")
	}
	if strings.Contains(domain, "..") {
		return errors.New("brief: domain has empty label (consecutive dots)")
	}
	for _, label := range strings.Split(domain, ".") {
		if label == "" {
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
