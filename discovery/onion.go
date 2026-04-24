package discovery

import (
	"errors"
	"strings"
)

// OnionSuffix is the label that marks a Tor onion-service domain.
const OnionSuffix = ".onion"

// OnionV3LabelLength is the character count of a version-3 onion
// service identifier, the only version permitted by the spec
// (DISCOVERY.md section 2.5.1).
const OnionV3LabelLength = 56

// IsOnionDomain reports whether d ends in ".onion". The check is
// case-insensitive per the standard convention for the .onion TLD.
func IsOnionDomain(d string) bool {
	return strings.HasSuffix(strings.ToLower(d), OnionSuffix)
}

// ValidateOnionDomain rejects onion domains that are not the v3 form.
// v2 onion addresses (16-character labels) are cryptographically
// deprecated and MUST NOT be used (DISCOVERY.md section 2.5.1).
//
// A domain of form "<label>.onion" is accepted when label has exactly
// OnionV3LabelLength characters. Multi-label onion domains ("sub.<label>.onion")
// are accepted when the rightmost label before .onion is the v3
// identifier.
func ValidateOnionDomain(d string) error {
	if !IsOnionDomain(d) {
		return errors.New("discovery: not an .onion domain")
	}
	lower := strings.ToLower(d)
	trimmed := strings.TrimSuffix(lower, OnionSuffix)
	if trimmed == "" {
		return errors.New("discovery: .onion domain has empty label")
	}
	labels := strings.Split(trimmed, ".")
	onionLabel := labels[len(labels)-1]
	if len(onionLabel) == 16 {
		return errors.New("discovery: version-2 .onion addresses are not supported; use a v3 address (56-character label)")
	}
	if len(onionLabel) != OnionV3LabelLength {
		return errors.New("discovery: .onion label is not a valid v3 identifier (expected 56 characters)")
	}
	for _, r := range onionLabel {
		if !((r >= 'a' && r <= 'z') || (r >= '2' && r <= '7')) {
			return errors.New("discovery: .onion label contains characters outside the v3 base32 alphabet")
		}
	}
	return nil
}
