package discovery_test

import (
	"strings"
	"testing"

	"semp.dev/semp-go/discovery"
)

// v3Label is a valid-shaped 56-character base32 v3 onion identifier
// for the tests below. The bits do not encode a real onion service;
// we only test the library's structural validation.
const v3Label = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx"

func TestIsOnionDomain(t *testing.T) {
	if !discovery.IsOnionDomain("example.onion") {
		t.Error("IsOnionDomain('example.onion') = false, want true")
	}
	if !discovery.IsOnionDomain("Example.Onion") {
		t.Error("IsOnionDomain is not case-insensitive")
	}
	if discovery.IsOnionDomain("example.com") {
		t.Error("IsOnionDomain('example.com') = true, want false")
	}
}

func TestValidateOnionDomainAcceptsV3(t *testing.T) {
	if err := discovery.ValidateOnionDomain(v3Label + ".onion"); err != nil {
		t.Errorf("ValidateOnionDomain v3: %v", err)
	}
	// Sub-labels before the v3 label are permitted.
	if err := discovery.ValidateOnionDomain("sub." + v3Label + ".onion"); err != nil {
		t.Errorf("ValidateOnionDomain sub.v3: %v", err)
	}
}

func TestValidateOnionDomainRejectsV2(t *testing.T) {
	// v2 onion labels are 16 characters.
	v2 := "abcdefghijklmnop"
	err := discovery.ValidateOnionDomain(v2 + ".onion")
	if err == nil {
		t.Error("ValidateOnionDomain on v2: want error")
	}
	if err != nil && !strings.Contains(err.Error(), "version-2") {
		t.Errorf("error %q should mention version-2", err)
	}
}

func TestValidateOnionDomainRejectsNonOnion(t *testing.T) {
	err := discovery.ValidateOnionDomain("example.com")
	if err == nil || !strings.Contains(err.Error(), "not an .onion") {
		t.Errorf("ValidateOnionDomain on non-onion: got %v, want 'not an .onion'", err)
	}
}

func TestValidateOnionDomainRejectsWrongLength(t *testing.T) {
	wrong := "abcdefg"
	err := discovery.ValidateOnionDomain(wrong + ".onion")
	if err == nil {
		t.Error("ValidateOnionDomain on short label: want error")
	}
}

func TestValidateOnionDomainRejectsInvalidAlphabet(t *testing.T) {
	// Replace one char with something outside base32.
	bad := strings.Repeat("a", 55) + "!"
	err := discovery.ValidateOnionDomain(bad + ".onion")
	if err == nil {
		t.Error("ValidateOnionDomain on invalid alphabet: want error")
	}
}
