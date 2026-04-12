package delivery_test

import (
	"testing"

	"semp.dev/semp-go/delivery"
)

// TestMatchVisibilityNobody is the default-deny path: a nil Visibility
// or one with mode `nobody` MUST never disclose status.
func TestMatchVisibilityNobody(t *testing.T) {
	if delivery.MatchVisibility(nil, "alice@example.com", "example.com", "semp.example.com") {
		t.Error("nil visibility should never disclose")
	}
	v := &delivery.Visibility{Mode: delivery.VisibilityNobody}
	if delivery.MatchVisibility(v, "alice@example.com", "example.com", "semp.example.com") {
		t.Error("nobody mode should never disclose")
	}
}

// TestMatchVisibilityEveryone covers the always-allow path.
func TestMatchVisibilityEveryone(t *testing.T) {
	v := &delivery.Visibility{Mode: delivery.VisibilityEveryone}
	if !delivery.MatchVisibility(v, "alice@example.com", "example.com", "semp.example.com") {
		t.Error("everyone mode should always disclose")
	}
	// Empty sender identifiers don't matter in everyone mode.
	if !delivery.MatchVisibility(v, "", "", "") {
		t.Error("everyone mode should disclose even with empty sender")
	}
}

// TestMatchVisibilityDomains confirms domain mode honors only domain
// allow-list entries.
func TestMatchVisibilityDomains(t *testing.T) {
	v := &delivery.Visibility{
		Mode: delivery.VisibilityDomains,
		Allow: []delivery.VisibilityEntry{
			{Type: "domain", Domain: "work.example.com"},
			{Type: "user", Address: "boss@personal.example"}, // ignored in this mode
		},
	}
	// Sender from work.example.com matches.
	if !delivery.MatchVisibility(v, "alice@work.example.com", "work.example.com", "") {
		t.Error("domain match should disclose")
	}
	// Same address but wrong domain does not.
	if delivery.MatchVisibility(v, "alice@other.example", "other.example", "") {
		t.Error("domain mismatch should not disclose")
	}
	// User entry is ignored in domains mode even though the address matches.
	if delivery.MatchVisibility(v, "boss@personal.example", "personal.example", "") {
		t.Error("user entry should be ignored in domains mode")
	}
}

// TestMatchVisibilityUsers confirms users mode honors only user
// allow-list entries.
func TestMatchVisibilityUsers(t *testing.T) {
	v := &delivery.Visibility{
		Mode: delivery.VisibilityUsers,
		Allow: []delivery.VisibilityEntry{
			{Type: "user", Address: "friend@personal.example"},
			{Type: "domain", Domain: "work.example.com"}, // ignored in this mode
		},
	}
	if !delivery.MatchVisibility(v, "friend@personal.example", "personal.example", "") {
		t.Error("user match should disclose")
	}
	if delivery.MatchVisibility(v, "alice@work.example.com", "work.example.com", "") {
		t.Error("domain entry should be ignored in users mode")
	}
}

// TestMatchVisibilityServers confirms servers mode honors only server
// allow-list entries.
func TestMatchVisibilityServers(t *testing.T) {
	v := &delivery.Visibility{
		Mode: delivery.VisibilityServers,
		Allow: []delivery.VisibilityEntry{
			{Type: "server", Server: "trusted.example.com"},
		},
	}
	if !delivery.MatchVisibility(v, "alice@anywhere.example", "anywhere.example", "trusted.example.com") {
		t.Error("server match should disclose")
	}
	if delivery.MatchVisibility(v, "alice@anywhere.example", "anywhere.example", "untrusted.example.com") {
		t.Error("server mismatch should not disclose")
	}
}

// TestMatchVisibilityCaseInsensitive confirms domain / user / server
// matching is case-insensitive.
func TestMatchVisibilityCaseInsensitive(t *testing.T) {
	v := &delivery.Visibility{
		Mode: delivery.VisibilityDomains,
		Allow: []delivery.VisibilityEntry{
			{Type: "domain", Domain: "Work.Example.COM"},
		},
	}
	if !delivery.MatchVisibility(v, "alice@work.example.com", "WORK.EXAMPLE.COM", "") {
		t.Error("case-insensitive domain match failed")
	}
}

// TestMatchVisibilityUnknownModeFailsClosed confirms an unrecognized
// mode is treated as nobody for forward-compatibility safety.
func TestMatchVisibilityUnknownModeFailsClosed(t *testing.T) {
	v := &delivery.Visibility{Mode: "future-mode"}
	if delivery.MatchVisibility(v, "alice@example.com", "example.com", "") {
		t.Error("unknown mode should fail closed")
	}
}
