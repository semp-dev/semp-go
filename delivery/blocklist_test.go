package delivery_test

import (
	"context"
	"testing"
	"time"

	semp "semp.dev/semp-go"
	"semp.dev/semp-go/delivery"
)

func userEntry(addr string, ack semp.Acknowledgment) delivery.BlockEntry {
	return delivery.BlockEntry{
		ID:             "user-" + addr,
		Entity:         delivery.Entity{Type: delivery.EntityUser, Address: addr},
		Acknowledgment: ack,
		Scope:          delivery.ScopeAll,
		CreatedAt:      time.Now().UTC(),
	}
}

func domainEntry(domain string, ack semp.Acknowledgment) delivery.BlockEntry {
	return delivery.BlockEntry{
		ID:             "domain-" + domain,
		Entity:         delivery.Entity{Type: delivery.EntityDomain, Domain: domain},
		Acknowledgment: ack,
		Scope:          delivery.ScopeAll,
		CreatedAt:      time.Now().UTC(),
	}
}

func serverEntry(host string, ack semp.Acknowledgment) delivery.BlockEntry {
	return delivery.BlockEntry{
		ID:             "server-" + host,
		Entity:         delivery.Entity{Type: delivery.EntityServer, Hostname: host},
		Acknowledgment: ack,
		Scope:          delivery.ScopeAll,
		CreatedAt:      time.Now().UTC(),
	}
}

// TestBlockListMatchUserExact confirms a user-level entry matches the
// exact sender address and returns the matching entry.
func TestBlockListMatchUserExact(t *testing.T) {
	list := &delivery.BlockList{
		Entries: []delivery.BlockEntry{userEntry("alice@example.com", semp.AckRejected)},
	}
	got := list.Match("alice@example.com", "example.com", "", false)
	if got == nil {
		t.Fatal("Match returned nil")
	}
	if got.ID != "user-alice@example.com" {
		t.Errorf("matched entry ID = %q, want user-alice@example.com", got.ID)
	}
}

// TestBlockListMatchUserCaseInsensitive confirms address matching is
// case-insensitive.
func TestBlockListMatchUserCaseInsensitive(t *testing.T) {
	list := &delivery.BlockList{
		Entries: []delivery.BlockEntry{userEntry("Alice@Example.com", semp.AckRejected)},
	}
	got := list.Match("alice@example.com", "example.com", "", false)
	if got == nil {
		t.Error("case-insensitive user match failed")
	}
}

// TestBlockListMatchDomainWildcard confirms a domain entry matches any
// address from that domain.
func TestBlockListMatchDomainWildcard(t *testing.T) {
	list := &delivery.BlockList{
		Entries: []delivery.BlockEntry{domainEntry("spam.example", semp.AckRejected)},
	}
	got := list.Match("anyone@spam.example", "spam.example", "", false)
	if got == nil {
		t.Fatal("domain wildcard match failed")
	}
	if got.Entity.Type != delivery.EntityDomain {
		t.Errorf("matched type = %s, want domain", got.Entity.Type)
	}
}

// TestBlockListMatchPrecedenceUserBeatsDomain confirms a user entry
// wins over a domain entry for the same sender per DELIVERY.md §4.3
// (most specific match wins).
func TestBlockListMatchPrecedenceUserBeatsDomain(t *testing.T) {
	list := &delivery.BlockList{
		Entries: []delivery.BlockEntry{
			domainEntry("example.com", semp.AckSilent),
			userEntry("alice@example.com", semp.AckRejected),
		},
	}
	got := list.Match("alice@example.com", "example.com", "", false)
	if got == nil {
		t.Fatal("Match returned nil")
	}
	if got.Entity.Type != delivery.EntityUser {
		t.Errorf("expected user precedence, got %s", got.Entity.Type)
	}
	if got.Acknowledgment != semp.AckRejected {
		t.Errorf("ack = %s, want rejected (from user entry)", got.Acknowledgment)
	}
}

// TestBlockListMatchPrecedenceServerBeatsDomain confirms server beats
// domain when both could apply.
func TestBlockListMatchPrecedenceServerBeatsDomain(t *testing.T) {
	list := &delivery.BlockList{
		Entries: []delivery.BlockEntry{
			domainEntry("example.com", semp.AckRejected),
			serverEntry("semp.example.com", semp.AckSilent),
		},
	}
	got := list.Match("alice@example.com", "example.com", "semp.example.com", false)
	if got == nil {
		t.Fatal("Match returned nil")
	}
	if got.Entity.Type != delivery.EntityServer {
		t.Errorf("expected server precedence, got %s", got.Entity.Type)
	}
}

// TestBlockListMatchExpired confirms entries past their ExpiresAt are
// ignored.
func TestBlockListMatchExpired(t *testing.T) {
	past := time.Now().UTC().Add(-time.Hour)
	entry := userEntry("alice@example.com", semp.AckRejected)
	entry.ExpiresAt = &past
	list := &delivery.BlockList{Entries: []delivery.BlockEntry{entry}}
	if got := list.Match("alice@example.com", "example.com", "", false); got != nil {
		t.Errorf("expired entry should not match, got %+v", got)
	}
}

// TestBlockListMatchScopeDirectVsGroup exercises the scope filter.
func TestBlockListMatchScopeDirectVsGroup(t *testing.T) {
	directEntry := userEntry("alice@example.com", semp.AckRejected)
	directEntry.Scope = delivery.ScopeDirect
	groupEntry := userEntry("bob@example.com", semp.AckRejected)
	groupEntry.Scope = delivery.ScopeGroup
	list := &delivery.BlockList{Entries: []delivery.BlockEntry{directEntry, groupEntry}}

	// Direct envelope from alice: direct entry applies, group doesn't.
	if got := list.Match("alice@example.com", "example.com", "", false); got == nil {
		t.Error("direct entry should apply to a direct envelope")
	}
	if got := list.Match("alice@example.com", "example.com", "", true); got != nil {
		t.Error("direct entry should NOT apply to a group envelope")
	}
	// Group envelope from bob: group entry applies.
	if got := list.Match("bob@example.com", "example.com", "", true); got == nil {
		t.Error("group entry should apply to a group envelope")
	}
	if got := list.Match("bob@example.com", "example.com", "", false); got != nil {
		t.Error("group entry should NOT apply to a direct envelope")
	}
}

// TestBlockListMatchEmptyOrNilNoMatch confirms an empty or nil list
// never matches.
func TestBlockListMatchEmptyOrNilNoMatch(t *testing.T) {
	if got := (*delivery.BlockList)(nil).Match("alice@example.com", "example.com", "", false); got != nil {
		t.Errorf("nil list matched: %+v", got)
	}
	empty := &delivery.BlockList{}
	if got := empty.Match("alice@example.com", "example.com", "", false); got != nil {
		t.Errorf("empty list matched: %+v", got)
	}
}

// TestBlockListMatchUnknownEntityIgnored confirms unknown entity types
// don't match (forward compatibility).
func TestBlockListMatchUnknownEntityIgnored(t *testing.T) {
	list := &delivery.BlockList{
		Entries: []delivery.BlockEntry{{
			ID:             "future",
			Entity:         delivery.Entity{Type: "fingerprint", Address: "alice@example.com"},
			Acknowledgment: semp.AckRejected,
			Scope:          delivery.ScopeAll,
		}},
	}
	if got := list.Match("alice@example.com", "example.com", "", false); got != nil {
		t.Errorf("unknown entity type matched: %+v", got)
	}
}

// TestStaticBlockListLookup exercises the in-memory lookup adapter.
func TestStaticBlockListLookup(t *testing.T) {
	list := &delivery.BlockList{
		UserID: "bob@example.com",
		Entries: []delivery.BlockEntry{userEntry("alice@example.com", semp.AckRejected)},
	}
	lookup := &delivery.StaticBlockListLookup{
		Lists: map[string]*delivery.BlockList{
			"bob@example.com": list,
		},
	}
	got, err := lookup.Lookup(context.Background(), "BOB@EXAMPLE.COM")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if got == nil {
		t.Fatal("Lookup returned nil for known recipient")
	}
	if got.UserID != "bob@example.com" {
		t.Errorf("UserID = %q, want bob@example.com", got.UserID)
	}
	got, err = lookup.Lookup(context.Background(), "carol@example.com")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil for unknown recipient, got %+v", got)
	}
}
