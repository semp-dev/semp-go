package delivery

import (
	"context"
	"strings"
	"time"

	semp "github.com/semp-dev/semp-go"
)

// EntityType identifies what kind of entity a block entry targets.
//
// Reference: DELIVERY.md §4.3.
type EntityType string

// EntityType values.
const (
	EntityUser   EntityType = "user"
	EntityDomain EntityType = "domain"
	EntityServer EntityType = "server"
)

// Entity is the JSON representation of the block entry's `entity` object.
// Only the field appropriate for Type is populated.
type Entity struct {
	Type     EntityType `json:"type"`
	Address  string     `json:"address,omitempty"`  // for EntityUser
	Domain   string     `json:"domain,omitempty"`   // for EntityDomain
	Hostname string     `json:"hostname,omitempty"` // for EntityServer
}

// Scope is the delivery-time applicability of a block entry
// (DELIVERY.md §4.4).
type Scope string

// Scope values.
const (
	ScopeAll    Scope = "all"
	ScopeDirect Scope = "direct"
	ScopeGroup  Scope = "group"
)

// BlockEntry is one row in a user's block list (DELIVERY.md §4.1).
type BlockEntry struct {
	ID                string              `json:"id"`
	Entity            Entity              `json:"entity"`
	Acknowledgment    semp.Acknowledgment `json:"acknowledgment"`
	Reason            string              `json:"reason,omitempty"`
	Scope             Scope               `json:"scope"`
	CreatedAt         time.Time           `json:"created_at"`
	ExpiresAt         *time.Time          `json:"expires_at,omitempty"`
	CreatedByDeviceID string              `json:"created_by_device_id"`
	Extensions        map[string]any      `json:"extensions,omitempty"`
}

// BlockList is a user's full block list, stored encrypted at rest per
// DELIVERY.md §6.3. The list is server-readable only when explicitly
// decrypted by the owning user's authenticated client device — the server
// MUST NOT be able to read it in plaintext as a long-running background
// process.
type BlockList struct {
	UserID  string       `json:"user_id"`
	Version uint64       `json:"list_version"`
	Entries []BlockEntry `json:"entries"`
}

// Match returns the entry that matches the given sender, or nil if none
// applies. Matching uses cryptographically verified identifiers per
// DELIVERY.md §4.3 closing paragraph: domain names from the verified
// postmark and key fingerprints from the verified handshake identity.
//
// Inputs:
//   - senderAddress: the full sender address from brief.from
//     (e.g. "alice@example.com"). Empty string disables user-level
//     matching.
//   - senderDomain: the verified sender domain from postmark.from_domain
//     (e.g. "example.com"). Empty string disables domain-level matching.
//   - senderServer: the SEMP server hostname through which the envelope
//     was routed (e.g. "semp.example.com"). Empty string disables
//     server-level matching.
//   - isGroup: true when the envelope is part of a group/mailing-list
//     thread (brief.group_id is non-empty). Used to enforce ScopeDirect /
//     ScopeGroup filtering per DELIVERY.md §4.4.
//
// Match enforces entity-type precedence: a `user` entry beats a `server`
// entry, which in turn beats a `domain` entry. The first matching entry
// at the most specific level is returned. Entries past their `expires_at`
// are ignored.
//
// All string comparisons are case-insensitive (addresses and DNS names
// are case-folded by the SEMP wire layer, but the block-list payload is
// user-supplied and could be entered in mixed case).
func (l *BlockList) Match(senderAddress, senderDomain, senderServer string, isGroup bool) *BlockEntry {
	if l == nil || len(l.Entries) == 0 {
		return nil
	}
	now := time.Now().UTC()
	address := strings.ToLower(senderAddress)
	domain := strings.ToLower(senderDomain)
	server := strings.ToLower(senderServer)

	// Walk the list once and remember the most-specific match. We
	// scan in a single pass and only upgrade the candidate when we
	// see a strictly more specific entity type. The precedence order
	// is user > server > domain.
	const (
		rankNone   = 0
		rankDomain = 1
		rankServer = 2
		rankUser   = 3
	)
	var (
		bestRank  int
		bestEntry *BlockEntry
	)

	for i := range l.Entries {
		e := &l.Entries[i]
		if e.ExpiresAt != nil && !e.ExpiresAt.IsZero() && !now.Before(*e.ExpiresAt) {
			continue
		}
		if !scopeApplies(e.Scope, isGroup) {
			continue
		}
		var rank int
		switch e.Entity.Type {
		case EntityUser:
			if address == "" || strings.ToLower(e.Entity.Address) != address {
				continue
			}
			rank = rankUser
		case EntityServer:
			if server == "" || strings.ToLower(e.Entity.Hostname) != server {
				continue
			}
			rank = rankServer
		case EntityDomain:
			if domain == "" || strings.ToLower(e.Entity.Domain) != domain {
				continue
			}
			rank = rankDomain
		default:
			// Unknown entity type — ignore for forward compatibility.
			continue
		}
		if rank > bestRank {
			bestRank = rank
			bestEntry = e
			if bestRank == rankUser {
				// Highest possible precedence; nothing can beat
				// this entry.
				return bestEntry
			}
		}
	}
	return bestEntry
}

// scopeApplies reports whether an entry with the given scope should be
// considered for an envelope whose group flag is isGroup.
func scopeApplies(scope Scope, isGroup bool) bool {
	switch scope {
	case "", ScopeAll:
		// Empty scope is treated as ScopeAll for forward compatibility
		// — a producer that omits the field gets the broadest match.
		return true
	case ScopeDirect:
		return !isGroup
	case ScopeGroup:
		return isGroup
	default:
		// Unknown scope: ignore for forward compatibility.
		return false
	}
}

// BlockListLookup is the minimal lookup interface the delivery pipeline
// needs to enforce user-level blocks at step 8 of DELIVERY.md §2.
//
// Implementations return the recipient's full block list. Returning
// (nil, nil) is the canonical "no list configured" answer and is
// treated as "no entries match". Returning a non-nil error stops the
// pipeline at the recipient with a transport-level error rather than
// a per-recipient rejection.
type BlockListLookup interface {
	Lookup(ctx context.Context, recipient string) (*BlockList, error)
}

// StaticBlockListLookup is a trivial in-memory BlockListLookup keyed by
// recipient address. Useful for tests and the demo binaries — production
// deployments should plug in a real persistent store.
type StaticBlockListLookup struct {
	Lists map[string]*BlockList
}

// Lookup implements BlockListLookup. Returns the entry from Lists keyed
// by recipient (case-insensitive), or (nil, nil) if no list exists for
// that recipient.
func (s *StaticBlockListLookup) Lookup(_ context.Context, recipient string) (*BlockList, error) {
	if s == nil || s.Lists == nil {
		return nil, nil
	}
	if l, ok := s.Lists[strings.ToLower(recipient)]; ok {
		return l, nil
	}
	return nil, nil
}
