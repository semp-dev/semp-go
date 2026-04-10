package delivery

import (
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
// applies. Matching MUST use cryptographically verified identifiers
// (DELIVERY.md §4.3 closing paragraph): domain names from the verified
// postmark and key fingerprints from the verified handshake identity.
//
// TODO(DELIVERY.md §4.3): implement strict matching including the scope
// filter and entity-type precedence.
func (l *BlockList) Match(senderAddress, senderDomain, senderServer string, isGroup bool) *BlockEntry {
	_, _, _, _ = senderAddress, senderDomain, senderServer, isGroup
	return nil
}
