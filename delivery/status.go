package delivery

import (
	"strings"
	"time"
)

// State is the recipient's published availability state (DELIVERY.md §1.6.3).
type State string

// State values.
const (
	StateAvailable    State = "available"
	StateAway         State = "away"
	StateDoNotDisturb State = "do_not_disturb"
)

// RecipientStatus is the optional status object that a recipient server
// MAY attach to a delivered acknowledgment when the sender matches the
// recipient's visibility rules (DELIVERY.md §1.6.1).
type RecipientStatus struct {
	State   State      `json:"state"`
	Message string     `json:"message,omitempty"` // max 256 UTF-8 bytes
	Until   *time.Time `json:"until,omitempty"`
}

// VisibilityMode controls who sees a recipient's status (DELIVERY.md §1.6.4).
type VisibilityMode string

// VisibilityMode values.
const (
	VisibilityEveryone VisibilityMode = "everyone"
	VisibilityDomains  VisibilityMode = "domains"
	VisibilityServers  VisibilityMode = "servers"
	VisibilityUsers    VisibilityMode = "users"
	// VisibilityNobody is the default; no status is ever disclosed.
	VisibilityNobody VisibilityMode = "nobody"
)

// Visibility is the full visibility configuration. Multiple rules are
// evaluated as a union: if any rule matches the sender, the status is
// included.
type Visibility struct {
	Mode  VisibilityMode    `json:"mode"`
	Allow []VisibilityEntry `json:"allow,omitempty"`
}

// VisibilityEntry is one entry in a Visibility allow list.
type VisibilityEntry struct {
	Type    string `json:"type"` // "domain" | "server" | "user"
	Domain  string `json:"domain,omitempty"`
	Server  string `json:"server,omitempty"`
	Address string `json:"address,omitempty"`
}

// MaxStatusMessageBytes is the maximum length of RecipientStatus.Message
// in UTF-8 bytes (DELIVERY.md §1.6.2).
const MaxStatusMessageBytes = 256

// MatchVisibility reports whether the given sender matches the
// recipient's status visibility rules and should therefore receive the
// recipient's status. Per DELIVERY.md §1.6.4:
//
//   - VisibilityNobody (the default) is the closed mode: never
//     disclose, regardless of the Allow list.
//   - VisibilityEveryone is the open mode: always disclose, regardless
//     of the Allow list.
//   - VisibilityDomains, VisibilityServers, VisibilityUsers all walk
//     the Allow list looking for a matching entry. The mode constrains
//     which entry types are honored: in `domains` mode only entries
//     with type `domain` are checked, in `servers` mode only entries
//     with type `server`, and in `users` mode only entries with type
//     `user`. Mismatched entries in the Allow list are ignored.
//
// A nil Visibility (no configuration at all) is equivalent to
// VisibilityNobody.
//
// All comparisons are case-insensitive. Empty sender identifiers
// disable matching for the corresponding entry type — a status policy
// cannot match a sender whose domain we do not know.
func MatchVisibility(v *Visibility, senderAddress, senderDomain, senderServer string) bool {
	if v == nil {
		return false
	}
	switch v.Mode {
	case "", VisibilityNobody:
		return false
	case VisibilityEveryone:
		return true
	case VisibilityDomains, VisibilityServers, VisibilityUsers:
		// fall through to allow-list walk below.
	default:
		// Unknown mode — fail closed.
		return false
	}
	address := strings.ToLower(senderAddress)
	domain := strings.ToLower(senderDomain)
	server := strings.ToLower(senderServer)
	for _, entry := range v.Allow {
		switch entry.Type {
		case "domain":
			if v.Mode != VisibilityDomains {
				continue
			}
			if domain != "" && strings.ToLower(entry.Domain) == domain {
				return true
			}
		case "server":
			if v.Mode != VisibilityServers {
				continue
			}
			if server != "" && strings.ToLower(entry.Server) == server {
				return true
			}
		case "user":
			if v.Mode != VisibilityUsers {
				continue
			}
			if address != "" && strings.ToLower(entry.Address) == address {
				return true
			}
		}
	}
	return false
}
