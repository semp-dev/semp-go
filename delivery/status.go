package delivery

import "time"

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

// MatchVisibility reports whether the given sender matches the visibility
// rules and should therefore receive the recipient's status. The default
// mode (VisibilityNobody) MUST return false.
//
// TODO(DELIVERY.md §1.6.4): implement domain / server / user matching.
func MatchVisibility(v *Visibility, senderAddress, senderDomain, senderServer string) bool {
	_, _, _, _ = v, senderAddress, senderDomain, senderServer
	return false
}
