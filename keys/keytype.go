package keys

// Type identifies the role of a SEMP key (KEY.md §1).
type Type string

// Persistent key types. Session keys are ephemeral and live in package
// session, not here.
const (
	TypeDomain     Type = "domain"
	TypeIdentity   Type = "identity"
	TypeEncryption Type = "encryption"
	TypeDevice     Type = "device"
)

// String satisfies fmt.Stringer.
func (t Type) String() string { return string(t) }
