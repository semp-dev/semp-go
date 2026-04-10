package seal

import (
	"github.com/semp-dev/semp-go/crypto"
	"github.com/semp-dev/semp-go/extensions"
	"github.com/semp-dev/semp-go/keys"
)

// Seal is the cryptographic seal that wraps every envelope (ENVELOPE.md §4.1).
type Seal struct {
	// Algorithm is the algorithm suite used for the wrapped keys and
	// integrity proofs, e.g. "pq-kyber768-x25519".
	Algorithm crypto.SuiteID `json:"algorithm"`

	// KeyID is the fingerprint of the sender domain key used to produce
	// Signature.
	KeyID keys.Fingerprint `json:"key_id"`

	// Signature is the sender domain key signature over the canonical
	// envelope bytes (with Signature and SessionMAC set to "" and
	// postmark.hop_count omitted).
	Signature string `json:"signature"`

	// SessionMAC is the K_env_mac MAC over the same canonical bytes.
	// Verifiable only by the receiving server, which holds the session key.
	SessionMAC string `json:"session_mac"`

	// BriefRecipients is the per-recipient wrap of K_brief. Two entries per
	// recipient: one keyed by the recipient server's domain key fingerprint
	// (so the server can decrypt the brief for policy enforcement), and one
	// keyed by the recipient client's encryption key fingerprint.
	BriefRecipients RecipientMap `json:"brief_recipients"`

	// EnclosureRecipients is the per-recipient wrap of K_enclosure. One
	// entry per recipient client only — servers cannot read the enclosure.
	EnclosureRecipients RecipientMap `json:"enclosure_recipients"`

	// Extensions are seal-layer extensions, visible to all routing servers.
	Extensions extensions.Map `json:"extensions,omitempty"`
}

// RecipientMap maps a key fingerprint (recipient server domain key or
// recipient client encryption key) to the base64-encoded wrapped symmetric
// key (K_brief or K_enclosure) encrypted under that recipient's public key.
type RecipientMap map[keys.Fingerprint]string
