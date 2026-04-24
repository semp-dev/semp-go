package seal

import (
	"semp.dev/semp-go/crypto"
	"semp.dev/semp-go/extensions"
	"semp.dev/semp-go/keys"
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
	// entry per recipient client only (servers cannot read the enclosure).
	EnclosureRecipients RecipientMap `json:"enclosure_recipients"`

	// FirstContactToken carries a solved proof-of-work token when the
	// envelope is a resubmission in response to a `policy_forbidden`
	// first-contact rejection (HANDSHAKE.md section 2.2a.4,
	// DELIVERY.md section 6.4). Nil when the recipient's policy does
	// not require a token or when no prior rejection has been solved.
	FirstContactToken *FirstContactToken `json:"first_contact_token"`

	// Extensions are seal-layer extensions, visible to all routing servers.
	Extensions extensions.Map `json:"extensions,omitempty"`
}

// FirstContactToken is a solved proof-of-work challenge presented by a
// sender in response to a recipient's first-contact policy gate
// (HANDSHAKE.md section 2.2a.4). The token binds the solved work to
// the specific envelope via its postmark_id, so a token solved for one
// envelope cannot be reused on another.
type FirstContactToken struct {
	// ChallengeID echoes the challenge_id of the rejection that issued
	// this challenge. The recipient server uses it to locate the
	// recorded challenge state.
	ChallengeID string `json:"challenge_id"`

	// Algorithm is the hash algorithm for the PoW. MUST be "sha256".
	Algorithm string `json:"algorithm"`

	// Prefix is the base64-encoded prefix as issued by the recipient
	// server. Its construction is
	//   base64(random_bytes(16) || SHA-256(sender_domain || recipient_address || postmark_id))
	// per HANDSHAKE.md section 2.2a.3.
	Prefix string `json:"prefix"`

	// Difficulty is the leading-zero-bit count required on the PoW
	// hash, as issued. Subject to the difficulty cap (28) in
	// HANDSHAKE.md section 2.2a.2.
	Difficulty int `json:"difficulty"`

	// PostmarkID is the postmark.id of the envelope this token is
	// bound to. MUST equal the carrying envelope's postmark.id.
	PostmarkID string `json:"postmark_id"`

	// Nonce is the base64-encoded nonce that, when hashed with Prefix,
	// satisfies Difficulty.
	Nonce string `json:"nonce"`

	// IssuedBy is the hostname of the recipient server that issued the
	// originating challenge.
	IssuedBy string `json:"issued_by"`
}

// RecipientMap maps a key fingerprint (recipient server domain key or
// recipient client encryption key) to the base64-encoded wrapped symmetric
// key (K_brief or K_enclosure) encrypted under that recipient's public key.
type RecipientMap map[keys.Fingerprint]string
