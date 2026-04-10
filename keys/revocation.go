package keys

import "time"

// Reason classifies why a key was revoked (KEY.md §8.2, ERRORS.md §8).
type Reason string

// Defined revocation reasons.
const (
	ReasonKeyCompromise        Reason = "key_compromise"
	ReasonSuperseded           Reason = "superseded"
	ReasonCessationOfOperation Reason = "cessation_of_operation"
	ReasonTemporaryHold        Reason = "temporary_hold"
)

// Revocation is the per-key revocation record returned in a key response
// (KEY.md §8.4) or stored as part of a SEMP_KEY_REVOCATION publication
// (KEY.md §8.1).
type Revocation struct {
	// Reason classifies the revocation.
	Reason Reason `json:"reason"`

	// RevokedAt is the timestamp at which the key was revoked.
	RevokedAt time.Time `json:"revoked_at"`

	// ReplacementKeyID is the fingerprint of a successor key, if known.
	// Senders SHOULD fetch the replacement when present (KEY.md §8.3).
	ReplacementKeyID Fingerprint `json:"replacement_key_id,omitempty"`
}

// Reversible reports whether the revocation may be lifted. Only
// ReasonTemporaryHold is potentially reversible; all others are permanent.
func (r *Revocation) Reversible() bool {
	if r == nil {
		return false
	}
	return r.Reason == ReasonTemporaryHold
}

// RevocationPublication is the wire format used when a domain or user
// publishes a batch of revocation records.
//
// Reference: KEY.md §8.1.
type RevocationPublication struct {
	Type        string             `json:"type"` // always "SEMP_KEY_REVOCATION"
	Version     string             `json:"version"`
	RevokedKeys []RevokedKeyEntry  `json:"revoked_keys"`
	Signature   PublicationSignature `json:"signature"`
}

// RevokedKeyEntry is one row inside a RevocationPublication.
type RevokedKeyEntry struct {
	KeyID            Fingerprint `json:"key_id"`
	Address          string      `json:"address,omitempty"`
	Reason           Reason      `json:"reason"`
	RevokedAt        time.Time   `json:"revoked_at"`
	ReplacementKeyID Fingerprint `json:"replacement_key_id,omitempty"`
}

// PublicationSignature is the signature attached to a key publication or
// revocation publication.
type PublicationSignature struct {
	Algorithm string      `json:"algorithm"`
	KeyID     Fingerprint `json:"key_id"`
	Value     string      `json:"value"`
}
