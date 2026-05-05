// Package recovery implements the data structures and signing
// primitives for SEMP account recovery per RECOVERY.md. The package
// covers the records every recovery flow shares: the successor
// record (RECOVERY.md §7), the Shamir recovery-set manifest
// (RECOVERY.md §5.2), and the per-device share record (RECOVERY.md
// §5.3). Server-assisted backup bundles (RECOVERY.md §2-4) and the
// restore flow itself (RECOVERY.md §6) are downstream uses of these
// records and live closer to the client / server packages that drive
// them.
package recovery

import "time"

// Wire-level type discriminators per RECOVERY.md.
const (
	SuccessorRecordType        = "SEMP_SUCCESSOR"
	RecoverySetManifestType    = "SEMP_RECOVERY_SET_MANIFEST"
	RecoveryShareRecordType    = "SEMP_RECOVERY_SHARE"
	RecordVersion              = "1.0.0"
)

// SuccessorRecord is a SEMP_SUCCESSOR record per RECOVERY.md §7.2.
// It links a prior identity key to a new identity key after recovery
// or rotation, carrying three independent signatures so third-party
// domains can verify continuity without needing the prior identity
// private key.
type SuccessorRecord struct {
	Type           string    `json:"type"`
	Version        string    `json:"version"`
	UserID         string    `json:"user_id"`
	PriorKeyID     string    `json:"prior_key_id"`
	NewKeyID       string    `json:"new_key_id"`
	NewPublicKey   string    `json:"new_public_key"` // base64
	RecoveredAt    time.Time `json:"recovered_at"`

	// RecoverySignature is produced by recovery_sign_sk (the
	// signing-key half of the recovery key pair derived from the
	// recovery secret per §3.3). Verifies under the
	// recovery_verify_pk that the prior identity key signed at
	// bundle upload time.
	RecoverySignature Signature `json:"recovery_signature"`

	// NewKeySignature is produced by the new identity private key.
	// Confirms the new key's consent to the successor record.
	NewKeySignature Signature `json:"new_key_signature"`

	// DomainSignature is produced by the home server's domain
	// signing key. Confirms the home server's participation per
	// §7.3.
	DomainSignature Signature `json:"domain_signature"`
}

// Signature is the reusable signature block used by recovery records.
// Algorithm and KeyID are covered by the canonical bytes the
// signature is computed over; only Value is elided during signing.
type Signature struct {
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"key_id"`
	Value     string `json:"value"`
}

// DeviceIdentityPubkey is the embedded device-key block carried in
// each manifest contributor entry per RECOVERY.md §5.2.
type DeviceIdentityPubkey struct {
	Algorithm string `json:"algorithm"`
	PublicKey string `json:"public_key"` // base64
	KeyID     string `json:"key_id"`
}

// RecoveryContributor is one device's binding to a Shamir share
// inside a manifest per RECOVERY.md §5.2.
type RecoveryContributor struct {
	ShareIndex           int                  `json:"share_index"`
	DeviceID             string               `json:"device_id"`
	DeviceIdentityPubkey DeviceIdentityPubkey `json:"device_identity_pubkey"`
}

// RecoverySetManifest is a SEMP_RECOVERY_SET_MANIFEST record per
// RECOVERY.md §5.2. It binds each Shamir share index to a specific
// device's identity public key, so a restoring client can verify
// share authenticity against the user's current device directory.
type RecoverySetManifest struct {
	Type         string                `json:"type"`
	Version      string                `json:"version"`
	BundleID     string                `json:"bundle_id"`
	Threshold    int                   `json:"threshold"`
	TotalShares  int                   `json:"total_shares"`
	Contributors []RecoveryContributor `json:"contributors"`
	IssuedAt     time.Time             `json:"issued_at"`
	Signature    Signature             `json:"signature"`
}

// RecoveryShareRecord is a SEMP_RECOVERY_SHARE record per
// RECOVERY.md §5.3. Each share is held by one device and is
// authenticated by that device's identity-key signature.
type RecoveryShareRecord struct {
	Type            string    `json:"type"`
	Version         string    `json:"version"`
	BundleID        string    `json:"bundle_id"`
	ShareIndex      int       `json:"share_index"`
	DeviceID        string    `json:"device_id"`
	Threshold       int       `json:"threshold"`
	TotalShares     int       `json:"total_shares"`
	ShareValue      string    `json:"share_value"` // base64
	IssuedAt        time.Time `json:"issued_at"`
	DeviceSignature Signature `json:"device_signature"`
}
