package recovery

import "time"

// BundleType is the wire-level type discriminator for backup
// bundles per RECOVERY.md §2.1.
const BundleType = "SEMP_BACKUP_BUNDLE"

// AEAD algorithm identifier used for the bundle payload per
// RECOVERY.md §2.5: xchacha20-poly1305 with a 24-byte nonce.
const BundlePayloadAEAD = "xchacha20-poly1305"

// KDFAlgorithm identifier per §2.5.
const KDFAlgorithmArgon2id = "argon2id"

// KDF parameter bounds per RECOVERY.md §2.5.
const (
	// MinKDFMemoryKB is the minimum Argon2id memory cost in KiB.
	// Clients MUST NOT publish a bundle with a weaker setting.
	MinKDFMemoryKB = 65536

	// MinKDFIterations is the minimum Argon2id time cost.
	MinKDFIterations = 2

	// MinKDFParallelism is the minimum Argon2id parallelism (lanes).
	MinKDFParallelism = 1

	// MinKDFSaltBytes is the minimum salt length.
	MinKDFSaltBytes = 16

	// RecommendedKDFMemoryKB matches the §2.5 RECOMMENDED default.
	RecommendedKDFMemoryKB = 262144

	// RecommendedKDFIterations matches the §2.5 RECOMMENDED default.
	RecommendedKDFIterations = 3

	// RecommendedKDFParallelism matches the §2.5 RECOMMENDED default.
	RecommendedKDFParallelism = 4
)

// BundleKDF is the key-derivation parameter block per RECOVERY.md
// §2.1 / §2.5.
type BundleKDF struct {
	Algorithm   string `json:"algorithm"`
	Salt        string `json:"salt"`         // base64
	MemoryKB    uint32 `json:"memory_kb"`
	Iterations  uint32 `json:"iterations"`
	Parallelism uint8  `json:"parallelism"`
}

// RecoveryVerifyPK is the public half of the deterministic recovery
// key pair embedded in a backup bundle per RECOVERY.md §3.3 and
// referenced by §7.5 successor-record verifiers.
type RecoveryVerifyPK struct {
	Algorithm string `json:"algorithm"`
	PublicKey string `json:"public_key"` // base64
}

// BackupBundle is the SEMP_BACKUP_BUNDLE record per RECOVERY.md §2.1.
//
// The bundle is signed by the user's currently active identity
// private key over the canonical bytes with signature.value elided,
// prefixed with SEMP-RECOVERY-BUNDLE: per ENVELOPE.md §4.3.
type BackupBundle struct {
	Type             string           `json:"type"`
	Version          string           `json:"version"`
	UserID           string           `json:"user_id"`
	BundleID         string           `json:"bundle_id"`
	CreatedAt        time.Time        `json:"created_at"`
	Supersedes       *string          `json:"supersedes"` // null-emitting
	KDF              BundleKDF        `json:"kdf"`
	PayloadAlgorithm string           `json:"payload_algorithm"`
	PayloadNonce     string           `json:"payload_nonce"`     // base64
	EncryptedPayload string           `json:"encrypted_payload"` // base64
	RecoveryVerifyPK RecoveryVerifyPK `json:"recovery_verify_pk"`
	Signature        Signature        `json:"signature"`
}

// IdentityKey is the inner identity-key block carried in
// BundlePayload.IdentityKey per §2.3.
type IdentityKey struct {
	Algorithm  string    `json:"algorithm"`
	PublicKey  string    `json:"public_key"`  // base64
	PrivateKey string    `json:"private_key"` // base64
	Created    time.Time `json:"created"`
	Expires    time.Time `json:"expires,omitempty"`
}

// EncryptionKey is one entry in BundlePayload.EncryptionKeys per
// §2.3. Includes superseded and revoked keys so envelopes sealed
// under any historical key remain decryptable after recovery.
type EncryptionKey struct {
	Algorithm    string     `json:"algorithm"`
	KeyID        string     `json:"key_id"`
	PublicKey    string     `json:"public_key"`  // base64
	PrivateKey   string     `json:"private_key"` // base64
	Created      time.Time  `json:"created"`
	Expires      time.Time  `json:"expires,omitempty"`
	SupersededAt *time.Time `json:"superseded_at"` // null-emitting
}

// BundlePayload is the plaintext shape of the encrypted_payload per
// RECOVERY.md §2.3.
//
// The Receipts field carries the user's accumulated delivery
// receipts per §2.3.1; clients SHOULD include every receipt they
// hold (in ascending accepted_at order) so a total device loss
// does not destroy the evidence archive.
type BundlePayload struct {
	IdentityKey    IdentityKey     `json:"identity_key"`
	EncryptionKeys []EncryptionKey `json:"encryption_keys"`
	Receipts       []any           `json:"receipts,omitempty"` // SEMP_DELIVERY_RECEIPT objects
	Metadata       map[string]any  `json:"metadata,omitempty"`
}
