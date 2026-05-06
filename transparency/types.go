// Package transparency implements the wire-record types and
// Merkle-tree primitives for SEMP key transparency per
// TRANSPARENCY.md.
//
// A domain supporting key transparency maintains a single
// append-only RFC 6962 Merkle tree of key events. Clients fetching
// keys augment the response with a Signed Tree Head (STH) and an
// inclusion proof so a third party can verify the published key
// matches the same key the domain has shown to every other client.
//
// Server-side log storage, the §2.4 HTTP endpoints, the §6 monitor
// behavior, and the §5 gossip-via-observations integration are
// operational and live in higher-level packages. This package
// covers the types every transparency participant shares: log
// entries, signed tree heads, inclusion and consistency proof
// records, plus RFC 6962 leaf and proof verification primitives.
package transparency

import "time"

// Wire-level type discriminators per TRANSPARENCY.md.
const (
	LogEntryVersion       = "1.0.0"
	SignedTreeHeadVersion = "1.0.0"
)

// LogEntryEvent names the kind of key event recorded as a leaf
// per TRANSPARENCY.md §2.2.
type LogEntryEvent string

// Log entry events.
const (
	// EventPublish is an initial key publication.
	EventPublish LogEntryEvent = "publish"

	// EventRotate is a key rotation. Supersedes names the key
	// being rotated out.
	EventRotate LogEntryEvent = "rotate"

	// EventRevoke records a revocation. RevokedAt and
	// RevokedReason are populated; PublicKey echoes the revoked
	// key for completeness.
	EventRevoke LogEntryEvent = "revoke"
)

// KeyType names the SEMP key kind being recorded per TRANSPARENCY.md
// §2.2 and KEY.md §1.
type KeyType string

// Key types recorded in the log.
const (
	KeyTypeIdentity   KeyType = "identity"
	KeyTypeEncryption KeyType = "encryption"
)

// LogEntry is one leaf of the transparency Merkle tree per
// TRANSPARENCY.md §2.2. Insertion order is the leaf's position; the
// log MUST NOT remove or reorder leaves.
//
// The leaf hash is SHA-256(0x00 || canonical_json_bytes) per RFC
// 6962 domain separation. Use HashLeaf for the standard
// computation.
type LogEntry struct {
	Event         LogEntryEvent `json:"event"`
	UserID        string        `json:"user_id"`
	KeyID         string        `json:"key_id"`
	KeyType       KeyType       `json:"key_type"`
	Algorithm     string        `json:"algorithm"`
	PublicKey     string        `json:"public_key"` // base64
	Created       time.Time     `json:"created"`
	Expires       *time.Time    `json:"expires"`        // nullable
	RevokedAt     *time.Time    `json:"revoked_at"`     // populated only on revoke
	RevokedReason *string       `json:"revoked_reason"` // populated only on revoke
	Supersedes    *string       `json:"supersedes"`     // populated only on rotate
	LogTimestamp  time.Time     `json:"log_timestamp"`
}

// Signature is the reusable signature block used by the STH per
// §2.3.
type Signature struct {
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"key_id"`
	Value     string `json:"value"`
}

// SignedTreeHead is the periodic published commitment per
// TRANSPARENCY.md §2.3. Domains MUST publish a fresh STH at least
// every hour; verifiers reject STHs older than 1 hour by the
// CONFORMANCE.md §9.3.1 tolerance.
type SignedTreeHead struct {
	LogSize   int64     `json:"log_size"`
	RootHash  string    `json:"root_hash"` // base64
	Timestamp time.Time `json:"timestamp"`
	Signature Signature `json:"signature"`
}

// MaxSTHFreshness is the spec's STH staleness ceiling per §2.3.
// Verifiers reject STHs whose timestamp is more than this old.
const MaxSTHFreshness = time.Hour

// InclusionProof is the §3.1 proof that LeafHash sits at LeafIndex
// in a tree of size LogSize whose root is published by an STH.
type InclusionProof struct {
	LogSize   int64    `json:"log_size"`
	LeafHash  string   `json:"leaf_hash"`  // base64
	LeafIndex int64    `json:"leaf_index"`
	Path      []string `json:"path"`        // base64 sibling hashes
}

// ConsistencyProof is the §3.2 proof that the tree of size FromSize
// is a prefix of the tree of size ToSize (i.e., the log was not
// rewritten between those sizes).
type ConsistencyProof struct {
	FromSize int64    `json:"from_size"`
	ToSize   int64    `json:"to_size"`
	Path     []string `json:"path"` // base64 hashes
}
