package handshake

import (
	"encoding/json"
	"time"

	"semp.dev/semp-go/extensions"
)

// MessageType is the wire-level type discriminator for handshake messages.
const MessageType = "SEMP_HANDSHAKE"

// Step is the handshake step discriminator (HANDSHAKE.md §1.4).
type Step string

// Defined handshake steps.
const (
	StepInit              Step = "init"
	StepResponse          Step = "response"
	StepChallenge         Step = "challenge"
	StepChallengeResponse Step = "challenge_response"
	StepConfirm           Step = "confirm"
	StepAccepted          Step = "accepted"
	StepRejected          Step = "rejected"
)

// ChallengeType is the discriminator for the kind of challenge a
// server issues during the handshake. The first (and currently only)
// defined type is ChallengeTypeProofOfWork. Clients that do not
// recognize the challenge_type MUST abort the handshake.
type ChallengeType string

// Defined challenge types.
const (
	// ChallengeTypeProofOfWork requires the client to find a nonce
	// such that SHA-256(prefix || ":" || challenge_id || ":" || nonce)
	// has at least `difficulty` leading zero bits.
	ChallengeTypeProofOfWork ChallengeType = "proof_of_work"
)

// Party is the handshake party discriminator (HANDSHAKE.md §1.4).
type Party string

// Defined parties.
const (
	PartyClient Party = "client"
	PartyServer Party = "server"
)

// EphemeralKey is the on-wire form of an ephemeral public key offered by a
// handshake participant.
type EphemeralKey struct {
	Algorithm string `json:"algorithm"`
	Key       string `json:"key"`
	KeyID     string `json:"key_id"`
}

// Capabilities is the algorithm and extension set offered or accepted
// by a handshake participant (HANDSHAKE.md section 5.2).
//
// Compression was removed from the spec in commit 87e1576. The
// `features` field was renamed to `extensions` to align with the spec
// (capabilities-level extension identifiers, distinct from the
// message-level extensions object).
type Capabilities struct {
	EncryptionAlgorithms []string `json:"encryption_algorithms"`
	Extensions           []string `json:"extensions"`
	MaxEnvelopeSize      int64    `json:"max_envelope_size,omitempty"`
	MaxBatchSize         int      `json:"max_batch_size,omitempty"`
}

// Negotiated is the agreed session parameters returned by the server in
// the response message.
type Negotiated struct {
	EncryptionAlgorithm string   `json:"encryption_algorithm"`
	Extensions          []string `json:"extensions"`
	MaxEnvelopeSize     int64    `json:"max_envelope_size,omitempty"`
	MaxBatchSize        int      `json:"max_batch_size,omitempty"`
}

// ClientInit is the message 1 sent by a client to its home server (HANDSHAKE.md §2.2).
//
// The init message is anonymous: it carries only an ephemeral key and
// capabilities. Nothing in this message identifies the client.
//
// The Extensions field is intentionally NOT marked omitempty: the canonical
// form of an init message MUST always include `"extensions":{}` even when
// no extensions are advertised, so that the confirmation hash in
// VECTORS.md §5.1 reproduces byte for byte.
type ClientInit struct {
	Type               string         `json:"type"`  // SEMP_HANDSHAKE
	Step               Step           `json:"step"`  // StepInit
	Party              Party          `json:"party"` // PartyClient
	Version            string         `json:"version"`
	Nonce              string         `json:"nonce"`
	Transport          string         `json:"transport"`
	ClientEphemeralKey EphemeralKey   `json:"client_ephemeral_key"`
	Capabilities       Capabilities   `json:"capabilities"`
	Extensions         extensions.Map `json:"extensions"`
}

// Challenge is the conditional message 1b returned by a server when it
// requires the client to solve a challenge before allocating session
// resources (HANDSHAKE.md §2.2a). The ChallengeType field identifies
// which kind of challenge this is; Parameters carries the type-specific
// payload as raw JSON.
//
// The first (and currently only) defined challenge type is
// ChallengeTypeProofOfWork, whose Parameters unmarshal into
// PoWChallengeParams. Future challenge types can be added without
// changing this struct — clients that do not recognize the
// challenge_type MUST abort the handshake.
type Challenge struct {
	Type            string          `json:"type"`
	Step            Step            `json:"step"` // StepChallenge
	Party           Party           `json:"party"`
	Version         string          `json:"version"`
	ChallengeID     string          `json:"challenge_id"`
	ChallengeType   ChallengeType   `json:"challenge_type"`
	Parameters      json.RawMessage `json:"parameters"`
	Expires         time.Time       `json:"expires"`
	ServerSignature string          `json:"server_signature"`
}

// ChallengeResponse is the message 1c sent by a client in response
// to a Challenge. The ChallengeType echoes the challenge's type, and
// Solution carries the type-specific solution payload as raw JSON.
type ChallengeResponse struct {
	Type          string          `json:"type"`
	Step          Step            `json:"step"` // StepChallengeResponse
	Party         Party           `json:"party"`
	Version       string          `json:"version"`
	ChallengeID   string          `json:"challenge_id"`
	ChallengeType ChallengeType   `json:"challenge_type"`
	Solution      json.RawMessage `json:"solution"`
}

// PoWChallengeParams is the Parameters payload for
// ChallengeTypeProofOfWork challenges.
type PoWChallengeParams struct {
	Algorithm  string `json:"algorithm"`  // always "sha256"
	Prefix     string `json:"prefix"`     // base64-encoded random bytes
	Difficulty int    `json:"difficulty"` // leading zero bits required
}

// PoWSolutionData is the Solution payload for
// ChallengeTypeProofOfWork challenge responses.
type PoWSolutionData struct {
	Nonce string `json:"nonce"` // base64-encoded nonce
	Hash  string `json:"hash"`  // hex-encoded SHA-256 hash
}

// ServerResponse is message 2 returned by the server (HANDSHAKE.md §2.3).
//
// As with ClientInit, Extensions is not marked omitempty so the canonical
// form always includes `"extensions":{}`.
type ServerResponse struct {
	Type                string             `json:"type"`
	Step                Step               `json:"step"` // StepResponse
	Party               Party              `json:"party"`
	Version             string             `json:"version"`
	SessionID           string             `json:"session_id"`
	ClientNonce         string             `json:"client_nonce"`
	ServerNonce         string             `json:"server_nonce"`
	ServerEphemeralKey  EphemeralKey       `json:"server_ephemeral_key"`
	ServerIdentityProof ServerIdentityProof `json:"server_identity_proof"`
	Negotiated          Negotiated         `json:"negotiated"`
	ServerSignature     string             `json:"server_signature"`
	Extensions          extensions.Map     `json:"extensions"`
}

// ServerIdentityProof is the proof embedded in ServerResponse that the
// server controls its domain's long-term key.
type ServerIdentityProof struct {
	Domain    string `json:"domain"`
	KeyID     string `json:"key_id"`
	Signature string `json:"signature"`
}

// ClientConfirm is message 3 sent by the client (HANDSHAKE.md §2.5). The
// IdentityProof field is the base64 ciphertext of an identity proof block
// encrypted under K_enc_c2s.
type ClientConfirm struct {
	Type             string         `json:"type"`
	Step             Step           `json:"step"` // StepConfirm
	Party            Party          `json:"party"`
	Version          string         `json:"version"`
	SessionID        string         `json:"session_id"`
	ConfirmationHash string         `json:"confirmation_hash"`
	IdentityProof    string         `json:"identity_proof"`
	Extensions       extensions.Map `json:"extensions"`
}

// IdentityProofBlock is the decrypted form of ClientConfirm.IdentityProof
// (HANDSHAKE.md §2.5.2).
type IdentityProofBlock struct {
	ClientID            string         `json:"client_id"`
	ClientIdentity      string         `json:"client_identity"`
	ClientLongTermKeyID string         `json:"client_long_term_key_id"`
	IdentitySignature   string         `json:"identity_signature"`
	Auth                AuthBlock      `json:"auth"`
}

// AuthBlock carries the authentication method and its parameters
// (HANDSHAKE.md §2.6).
type AuthBlock struct {
	Method string         `json:"method"`
	Params map[string]any `json:"params"`
}

// Accepted is the success outcome message 4 (HANDSHAKE.md §2.7).
type Accepted struct {
	Type            string         `json:"type"`
	Step            Step           `json:"step"` // StepAccepted
	Party           Party          `json:"party"`
	Version         string         `json:"version"`
	SessionID       string         `json:"session_id"`
	SessionTTL      int            `json:"session_ttl"`
	Permissions     []string       `json:"permissions,omitempty"`
	ServerSignature string         `json:"server_signature"`
	Extensions      extensions.Map `json:"extensions"`
}

// Rejected is the failure outcome message 4 (HANDSHAKE.md §2.7).
type Rejected struct {
	Type            string         `json:"type"`
	Step            Step           `json:"step"` // StepRejected
	Party           Party          `json:"party"`
	Version         string         `json:"version"`
	SessionID       string         `json:"session_id,omitempty"`
	ReasonCode      string         `json:"reason_code"`
	Reason          string         `json:"reason"`
	ServerSignature string         `json:"server_signature"`
	Extensions      extensions.Map `json:"extensions"`
}
