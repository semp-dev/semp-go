package session

import "time"

// MessageType is the wire-level type discriminator for rekey messages.
const MessageType = "SEMP_REKEY"

// Rekey steps (HANDSHAKE.md §1.4 SEMP_REKEY discriminator).
const (
	StepRekeyInit     = "init"
	StepRekeyAccepted = "accepted"
	StepRekeyRejected = "rejected"
)

// RekeyInit is the rekey-init message sent by the initiating party to
// rotate session keys without a full re-authentication (SESSION.md §3.2).
//
// The message is encrypted under the current K_enc_*2* and MACed under the
// corresponding K_mac_*2* before transmission. Possession of the current
// session keys is the only authentication required.
type RekeyInit struct {
	Type            string         `json:"type"` // always SEMP_REKEY
	Step            string         `json:"step"` // always StepRekeyInit
	Version         string         `json:"version"`
	SessionID       string         `json:"session_id"`
	NewEphemeralKey EphemeralKey   `json:"new_ephemeral_key"`
	RekeyNonce      string         `json:"rekey_nonce"`
}

// RekeyAccepted is the responder's acceptance of a rekey exchange.
type RekeyAccepted struct {
	Type            string       `json:"type"`
	Step            string       `json:"step"` // StepRekeyAccepted
	Version         string       `json:"version"`
	SessionID       string       `json:"session_id"`
	NewSessionID    string       `json:"new_session_id"`
	NewEphemeralKey EphemeralKey `json:"new_ephemeral_key"`
	RekeyNonce      string       `json:"rekey_nonce"`
	ResponderNonce  string       `json:"responder_nonce"`
}

// RekeyRejected is the responder's rejection of a rekey exchange. The
// reason code is one of session_expired, rekey_unsupported, or rate_limited
// per SESSION.md §3.2.
type RekeyRejected struct {
	Type       string `json:"type"`
	Step       string `json:"step"` // StepRekeyRejected
	Version    string `json:"version"`
	SessionID  string `json:"session_id"`
	ReasonCode string `json:"reason_code"`
	Reason     string `json:"reason"`
}

// EphemeralKey is the new ephemeral public key offered or accepted in a
// rekey exchange.
type EphemeralKey struct {
	Algorithm string `json:"algorithm"`
	Key       string `json:"key"`
	KeyID     string `json:"key_id"`
}

// RekeyThreshold is the fraction of TTL at which clients SHOULD initiate
// rekeying. SESSION.md §3.1 recommends 80%.
const RekeyThreshold = 0.8

// MaxRekeysPerSession is the upper bound on rekey events per session
// lifetime per SESSION.md §3.5.
const MaxRekeysPerSession = 10

// MinRekeyInterval is the minimum spacing between rekey events per
// SESSION.md §3.5.
const MinRekeyInterval = 1 * time.Minute
