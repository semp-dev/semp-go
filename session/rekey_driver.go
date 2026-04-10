package session

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	semp "github.com/semp-dev/semp-go"
	"github.com/semp-dev/semp-go/crypto"
	"github.com/semp-dev/semp-go/keys"
)

// RekeyStream is the minimal message-stream interface a rekey driver
// needs from a transport. transport.Conn and the handshake /
// inboxd MessageStream interfaces all satisfy it structurally.
type RekeyStream interface {
	Send(ctx context.Context, msg []byte) error
	Recv(ctx context.Context) ([]byte, error)
}

// Rekeyer runs the client-initiated side of a SEMP_REKEY exchange
// (SESSION.md §3). It is stateful: each call to Rekey consumes one
// rekey slot on the session.
//
// Usage:
//
//	r := &session.Rekeyer{Suite: suite, Session: sess}
//	err := r.Rekey(ctx, stream)
//	if err == nil {
//	    // sess.ID is now the new session ID
//	    // sess.PreviousID holds the previous one during the transition window
//	}
type Rekeyer struct {
	// Suite is the negotiated cryptographic suite. Must match the one
	// used to establish the session.
	Suite crypto.Suite

	// Session is the session to rekey. On success, Session.ApplyRekey
	// is called with the new keys, the new ID, and the current time.
	Session *Session
}

// Rekey executes the two-message SEMP_REKEY exchange over stream:
//
//  1. Generate a fresh ephemeral key pair and rekey nonce.
//  2. Send RekeyInit.
//  3. Receive RekeyAccepted (or RekeyRejected).
//  4. Compute the shared secret via X25519 against the responder's
//     ephemeral public key.
//  5. Derive the five new session keys via crypto.DeriveRekeyKeys
//     with salt = rekey_nonce || responder_nonce.
//  6. Call Session.ApplyRekey to install the new keys and ID.
//
// Rekey is NOT invoked automatically — callers decide when to rekey
// (typically at 80% TTL per SESSION.md §3.1).
//
// Reference: SESSION.md §3.2 – §3.5.
func (r *Rekeyer) Rekey(ctx context.Context, stream RekeyStream) error {
	if r == nil || r.Suite == nil || r.Session == nil {
		return errors.New("session: nil rekeyer")
	}
	now := time.Now()
	if ok, code, reason := r.Session.CanRekey(now); !ok {
		return fmt.Errorf("session: cannot rekey: %s: %s", code, reason)
	}

	// Generate fresh ephemeral key material.
	ephPub, ephPriv, err := r.Suite.KEM().GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("session: rekey ephemeral keypair: %w", err)
	}
	defer crypto.Zeroize(ephPriv)

	rekeyNonce := make([]byte, 32)
	if _, err := rand.Read(rekeyNonce); err != nil {
		return fmt.Errorf("session: rekey nonce: %w", err)
	}

	initMsg := RekeyInit{
		Type:      MessageType,
		Step:      StepRekeyInit,
		Version:   semp.ProtocolVersion,
		SessionID: r.Session.ID,
		NewEphemeralKey: EphemeralKey{
			Algorithm: string(r.Suite.ID()),
			Key:       base64.StdEncoding.EncodeToString(ephPub),
			KeyID:     string(keys.Compute(ephPub)),
		},
		RekeyNonce: base64.StdEncoding.EncodeToString(rekeyNonce),
	}
	initBytes, err := json.Marshal(&initMsg)
	if err != nil {
		return fmt.Errorf("session: marshal rekey init: %w", err)
	}
	if err := stream.Send(ctx, initBytes); err != nil {
		return fmt.Errorf("session: send rekey init: %w", err)
	}

	respBytes, err := stream.Recv(ctx)
	if err != nil {
		return fmt.Errorf("session: recv rekey response: %w", err)
	}
	step, err := peekRekeyStep(respBytes)
	if err != nil {
		return err
	}
	switch step {
	case StepRekeyRejected:
		var rej RekeyRejected
		if err := json.Unmarshal(respBytes, &rej); err != nil {
			return fmt.Errorf("session: parse rekey_rejected: %w", err)
		}
		return fmt.Errorf("session: rekey rejected: %s: %s", rej.ReasonCode, rej.Reason)
	case StepRekeyAccepted:
		// fall through
	default:
		return fmt.Errorf("session: unexpected rekey step %q", step)
	}

	var acc RekeyAccepted
	if err := json.Unmarshal(respBytes, &acc); err != nil {
		return fmt.Errorf("session: parse rekey_accepted: %w", err)
	}
	if acc.SessionID != r.Session.ID {
		return fmt.Errorf("session: rekey_accepted session_id mismatch: got %s want %s", acc.SessionID, r.Session.ID)
	}
	// Sanity: responder MUST echo our nonce.
	if acc.RekeyNonce != initMsg.RekeyNonce {
		return errors.New("session: rekey_accepted echoed wrong rekey_nonce")
	}

	responderEphPub, err := base64.StdEncoding.DecodeString(acc.NewEphemeralKey.Key)
	if err != nil {
		return fmt.Errorf("session: responder ephemeral key base64: %w", err)
	}
	responderNonce, err := base64.StdEncoding.DecodeString(acc.ResponderNonce)
	if err != nil {
		return fmt.Errorf("session: responder_nonce base64: %w", err)
	}

	shared, err := r.Suite.KEM().Agree(ephPriv, responderEphPub)
	if err != nil {
		return fmt.Errorf("session: rekey DH: %w", err)
	}
	defer crypto.Zeroize(shared)

	newKeys, err := crypto.DeriveRekeyKeys(r.Suite.KDF(), shared, rekeyNonce, responderNonce)
	if err != nil {
		return fmt.Errorf("session: derive rekey keys: %w", err)
	}

	r.Session.ApplyRekey(acc.NewSessionID, newKeys, time.Now())
	return nil
}

// RekeyHandler runs the responder side of a SEMP_REKEY exchange. It is
// invoked with an already-received RekeyInit byte slice (which the
// dispatch loop has just read off the stream). It writes either a
// RekeyAccepted or a RekeyRejected message back to stream.
//
// On success, the supplied *Session is mutated via ApplyRekey so that
// subsequent operations use the new keys. On rejection, the session is
// left untouched.
type RekeyHandler struct {
	Suite   crypto.Suite
	Session *Session
}

// Handle processes one rekey init message and writes the response.
// Returns nil on either rekey_accepted or rekey_rejected (both are
// "handled" outcomes); returns a non-nil error only on transport-level
// or decode failures that prevent a response from being written.
func (h *RekeyHandler) Handle(ctx context.Context, stream RekeyStream, raw []byte) error {
	if h == nil || h.Suite == nil || h.Session == nil {
		return errors.New("session: nil rekey handler")
	}
	var init RekeyInit
	if err := json.Unmarshal(raw, &init); err != nil {
		return fmt.Errorf("session: parse rekey_init: %w", err)
	}
	if init.Type != MessageType || init.Step != StepRekeyInit {
		return fmt.Errorf("session: unexpected rekey type/step: %s/%s", init.Type, init.Step)
	}
	if init.SessionID != h.Session.ID {
		return h.reject(ctx, stream, init.SessionID, "session_expired",
			fmt.Sprintf("session %s is not the current session", init.SessionID))
	}
	now := time.Now()
	if ok, code, reason := h.Session.CanRekey(now); !ok {
		return h.reject(ctx, stream, init.SessionID, code, reason)
	}

	initiatorEphPub, err := base64.StdEncoding.DecodeString(init.NewEphemeralKey.Key)
	if err != nil {
		return h.reject(ctx, stream, init.SessionID, "rekey_unsupported",
			fmt.Sprintf("invalid new_ephemeral_key: %v", err))
	}
	initiatorNonce, err := base64.StdEncoding.DecodeString(init.RekeyNonce)
	if err != nil {
		return h.reject(ctx, stream, init.SessionID, "rekey_unsupported",
			fmt.Sprintf("invalid rekey_nonce: %v", err))
	}

	// Generate OUR ephemeral keypair and responder nonce.
	respEphPub, respEphPriv, err := h.Suite.KEM().GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("session: responder ephemeral: %w", err)
	}
	defer crypto.Zeroize(respEphPriv)

	responderNonce := make([]byte, 32)
	if _, err := rand.Read(responderNonce); err != nil {
		return fmt.Errorf("session: responder nonce: %w", err)
	}

	// Shared secret + new session keys.
	shared, err := h.Suite.KEM().Agree(respEphPriv, initiatorEphPub)
	if err != nil {
		return h.reject(ctx, stream, init.SessionID, "rekey_unsupported",
			fmt.Sprintf("DH failed: %v", err))
	}
	defer crypto.Zeroize(shared)
	newKeys, err := crypto.DeriveRekeyKeys(h.Suite.KDF(), shared, initiatorNonce, responderNonce)
	if err != nil {
		return fmt.Errorf("session: derive rekey keys: %w", err)
	}

	// Mint a new session ID (simple counter-based for now — the spec
	// says ULID RECOMMENDED).
	newID, err := newRekeySessionID()
	if err != nil {
		return fmt.Errorf("session: new session id: %w", err)
	}

	acc := RekeyAccepted{
		Type:         MessageType,
		Step:         StepRekeyAccepted,
		Version:      semp.ProtocolVersion,
		SessionID:    init.SessionID,
		NewSessionID: newID,
		NewEphemeralKey: EphemeralKey{
			Algorithm: string(h.Suite.ID()),
			Key:       base64.StdEncoding.EncodeToString(respEphPub),
			KeyID:     string(keys.Compute(respEphPub)),
		},
		RekeyNonce:     init.RekeyNonce,
		ResponderNonce: base64.StdEncoding.EncodeToString(responderNonce),
	}
	accBytes, err := json.Marshal(&acc)
	if err != nil {
		return fmt.Errorf("session: marshal rekey_accepted: %w", err)
	}
	if err := stream.Send(ctx, accBytes); err != nil {
		return fmt.Errorf("session: send rekey_accepted: %w", err)
	}

	h.Session.ApplyRekey(newID, newKeys, now)
	return nil
}

// reject writes a rekey_rejected message to stream. Returns nil on
// successful write; the caller treats "we sent a rejection" as a
// handled outcome.
func (h *RekeyHandler) reject(ctx context.Context, stream RekeyStream, sessionID, code, reason string) error {
	rej := RekeyRejected{
		Type:       MessageType,
		Step:       StepRekeyRejected,
		Version:    semp.ProtocolVersion,
		SessionID:  sessionID,
		ReasonCode: code,
		Reason:     reason,
	}
	out, err := json.Marshal(&rej)
	if err != nil {
		return fmt.Errorf("session: marshal rekey_rejected: %w", err)
	}
	return stream.Send(ctx, out)
}

// peekRekeyStep extracts the `step` field from a SEMP_REKEY message
// without fully unmarshaling the rest of the structure.
func peekRekeyStep(data []byte) (string, error) {
	var probe struct {
		Type string `json:"type"`
		Step string `json:"step"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return "", fmt.Errorf("session: peek rekey step: %w", err)
	}
	if probe.Type != MessageType {
		return "", fmt.Errorf("session: unexpected type %q in rekey stream", probe.Type)
	}
	return probe.Step, nil
}

// newRekeySessionID returns a fresh session ID for a rekey exchange.
// The format is a 26-character Crockford base32 string similar to the
// one handshake.newULID produces — we inline a tiny generator rather
// than import handshake (which would create a cycle).
func newRekeySessionID() (string, error) {
	const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	// Stamp the high 48 bits with the current millisecond timestamp so
	// the result sorts roughly by time.
	ms := uint64(time.Now().UnixMilli())
	buf[0] = byte(ms >> 40)
	buf[1] = byte(ms >> 32)
	buf[2] = byte(ms >> 24)
	buf[3] = byte(ms >> 16)
	buf[4] = byte(ms >> 8)
	buf[5] = byte(ms)
	// 26-char encoding of 16 bytes (128 bits); we take 26 chars and
	// pad with the last alphabet char if we run short.
	out := make([]byte, 26)
	for i := 0; i < 26; i++ {
		idx := (int(buf[i%16]) >> ((i % 2) * 4)) & 0x1f
		out[i] = alphabet[idx]
	}
	return string(out), nil
}
