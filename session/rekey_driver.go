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

	// InitiatorDirection identifies which half of the session keys the
	// initiator uses to encrypt its rekey messages per SESSION.md §3.2.
	// For a client-initiated rekey this is DirectionC2S; for a
	// federation-initiated rekey the initiating server uses whichever
	// half of the session it "owns" (by convention, the side that
	// opened the connection uses c2s).
	//
	// A zero value defaults to DirectionC2S so existing callers that
	// drive a client session keep working without changes.
	InitiatorDirection string
}

// Rekey executes the two-message SEMP_REKEY exchange over stream:
//
//  1. Generate a fresh ephemeral key pair and rekey nonce.
//  2. Seal the RekeyInit under K_enc_{initiator direction} and send.
//  3. Receive the sealed response, open it under the opposite
//     directional keys, parse the inner RekeyAccepted (or RekeyRejected).
//  4. Compute the shared secret via X25519 against the responder's
//     ephemeral public key.
//  5. Derive the five new session keys via crypto.DeriveRekeyKeys
//     with salt = rekey_nonce || responder_nonce.
//  6. Call Session.ApplyRekey to install the new keys and ID.
//
// Both messages are AEAD-sealed under the current session's directional
// keys per SESSION.md §3.2. The AEAD additional data binds each
// ciphertext to the direction label, the current session ID, and the
// corresponding MAC key, so an attacker who somehow extracted the
// encryption key alone still could not forge a message — the MAC
// key is mixed into the AAD.
//
// Rekey is NOT invoked automatically — callers decide when to rekey
// (typically at 80% TTL per SESSION.md §3.1).
//
// Reference: SESSION.md §3.2 – §3.5.
func (r *Rekeyer) Rekey(ctx context.Context, stream RekeyStream) error {
	if r == nil || r.Suite == nil || r.Session == nil {
		return errors.New("session: nil rekeyer")
	}
	initDir := r.InitiatorDirection
	if initDir == "" {
		initDir = DirectionC2S
	}
	respDir := DirectionS2C
	if initDir == DirectionS2C {
		respDir = DirectionC2S
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
	initBytes, err := marshalRekeyBody(&initMsg)
	if err != nil {
		return fmt.Errorf("session: marshal rekey init: %w", err)
	}
	sealed, err := SealRekeyMessage(r.Suite, r.Session, initDir, initBytes)
	if err != nil {
		return fmt.Errorf("session: seal rekey init: %w", err)
	}
	sealedBytes, err := json.Marshal(sealed)
	if err != nil {
		return fmt.Errorf("session: marshal sealed rekey: %w", err)
	}
	if err := stream.Send(ctx, sealedBytes); err != nil {
		return fmt.Errorf("session: send sealed rekey init: %w", err)
	}

	respRaw, err := stream.Recv(ctx)
	if err != nil {
		return fmt.Errorf("session: recv rekey response: %w", err)
	}
	var sealedResp SealedRekey
	if err := json.Unmarshal(respRaw, &sealedResp); err != nil {
		return fmt.Errorf("session: parse sealed rekey response: %w", err)
	}
	if sealedResp.Type != MessageType {
		return fmt.Errorf("session: expected sealed rekey, got type %q", sealedResp.Type)
	}
	if !sealedResp.Sealed {
		return errors.New("session: rekey response is not sealed")
	}
	if sealedResp.Direction != respDir {
		return fmt.Errorf("session: sealed rekey response direction %q, want %q", sealedResp.Direction, respDir)
	}
	respBytes, err := OpenRekeyMessage(r.Suite, r.Session, &sealedResp)
	if err != nil {
		return fmt.Errorf("session: open rekey response: %w", err)
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

	// Initiator-side KEM finalization: decapsulate the responder's
	// wire blob (baseline X25519: just a pub key; hybrid Kyber768+X25519:
	// responderX25519Pub || kyberCiphertext) to derive the shared
	// secret.
	shared, err := r.Suite.KEM().Decapsulate(responderEphPub, ephPriv)
	if err != nil {
		return fmt.Errorf("session: rekey KEM: %w", err)
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
// invoked with an already-received (sealed) SEMP_REKEY byte slice which
// the dispatch loop has just read off the stream. It writes either a
// sealed RekeyAccepted or a sealed RekeyRejected back to stream.
//
// On success, the supplied *Session is mutated via ApplyRekey so that
// subsequent operations use the new keys. On rejection, the session is
// left untouched.
type RekeyHandler struct {
	Suite   crypto.Suite
	Session *Session

	// InitiatorDirection identifies which half of the session keys
	// the INITIATOR uses. The handler uses the opposite direction to
	// seal its response. Zero means DirectionC2S (the client-
	// initiated rekey default), so the handler seals its response
	// under DirectionS2C.
	InitiatorDirection string
}

// Handle processes one sealed SEMP_REKEY message and writes the
// response. Returns nil on either rekey_accepted or rekey_rejected
// (both are "handled" outcomes); returns a non-nil error only on
// transport-level or unseal failures that prevent a response from
// being written.
func (h *RekeyHandler) Handle(ctx context.Context, stream RekeyStream, raw []byte) error {
	if h == nil || h.Suite == nil || h.Session == nil {
		return errors.New("session: nil rekey handler")
	}
	initDir := h.InitiatorDirection
	if initDir == "" {
		initDir = DirectionC2S
	}
	respDir := DirectionS2C
	if initDir == DirectionS2C {
		respDir = DirectionC2S
	}

	// Open the sealed envelope.
	var sealed SealedRekey
	if err := json.Unmarshal(raw, &sealed); err != nil {
		return fmt.Errorf("session: parse sealed rekey: %w", err)
	}
	if sealed.Type != MessageType {
		return fmt.Errorf("session: unexpected sealed type %q", sealed.Type)
	}
	if !sealed.Sealed {
		return errors.New("session: rekey message is not sealed (cleartext not supported)")
	}
	if sealed.Direction != initDir {
		return fmt.Errorf("session: sealed rekey direction %q, expected %q", sealed.Direction, initDir)
	}
	plaintext, err := OpenRekeyMessage(h.Suite, h.Session, &sealed)
	if err != nil {
		// We can't respond under the session keys if the initiator
		// didn't hold them. Return the error to the caller; the
		// dispatch loop will log it and move on.
		return fmt.Errorf("session: open sealed rekey: %w", err)
	}

	var init RekeyInit
	if err := json.Unmarshal(plaintext, &init); err != nil {
		return fmt.Errorf("session: parse rekey_init: %w", err)
	}
	if init.Type != MessageType || init.Step != StepRekeyInit {
		return fmt.Errorf("session: unexpected rekey type/step: %s/%s", init.Type, init.Step)
	}
	if init.SessionID != h.Session.ID {
		return h.reject(ctx, stream, respDir, init.SessionID, "session_expired",
			fmt.Sprintf("session %s is not the current session", init.SessionID))
	}
	now := time.Now()
	if ok, code, reason := h.Session.CanRekey(now); !ok {
		return h.reject(ctx, stream, respDir, init.SessionID, code, reason)
	}

	initiatorEphPub, err := base64.StdEncoding.DecodeString(init.NewEphemeralKey.Key)
	if err != nil {
		return h.reject(ctx, stream, respDir, init.SessionID, "rekey_unsupported",
			fmt.Sprintf("invalid new_ephemeral_key: %v", err))
	}
	initiatorNonce, err := base64.StdEncoding.DecodeString(init.RekeyNonce)
	if err != nil {
		return h.reject(ctx, stream, respDir, init.SessionID, "rekey_unsupported",
			fmt.Sprintf("invalid rekey_nonce: %v", err))
	}

	// Responder-side KEM step: encapsulate under the initiator's
	// ephemeral public key to derive the shared secret and produce
	// the wire blob we send back as responder_ephemeral_key. For
	// baseline X25519 this is equivalent to the legacy GenerateKeyPair
	// + Agree flow (Encapsulate internally generates a fresh X25519
	// pair); for the hybrid suite it packs responderX25519Pub ||
	// kyberCiphertext. The responder holds no ephemeral private key
	// after this call — Encapsulate zeroizes it internally.
	shared, respEphPub, err := h.Suite.KEM().Encapsulate(initiatorEphPub)
	if err != nil {
		return h.reject(ctx, stream, respDir, init.SessionID, "rekey_unsupported",
			fmt.Sprintf("KEM encapsulate failed: %v", err))
	}
	defer crypto.Zeroize(shared)

	responderNonce := make([]byte, 32)
	if _, err := rand.Read(responderNonce); err != nil {
		return fmt.Errorf("session: responder nonce: %w", err)
	}
	newKeys, err := crypto.DeriveRekeyKeys(h.Suite.KDF(), shared, initiatorNonce, responderNonce)
	if err != nil {
		return fmt.Errorf("session: derive rekey keys: %w", err)
	}

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
	accBytes, err := marshalRekeyBody(&acc)
	if err != nil {
		return fmt.Errorf("session: marshal rekey_accepted: %w", err)
	}
	// Seal the response under the OLD session keys — the peer only
	// gets to see the accepted message after successful AEAD open,
	// which proves we hold the keys. After we apply the rekey we
	// switch to the new keys for any subsequent message.
	sealedAcc, err := SealRekeyMessage(h.Suite, h.Session, respDir, accBytes)
	if err != nil {
		return fmt.Errorf("session: seal rekey_accepted: %w", err)
	}
	sealedBytes, err := json.Marshal(sealedAcc)
	if err != nil {
		return fmt.Errorf("session: marshal sealed rekey_accepted: %w", err)
	}
	if err := stream.Send(ctx, sealedBytes); err != nil {
		return fmt.Errorf("session: send sealed rekey_accepted: %w", err)
	}

	h.Session.ApplyRekey(newID, newKeys, now)
	return nil
}

// reject writes a sealed rekey_rejected message to stream. Returns nil
// on successful write; the caller treats "we sent a rejection" as a
// handled outcome.
func (h *RekeyHandler) reject(ctx context.Context, stream RekeyStream, respDir, sessionID, code, reason string) error {
	rej := RekeyRejected{
		Type:       MessageType,
		Step:       StepRekeyRejected,
		Version:    semp.ProtocolVersion,
		SessionID:  sessionID,
		ReasonCode: code,
		Reason:     reason,
	}
	body, err := marshalRekeyBody(&rej)
	if err != nil {
		return fmt.Errorf("session: marshal rekey_rejected: %w", err)
	}
	sealed, err := SealRekeyMessage(h.Suite, h.Session, respDir, body)
	if err != nil {
		return fmt.Errorf("session: seal rekey_rejected: %w", err)
	}
	out, err := json.Marshal(sealed)
	if err != nil {
		return fmt.Errorf("session: marshal sealed rekey_rejected: %w", err)
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
