package session

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	semp "github.com/semp-dev/semp-go"
	"github.com/semp-dev/semp-go/crypto"
)

// SealedRekey is the wire-level envelope that carries an AEAD-encrypted
// SEMP_REKEY message over the authenticated session channel
// (SESSION.md §3.2: "Both messages are encrypted and MACed using the
// current session keys").
//
// The dispatch loop recognizes a rekey message by the top-level `type`
// field; the actual RekeyInit / RekeyAccepted / RekeyRejected body is
// JSON-encoded, AEAD-sealed under the current K_enc_*2*, and base64-
// encoded into Ciphertext. The AEAD's own tag serves as the MAC — the
// spec's "MACed under the corresponding MAC key" language is satisfied
// by including the MAC key in the AEAD additional data, which binds
// the ciphertext to both keys simultaneously.
//
// Direction is "c2s" when the initiator is the client half of the
// session and "s2c" when it is the server half. A receiver uses
// Direction to pick the right pair of (encryption key, MAC key) to
// open the message. Tampering with Direction causes decryption to
// fail because the AAD changes.
type SealedRekey struct {
	// Type is always MessageType ("SEMP_REKEY") — the inboxd dispatch
	// loop uses this to route sealed rekey messages through the rekey
	// handler.
	Type string `json:"type"`

	// Sealed is true for encrypted messages. A future revision might
	// allow cleartext rekey during upgrade, which is why this is
	// explicit rather than implicit.
	Sealed bool `json:"sealed"`

	// Direction is "c2s" or "s2c" — selects which pair of session
	// keys to use.
	Direction string `json:"direction"`

	// Version is the protocol version.
	Version string `json:"version"`

	// Nonce is the base64-encoded AEAD nonce.
	Nonce string `json:"nonce"`

	// Ciphertext is the base64-encoded AEAD ciphertext || auth tag.
	Ciphertext string `json:"ciphertext"`
}

// Direction values.
const (
	DirectionC2S = "c2s"
	DirectionS2C = "s2c"
)

// SealRekeyMessage encrypts the JSON-encoded rekey message `plaintext`
// under the session's directional encryption key, binding the MAC key
// as AEAD additional data. The result is a SealedRekey ready to be
// marshaled and sent.
//
// direction MUST be DirectionC2S when the caller is the initiator's
// client side (or, for federation, the side that opened the
// connection), and DirectionS2C otherwise.
func SealRekeyMessage(suite crypto.Suite, s *Session, direction string, plaintext []byte) (*SealedRekey, error) {
	if suite == nil {
		return nil, errors.New("session: nil suite")
	}
	if s == nil {
		return nil, errors.New("session: nil session")
	}
	encKey, macKey, err := pickRekeyKeys(s, direction)
	if err != nil {
		return nil, err
	}
	aead := suite.AEAD()
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("session: rekey nonce: %w", err)
	}
	// Additional authenticated data binds the ciphertext to (a) the
	// direction label (so an attacker can't relabel c2s as s2c), (b)
	// the current session ID (so an attacker can't replay a sealed
	// rekey from a different session), and (c) the MAC key (so
	// cracking the AEAD alone is insufficient — the attacker would
	// also need the MAC key, satisfying the spec's "MACed under the
	// MAC key" requirement).
	ad := rekeyAAD(direction, s.ID, macKey)
	ct, err := aead.Seal(encKey, nonce, plaintext, ad)
	if err != nil {
		return nil, fmt.Errorf("session: AEAD seal: %w", err)
	}
	return &SealedRekey{
		Type:       MessageType,
		Sealed:     true,
		Direction:  direction,
		Version:    semp.ProtocolVersion,
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ct),
	}, nil
}

// OpenRekeyMessage reverses SealRekeyMessage: it decrypts the sealed
// blob under the session's directional keys and returns the plaintext
// JSON body. The caller parses the body into the appropriate
// RekeyInit / RekeyAccepted / RekeyRejected struct.
//
// OpenRekeyMessage is direction-aware: when processing a message sent
// in the c2s direction, the RECEIVER (server) still uses the c2s key
// pair to decrypt, because both sides agree on which directional keys
// name which half of the session. sealed.Direction tells the receiver
// which pair to use.
func OpenRekeyMessage(suite crypto.Suite, s *Session, sealed *SealedRekey) ([]byte, error) {
	if suite == nil {
		return nil, errors.New("session: nil suite")
	}
	if s == nil {
		return nil, errors.New("session: nil session")
	}
	if sealed == nil {
		return nil, errors.New("session: nil sealed rekey")
	}
	if sealed.Type != MessageType {
		return nil, fmt.Errorf("session: unexpected type %q", sealed.Type)
	}
	if !sealed.Sealed {
		return nil, errors.New("session: rekey message is not sealed")
	}
	encKey, macKey, err := pickRekeyKeys(s, sealed.Direction)
	if err != nil {
		return nil, err
	}
	nonce, err := base64.StdEncoding.DecodeString(sealed.Nonce)
	if err != nil {
		return nil, fmt.Errorf("session: rekey nonce base64: %w", err)
	}
	ct, err := base64.StdEncoding.DecodeString(sealed.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("session: rekey ciphertext base64: %w", err)
	}
	ad := rekeyAAD(sealed.Direction, s.ID, macKey)
	pt, err := suite.AEAD().Open(encKey, nonce, ct, ad)
	if err != nil {
		return nil, fmt.Errorf("session: AEAD open: %w", err)
	}
	return pt, nil
}

// pickRekeyKeys returns the (encryption, MAC) key pair for the given
// direction. An error is returned if the session has no keys or the
// direction is unknown.
func pickRekeyKeys(s *Session, direction string) (encKey, macKey []byte, err error) {
	if s.keys == nil {
		return nil, nil, errors.New("session: no session keys")
	}
	switch direction {
	case DirectionC2S:
		return s.keys.EncC2S, s.keys.MACC2S, nil
	case DirectionS2C:
		return s.keys.EncS2C, s.keys.MACS2C, nil
	default:
		return nil, nil, fmt.Errorf("session: unknown rekey direction %q", direction)
	}
}

// rekeyAAD builds the AEAD additional data for a sealed rekey message.
// The resulting byte slice binds the ciphertext to the direction
// label, the current session ID, and the directional MAC key.
func rekeyAAD(direction, sessionID string, macKey []byte) []byte {
	// Length-prefixed concatenation to avoid any ambiguity about
	// where one field ends and the next begins.
	total := 4 + len(direction) + 4 + len(sessionID) + 4 + len(macKey)
	buf := make([]byte, 0, total)
	buf = appendLP(buf, []byte(direction))
	buf = appendLP(buf, []byte(sessionID))
	buf = appendLP(buf, macKey)
	return buf
}

// appendLP appends a 4-byte big-endian length prefix followed by b.
func appendLP(out, b []byte) []byte {
	n := len(b)
	out = append(out, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	out = append(out, b...)
	return out
}

// marshalRekeyBody is a tiny helper that JSON-encodes any of the
// RekeyInit / RekeyAccepted / RekeyRejected message structs.
func marshalRekeyBody(v any) ([]byte, error) {
	return json.Marshal(v)
}
