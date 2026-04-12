package test

import (
	"encoding/json"
	"strings"
	"testing"

	"semp.dev/semp-go/crypto"
	"semp.dev/semp-go/session"
)

// TestRekeySealRoundTrip exercises SealRekeyMessage / OpenRekeyMessage
// directly against a fabricated *session.Session so we can assert the
// wire format and the cryptographic guarantees without a full
// handshake round trip.
func TestRekeySealRoundTrip(t *testing.T) {
	suite := crypto.SuiteBaseline

	// Fabricate a session with a full set of derived keys.
	ikm := []byte("test-rekey-seal-ikm-abcdefghijklmnopqrstuvwxyz")
	cn := []byte("cn--------------------------------")
	sn := []byte("sn--------------------------------")
	keys, err := crypto.DeriveSessionKeys(suite.KDF(), ikm, cn, sn)
	if err != nil {
		t.Fatalf("DeriveSessionKeys: %v", err)
	}
	sess := session.New(session.RoleClient)
	sess.ID = "01JTESTSEALED000000000000001"
	sess.State = session.StateActive
	sess.SetKeys(keys)

	plain := []byte(`{"type":"SEMP_REKEY","step":"init","hello":"world"}`)

	// c2s seal/open round trip.
	sealed, err := session.SealRekeyMessage(suite, sess, session.DirectionC2S, plain)
	if err != nil {
		t.Fatalf("SealRekeyMessage c2s: %v", err)
	}
	if sealed.Type != session.MessageType {
		t.Errorf("sealed.Type = %q, want %q", sealed.Type, session.MessageType)
	}
	if !sealed.Sealed {
		t.Error("sealed.Sealed should be true")
	}
	if sealed.Direction != session.DirectionC2S {
		t.Errorf("sealed.Direction = %q, want %q", sealed.Direction, session.DirectionC2S)
	}
	if sealed.Ciphertext == "" || sealed.Nonce == "" {
		t.Error("sealed missing nonce or ciphertext")
	}

	// Wire format round trip: the sealed struct must survive
	// json.Marshal + json.Unmarshal without losing any field.
	wire, err := json.Marshal(sealed)
	if err != nil {
		t.Fatalf("marshal sealed: %v", err)
	}
	if strings.Contains(string(wire), "world") {
		t.Error("sealed wire bytes contain plaintext substring 'world'")
	}
	var decoded session.SealedRekey
	if err := json.Unmarshal(wire, &decoded); err != nil {
		t.Fatalf("unmarshal sealed: %v", err)
	}

	opened, err := session.OpenRekeyMessage(suite, sess, &decoded)
	if err != nil {
		t.Fatalf("OpenRekeyMessage: %v", err)
	}
	if string(opened) != string(plain) {
		t.Errorf("opened mismatch:\n  got  %s\n  want %s", opened, plain)
	}

	// s2c seal/open round trip (proves the directional keys work
	// independently).
	sealedS2C, err := session.SealRekeyMessage(suite, sess, session.DirectionS2C, plain)
	if err != nil {
		t.Fatalf("SealRekeyMessage s2c: %v", err)
	}
	openedS2C, err := session.OpenRekeyMessage(suite, sess, sealedS2C)
	if err != nil {
		t.Fatalf("OpenRekeyMessage s2c: %v", err)
	}
	if string(openedS2C) != string(plain) {
		t.Errorf("s2c opened mismatch")
	}

	// A c2s-sealed message MUST NOT decrypt against s2c keys. Force
	// the direction label to s2c on a c2s ciphertext and confirm
	// decryption fails.
	tampered := *sealed
	tampered.Direction = session.DirectionS2C
	if _, err := session.OpenRekeyMessage(suite, sess, &tampered); err == nil {
		t.Error("cross-direction decryption should have failed")
	}
}

// TestRekeySealTamperedCiphertextRejected confirms that flipping a
// single byte in the base64 ciphertext or nonce causes AEAD Open to
// reject the message. This catches any regression where the rekey
// driver stops binding the MAC key into the AAD.
func TestRekeySealTamperedCiphertextRejected(t *testing.T) {
	suite := crypto.SuiteBaseline
	ikm := []byte("test-rekey-tamper-ikm-padding-to-32")
	cn := []byte("cn--------------------------------")
	sn := []byte("sn--------------------------------")
	keys, err := crypto.DeriveSessionKeys(suite.KDF(), ikm, cn, sn)
	if err != nil {
		t.Fatalf("DeriveSessionKeys: %v", err)
	}
	sess := session.New(session.RoleClient)
	sess.ID = "01JTESTSEALED000000000000002"
	sess.State = session.StateActive
	sess.SetKeys(keys)

	sealed, err := session.SealRekeyMessage(suite, sess, session.DirectionC2S, []byte(`{"a":1}`))
	if err != nil {
		t.Fatalf("SealRekeyMessage: %v", err)
	}

	// Flip one character of the ciphertext string.
	tampered := *sealed
	if len(tampered.Ciphertext) < 4 {
		t.Fatalf("ciphertext too short to tamper")
	}
	b := []byte(tampered.Ciphertext)
	b[len(b)/2] ^= 0x01 // flip a bit in the middle
	tampered.Ciphertext = string(b)
	if _, err := session.OpenRekeyMessage(suite, sess, &tampered); err == nil {
		t.Error("OpenRekeyMessage accepted a tampered ciphertext")
	}

	// Changing the session ID MUST also cause AEAD Open to fail,
	// because session ID is in the AAD.
	otherSess := session.New(session.RoleClient)
	otherSess.ID = "01JTESTSEALED000000000000999"
	otherSess.State = session.StateActive
	otherSess.SetKeys(keys)
	if _, err := session.OpenRekeyMessage(suite, otherSess, sealed); err == nil {
		t.Error("OpenRekeyMessage accepted a message bound to a different session ID")
	}
}

// TestRekeySealWireFormatIsOpaque confirms that the SEMP_REKEY wire
// bytes reveal none of the plaintext fields (session_id, rekey_nonce,
// ephemeral key material, etc.) to a passive observer — only the type
// discriminator, direction, and ciphertext.
func TestRekeySealWireFormatIsOpaque(t *testing.T) {
	suite := crypto.SuiteBaseline
	ikm := []byte("test-rekey-wire-opaque-padding---ikm")
	cn := []byte("cn--------------------------------")
	sn := []byte("sn--------------------------------")
	sessionKeys, err := crypto.DeriveSessionKeys(suite.KDF(), ikm, cn, sn)
	if err != nil {
		t.Fatalf("DeriveSessionKeys: %v", err)
	}
	sess := session.New(session.RoleClient)
	sess.ID = "01JTESTSEALED000000000000003"
	sess.State = session.StateActive
	sess.SetKeys(sessionKeys)

	// A rekey_init with a distinctive string we can grep for on the
	// wire bytes.
	inner := `{"type":"SEMP_REKEY","step":"init","session_id":"01JTESTSEALED000000000000003","rekey_nonce":"PLAINTEXT-MARKER-abcdefghij"}`
	sealed, err := session.SealRekeyMessage(suite, sess, session.DirectionC2S, []byte(inner))
	if err != nil {
		t.Fatalf("SealRekeyMessage: %v", err)
	}
	wire, err := json.Marshal(sealed)
	if err != nil {
		t.Fatalf("marshal sealed: %v", err)
	}
	if strings.Contains(string(wire), "PLAINTEXT-MARKER") {
		t.Error("wire bytes contain the plaintext marker — sealing is not working")
	}
	if strings.Contains(string(wire), "rekey_nonce") {
		t.Error("wire bytes contain the plaintext field name 'rekey_nonce'")
	}
	// Sanity: the wire DOES contain the top-level discriminator so
	// the inboxd dispatch loop can route it.
	if !strings.Contains(string(wire), `"type":"SEMP_REKEY"`) {
		t.Error("wire bytes missing the SEMP_REKEY type discriminator")
	}
}
