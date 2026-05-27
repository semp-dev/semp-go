package handshake_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/semp-dev/semp-go/extensions"
	"github.com/semp-dev/semp-go/handshake"
)

// TestResumeMarshalsExpectedShape confirms the Resume request
// matches the JSON shape from HANDSHAKE.md §2.8.2.
func TestResumeMarshalsExpectedShape(t *testing.T) {
	r := handshake.Resume{
		Type:             handshake.MessageType,
		Step:             handshake.StepResume,
		Party:            handshake.PartyClient,
		Version:          "1.0.0",
		Nonce:            "client-nonce-b64",
		ResumptionTicket: "ticket-bytes-b64",
		ClientEphemeralKey: handshake.EphemeralKey{
			Algorithm: "x25519-chacha20-poly1305",
			Key:       "ephemeral-pub-b64",
			KeyID:     "ephemeral-fp",
		},
		Transport:  "ws",
		Extensions: extensions.Map{},
	}
	out, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	got := string(out)
	for _, want := range []string{
		`"type":"SEMP_HANDSHAKE"`,
		`"step":"resume"`,
		`"party":"client"`,
		`"resumption_ticket":"ticket-bytes-b64"`,
		`"client_ephemeral_key":`,
		`"transport":"ws"`,
		`"extensions":{}`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("marshaled Resume missing %q\n got: %s", want, got)
		}
	}
}

// TestAcceptedOmitsResumptionFieldsForFullHandshake confirms the
// new resumption-only fields are omitted when not set, so
// full-handshake Accepted bytes are unchanged from before commit 2.
func TestAcceptedOmitsResumptionFieldsForFullHandshake(t *testing.T) {
	a := handshake.Accepted{
		Type:            handshake.MessageType,
		Step:            handshake.StepAccepted,
		Party:           handshake.PartyServer,
		Version:         "1.0.0",
		SessionID:       "01JTESTACCEPTED0000000000001",
		SessionTTL:      300,
		ServerSignature: "sig",
		Extensions:      extensions.Map{},
	}
	out, err := json.Marshal(a)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	got := string(out)
	for _, forbidden := range []string{
		`"server_nonce":`,
		`"server_ephemeral_key":`,
		`"resumption_ticket":`,
	} {
		if strings.Contains(got, forbidden) {
			t.Errorf("full-handshake Accepted MUST NOT contain %s\n got: %s", forbidden, got)
		}
	}
}

// TestAcceptedIncludesResumptionFieldsWhenSet confirms the
// resumption-response shape from HANDSHAKE.md §2.8.2: Accepted
// carries server_nonce, server_ephemeral_key, and resumption_ticket
// when responding to a Resume request.
func TestAcceptedIncludesResumptionFieldsWhenSet(t *testing.T) {
	expires := time.Date(2026, 5, 9, 12, 0, 0, 0, time.UTC)
	a := handshake.Accepted{
		Type:        handshake.MessageType,
		Step:        handshake.StepAccepted,
		Party:       handshake.PartyServer,
		Version:     "1.0.0",
		SessionID:   "01JTESTRESUMEACCEPTED00000001",
		SessionTTL:  300,
		ServerNonce: "server-nonce-b64",
		ServerEphemeralKey: &handshake.EphemeralKey{
			Algorithm: "x25519-chacha20-poly1305",
			Key:       "server-eph-pub-b64",
			KeyID:     "server-eph-fp",
		},
		ResumptionTicket: &handshake.ResumptionTicket{
			Value:     "new-ticket-b64",
			ExpiresAt: expires,
		},
		ServerSignature: "sig",
		Extensions:      extensions.Map{},
	}
	out, err := json.Marshal(a)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	got := string(out)
	for _, want := range []string{
		`"server_nonce":"server-nonce-b64"`,
		`"server_ephemeral_key":`,
		`"resumption_ticket":`,
		`"value":"new-ticket-b64"`,
		`"expires_at":"2026-05-09T12:00:00Z"`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("resume-Accepted missing %q\n got: %s", want, got)
		}
	}
}
