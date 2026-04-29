package inboxd

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	semp "semp.dev/semp-go"
	"semp.dev/semp-go/brief"
	"semp.dev/semp-go/crypto"
	"semp.dev/semp-go/delivery"
	"semp.dev/semp-go/enclosure"
	"semp.dev/semp-go/envelope"
	"semp.dev/semp-go/keys"
	"semp.dev/semp-go/seal"
)

// fakeStream is a one-shot MessageStream that captures whatever the
// server writes via Send. Recv is unused for these direct
// handleClientSubmission calls.
type fakeStream struct {
	sent [][]byte
}

func (f *fakeStream) Send(_ context.Context, msg []byte) error {
	f.sent = append(f.sent, append([]byte{}, msg...))
	return nil
}

func (f *fakeStream) Recv(_ context.Context) ([]byte, error) {
	return nil, nil
}

// inboxdHarness builds the minimum viable inboxd.Server with one local
// recipient (alice@example.com) and a fully functional signing /
// encryption setup. Optional knobs let individual tests inject a block
// list or domain policy.
type inboxdHarness struct {
	server         *Server
	suite          crypto.Suite
	domainSignPub  []byte
	domainSignPriv []byte
	domainSignFP   keys.Fingerprint
	domainEncPub   []byte
	domainEncPriv  []byte
	domainEncFP    keys.Fingerprint
	clientEncPub   []byte
	clientEncFP    keys.Fingerprint
	envMAC         []byte
}

func newInboxdHarness(t *testing.T) *inboxdHarness {
	t.Helper()
	suite := crypto.SuiteBaseline
	signPub, signPriv, err := suite.Signer().GenerateKeyPair()
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	encPub, encPriv, err := suite.KEM().GenerateKeyPair()
	if err != nil {
		t.Fatalf("server enc: %v", err)
	}
	clientPub, _, err := suite.KEM().GenerateKeyPair()
	if err != nil {
		t.Fatalf("client enc: %v", err)
	}
	envMAC, err := crypto.FreshKey(suite.AEAD())
	if err != nil {
		t.Fatalf("envMAC: %v", err)
	}
	h := &inboxdHarness{
		suite:          suite,
		domainSignPub:  signPub,
		domainSignPriv: signPriv,
		domainSignFP:   keys.Compute(signPub),
		domainEncPub:   encPub,
		domainEncPriv:  encPriv,
		domainEncFP:    keys.Compute(encPub),
		clientEncPub:   clientPub,
		clientEncFP:    keys.Compute(clientPub),
		envMAC:         envMAC,
	}
	h.server = &Server{
		Mode:           ModeClient,
		Suite:          suite,
		Inbox:          delivery.NewInbox(),
		LocalDomain:    "example.com",
		DomainSignFP:   h.domainSignFP,
		DomainSignPriv: signPriv,
		DomainEncFP:    h.domainEncFP,
		DomainEncPriv:  encPriv,
		DomainEncPub:   encPub,
		Identity:       "carol@example.com",
		EnvMAC:         envMAC,
	}
	return h
}

// composeUnsigned builds an unsigned envelope addressed from carol to
// the supplied recipients. inboxd's client-mode flow signs it during
// handleClientSubmission.
func (h *inboxdHarness) composeUnsigned(t *testing.T, postmarkID, from string, to []string) *envelope.Envelope {
	t.Helper()
	addrs := make([]brief.Address, len(to))
	for i, a := range to {
		addrs[i] = brief.Address(a)
	}
	in := &envelope.ComposeInput{
		Suite: h.suite,
		Postmark: envelope.Postmark{
			ID:         postmarkID,
			SessionID:  "sess-" + postmarkID,
			FromDomain: "example.com",
			ToDomain:   "example.com",
			Expires:    time.Now().UTC().Add(time.Hour),
		},
		Brief: brief.Brief{
			MessageID: "msg-" + postmarkID,
			From:      brief.Address(from),
			To:        addrs,
			SentAt:    time.Now().UTC(),
		},
		Enclosure: enclosure.Enclosure{
			Subject:     "blocklist test",
			ContentType: "text/plain",
			Body:        enclosure.Body{"text/plain": "hello"},
		},
		SenderDomainKeyID: h.domainSignFP,
		BriefRecipients: []seal.RecipientKey{
			{Fingerprint: h.domainEncFP, PublicKey: h.domainEncPub, Kind: seal.KindServerDomain},
			{Fingerprint: h.clientEncFP, PublicKey: h.clientEncPub, Kind: seal.KindUserClient},
		},
		EnclosureRecipients: []seal.RecipientKey{
			{Fingerprint: h.clientEncFP, PublicKey: h.clientEncPub, Kind: seal.KindUserClient},
		},
	}
	env, err := envelope.Compose(in)
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	return env
}

// TestInboxdClientPipelineHappyPath confirms the refactored
// handleClientSubmission still produces a delivered outcome for a
// local recipient. This guards against regressions in the migration
// to delivery.Pipeline.
func TestInboxdClientPipelineHappyPath(t *testing.T) {
	h := newInboxdHarness(t)
	env := h.composeUnsigned(t, "pm-happy", "carol@example.com", []string{"alice@example.com"})

	stream := &fakeStream{}
	if err := h.server.handleClientSubmission(context.Background(), stream, env); err != nil {
		t.Fatalf("handleClientSubmission: %v", err)
	}
	if len(stream.sent) != 1 {
		t.Fatalf("sent = %d messages, want 1", len(stream.sent))
	}
	var resp delivery.SubmissionResponse
	if err := json.Unmarshal(stream.sent[0], &resp); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if len(resp.Results) != 1 {
		t.Fatalf("results = %d, want 1", len(resp.Results))
	}
	if resp.Results[0].Status != semp.StatusDelivered {
		t.Errorf("status = %s, want delivered", resp.Results[0].Status)
	}
	if h.server.Inbox.Pending("alice@example.com") != 1 {
		t.Error("alice's inbox should have one queued envelope")
	}
}

// TestInboxdClientPipelineBlocklistRejects exercises the new BlockList
// wiring through inboxd: an entry blocking carol on alice's list
// produces a per-recipient rejection rather than a delivered outcome.
func TestInboxdClientPipelineBlocklistRejects(t *testing.T) {
	h := newInboxdHarness(t)
	h.server.BlockList = &delivery.StaticBlockListLookup{
		Lists: map[string]*delivery.BlockList{
			"alice@example.com": {
				UserID: "alice@example.com",
				Entries: []delivery.BlockEntry{{
					ID:             "block-carol",
					Entity:         delivery.Entity{Type: delivery.EntityUser, Address: "carol@example.com"},
					Acknowledgment: semp.AckRejected,
					Scope:          delivery.ScopeAll,
					CreatedAt:      time.Now().UTC(),
				}},
			},
		},
	}

	env := h.composeUnsigned(t, "pm-blocked", "carol@example.com", []string{"alice@example.com"})
	stream := &fakeStream{}
	if err := h.server.handleClientSubmission(context.Background(), stream, env); err != nil {
		t.Fatalf("handleClientSubmission: %v", err)
	}
	if len(stream.sent) != 1 {
		t.Fatalf("sent = %d messages, want 1", len(stream.sent))
	}
	var resp delivery.SubmissionResponse
	if err := json.Unmarshal(stream.sent[0], &resp); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if len(resp.Results) != 1 {
		t.Fatalf("results = %d, want 1", len(resp.Results))
	}
	got := resp.Results[0]
	if got.Status != semp.StatusRejected {
		t.Errorf("status = %s, want rejected", got.Status)
	}
	if got.ReasonCode != semp.ReasonBlocked {
		t.Errorf("reason_code = %s, want blocked", got.ReasonCode)
	}
	if h.server.Inbox.Pending("alice@example.com") != 0 {
		t.Error("blocked envelope should not have been stored")
	}
}

// TestInboxdClientPipelineSilentBlockSurfacesSilentStatus confirms a
// `silent` block entry produces StatusSilent (the inboxd loop still
// emits a response carrying the silent status — DELIVERY.md §1.3
// allows the protocol-level silent acknowledgment to be reported back
// to the sender's home server even though it carries no reason).
func TestInboxdClientPipelineSilentBlockSurfacesSilentStatus(t *testing.T) {
	h := newInboxdHarness(t)
	h.server.BlockList = &delivery.StaticBlockListLookup{
		Lists: map[string]*delivery.BlockList{
			"alice@example.com": {
				Entries: []delivery.BlockEntry{{
					ID:             "silent-carol",
					Entity:         delivery.Entity{Type: delivery.EntityUser, Address: "carol@example.com"},
					Acknowledgment: semp.AckSilent,
					Scope:          delivery.ScopeAll,
					CreatedAt:      time.Now().UTC(),
				}},
			},
		},
	}

	env := h.composeUnsigned(t, "pm-silent", "carol@example.com", []string{"alice@example.com"})
	stream := &fakeStream{}
	if err := h.server.handleClientSubmission(context.Background(), stream, env); err != nil {
		t.Fatalf("handleClientSubmission: %v", err)
	}
	var resp delivery.SubmissionResponse
	if err := json.Unmarshal(stream.sent[0], &resp); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if resp.Results[0].Status != semp.StatusSilent {
		t.Errorf("status = %s, want silent", resp.Results[0].Status)
	}
	if h.server.Inbox.Pending("alice@example.com") != 0 {
		t.Error("silent block should not deliver to inbox")
	}
}

// TestInboxdDomainPolicyRejects confirms the DomainPolicy hook on
// Server is honored by the pipeline path.
func TestInboxdDomainPolicyRejects(t *testing.T) {
	h := newInboxdHarness(t)
	h.server.DomainPolicy = func(_ context.Context, fromDomain, _ string) (semp.Acknowledgment, semp.ReasonCode, string) {
		return semp.AckRejected, semp.ReasonRateLimited, "test policy denial"
	}
	env := h.composeUnsigned(t, "pm-policy", "carol@example.com", []string{"alice@example.com"})
	stream := &fakeStream{}
	if err := h.server.handleClientSubmission(context.Background(), stream, env); err != nil {
		t.Fatalf("handleClientSubmission: %v", err)
	}
	var resp delivery.SubmissionResponse
	if err := json.Unmarshal(stream.sent[0], &resp); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if resp.Results[0].Status != semp.StatusRejected {
		t.Errorf("status = %s, want rejected", resp.Results[0].Status)
	}
	if resp.Results[0].ReasonCode != semp.ReasonRateLimited {
		t.Errorf("reason_code = %s, want rate_limited", resp.Results[0].ReasonCode)
	}
}
