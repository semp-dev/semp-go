package delivery_test

import (
	"context"
	"errors"
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

// pipelineFixture bundles the keys and helper objects every pipeline
// test needs to compose a valid envelope: sender domain signing key,
// receiver server domain encryption key, receiver client encryption
// key, plus K_env_mac.
type pipelineFixture struct {
	suite           crypto.Suite
	senderDomainPub []byte
	senderDomainPriv []byte
	senderDomainFP  keys.Fingerprint
	serverEncFP     keys.Fingerprint
	serverEncPub    []byte
	serverEncPriv   []byte
	clientEncFP     keys.Fingerprint
	clientEncPub    []byte
	envMAC          []byte
}

func newFixture(t *testing.T) *pipelineFixture {
	t.Helper()
	suite := crypto.SuiteBaseline
	signPub, signPriv, err := suite.Signer().GenerateKeyPair()
	if err != nil {
		t.Fatalf("sender signer keypair: %v", err)
	}
	serverPub, serverPriv, err := suite.KEM().GenerateKeyPair()
	if err != nil {
		t.Fatalf("server enc keypair: %v", err)
	}
	clientPub, _, err := suite.KEM().GenerateKeyPair()
	if err != nil {
		t.Fatalf("client enc keypair: %v", err)
	}
	envMAC, err := crypto.FreshKey(suite.AEAD())
	if err != nil {
		t.Fatalf("envMAC: %v", err)
	}
	return &pipelineFixture{
		suite:            suite,
		senderDomainPub:  signPub,
		senderDomainPriv: signPriv,
		senderDomainFP:   keys.Compute(signPub),
		serverEncFP:      keys.Compute(serverPub),
		serverEncPub:     serverPub,
		serverEncPriv:    serverPriv,
		clientEncFP:      keys.Compute(clientPub),
		clientEncPub:     clientPub,
		envMAC:           envMAC,
	}
}

// composeSigned builds a fully signed envelope addressed to the given
// To recipient list, optionally setting GroupID.
func (f *pipelineFixture) composeSigned(t *testing.T, postmarkID, fromAddress string, fromDomain string, toAddrs []string, groupID string) *envelope.Envelope {
	t.Helper()
	to := make([]brief.Address, len(toAddrs))
	for i, a := range toAddrs {
		to[i] = brief.Address(a)
	}
	bf := brief.Brief{
		MessageID: "msg-" + postmarkID,
		From:      brief.Address(fromAddress),
		To:        to,
		SentAt:    time.Now().UTC(),
		GroupID:   groupID,
	}
	enc := enclosure.Enclosure{
		Subject:     "pipeline test",
		ContentType: "text/plain",
		Body:        enclosure.Body{"text/plain": "hello"},
	}
	in := &envelope.ComposeInput{
		Suite: f.suite,
		Postmark: envelope.Postmark{
			ID:         postmarkID,
			SessionID:  "sess-" + postmarkID,
			FromDomain: fromDomain,
			ToDomain:   "recv.example",
			Expires:    time.Now().UTC().Add(time.Hour),
		},
		Brief:             bf,
		Enclosure:         enc,
		SenderDomainKeyID: f.senderDomainFP,
		BriefRecipients: []seal.RecipientKey{
			{Fingerprint: f.serverEncFP, PublicKey: f.serverEncPub},
			{Fingerprint: f.clientEncFP, PublicKey: f.clientEncPub},
		},
		EnclosureRecipients: []seal.RecipientKey{
			{Fingerprint: f.clientEncFP, PublicKey: f.clientEncPub},
		},
	}
	env, err := envelope.Compose(in)
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	if err := envelope.Sign(env, f.suite, f.senderDomainPriv, f.envMAC); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return env
}

// localTo configures IsLocal to recognize a fixed set of addresses.
func localTo(addrs ...string) delivery.LocalAddressFunc {
	set := make(map[string]bool, len(addrs))
	for _, a := range addrs {
		set[a] = true
	}
	return func(addr string) bool { return set[addr] }
}

// staticDomainKeys returns a DomainKeyLookup that resolves a single
// domain → public key mapping.
type staticDomainKeys struct {
	domain string
	pub    []byte
	err    error
}

func (s *staticDomainKeys) LookupDomainPublicKey(_ context.Context, domain string) ([]byte, error) {
	if s.err != nil {
		return nil, s.err
	}
	if domain == s.domain {
		return s.pub, nil
	}
	return nil, nil
}

// TestPipelineHappyPathFederation runs the full pipeline against a
// signed envelope: every step passes and the recipient ends up with a
// `delivered` outcome and one queued envelope.
func TestPipelineHappyPathFederation(t *testing.T) {
	f := newFixture(t)
	env := f.composeSigned(t, "pm-happy", "alice@send.example", "send.example", []string{"bob@recv.example"}, "")

	inbox := delivery.NewInbox()
	pipe := &delivery.Pipeline{
		Suite:         f.suite,
		EnvMAC:        func() []byte { return f.envMAC },
		DomainKeys:    &staticDomainKeys{domain: "send.example", pub: f.senderDomainPub},
		DomainEncFP:   f.serverEncFP,
		DomainEncPriv: f.serverEncPriv,
		IsLocal:       localTo("bob@recv.example"),
		Inbox:         inbox,
	}
	res, err := pipe.Process(context.Background(), env)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if res.Rejected() {
		t.Fatalf("envelope unexpectedly rejected: %s — %s", res.Rejection.Code, res.Rejection.Reason)
	}
	if len(res.Results) != 1 {
		t.Fatalf("results = %d, want 1", len(res.Results))
	}
	if res.Results[0].Status != semp.StatusDelivered {
		t.Errorf("status = %s, want delivered", res.Results[0].Status)
	}
	if got := inbox.Pending("bob@recv.example"); got != 1 {
		t.Errorf("inbox pending = %d, want 1", got)
	}
	if res.Brief == nil {
		t.Error("Result.Brief should be populated on success")
	}
}

// TestPipelineExpiredEnvelope confirms step 2 catches expired
// postmarks and surfaces an envelope-wide rejection.
func TestPipelineExpiredEnvelope(t *testing.T) {
	f := newFixture(t)
	env := f.composeSigned(t, "pm-exp", "alice@send.example", "send.example", []string{"bob@recv.example"}, "")
	env.Postmark.Expires = time.Now().UTC().Add(-time.Minute)
	// Re-sign so the modified postmark still verifies.
	if err := envelope.Sign(env, f.suite, f.senderDomainPriv, f.envMAC); err != nil {
		t.Fatalf("Sign: %v", err)
	}

	pipe := &delivery.Pipeline{
		Suite:         f.suite,
		EnvMAC:        func() []byte { return f.envMAC },
		DomainKeys:    &staticDomainKeys{domain: "send.example", pub: f.senderDomainPub},
		DomainEncFP:   f.serverEncFP,
		DomainEncPriv: f.serverEncPriv,
		IsLocal:       localTo("bob@recv.example"),
		Inbox:         delivery.NewInbox(),
	}
	res, err := pipe.Process(context.Background(), env)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if !res.Rejected() {
		t.Fatal("expired envelope should produce a rejection")
	}
	if res.Rejection.Code != semp.ReasonEnvelopeExpired {
		t.Errorf("code = %s, want envelope_expired", res.Rejection.Code)
	}
}

// TestPipelineMissingSessionID confirms step 3 catches an empty
// session_id with reason no_session.
func TestPipelineMissingSessionID(t *testing.T) {
	f := newFixture(t)
	env := f.composeSigned(t, "pm-nosess", "alice@send.example", "send.example", []string{"bob@recv.example"}, "")
	env.Postmark.SessionID = ""
	if err := envelope.Sign(env, f.suite, f.senderDomainPriv, f.envMAC); err != nil {
		t.Fatalf("Sign: %v", err)
	}

	pipe := &delivery.Pipeline{
		Suite:         f.suite,
		EnvMAC:        func() []byte { return f.envMAC },
		DomainKeys:    &staticDomainKeys{domain: "send.example", pub: f.senderDomainPub},
		DomainEncFP:   f.serverEncFP,
		DomainEncPriv: f.serverEncPriv,
		IsLocal:       localTo("bob@recv.example"),
		Inbox:         delivery.NewInbox(),
	}
	res, err := pipe.Process(context.Background(), env)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if !res.Rejected() || res.Rejection.Code != semp.ReasonNoSession {
		t.Errorf("rejection code = %v, want no_session", res.Rejection)
	}
}

// TestPipelineRetiredSession confirms step 3 consults the ExpiryLog
// and rejects retired sessions with handshake_invalid.
func TestPipelineRetiredSession(t *testing.T) {
	f := newFixture(t)
	env := f.composeSigned(t, "pm-retired", "alice@send.example", "send.example", []string{"bob@recv.example"}, "")

	pipe := &delivery.Pipeline{
		Suite:         f.suite,
		EnvMAC:        func() []byte { return f.envMAC },
		Sessions:      &fakeExpiryLog{retired: map[string]bool{env.Postmark.SessionID: true}},
		DomainKeys:    &staticDomainKeys{domain: "send.example", pub: f.senderDomainPub},
		DomainEncFP:   f.serverEncFP,
		DomainEncPriv: f.serverEncPriv,
		IsLocal:       localTo("bob@recv.example"),
		Inbox:         delivery.NewInbox(),
	}
	res, err := pipe.Process(context.Background(), env)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if !res.Rejected() || res.Rejection.Code != semp.ReasonHandshakeInvalid {
		t.Errorf("rejection code = %v, want handshake_invalid", res.Rejection)
	}
}

// TestPipelineBadSessionMAC confirms step 4 catches a wrong K_env_mac.
func TestPipelineBadSessionMAC(t *testing.T) {
	f := newFixture(t)
	env := f.composeSigned(t, "pm-mac", "alice@send.example", "send.example", []string{"bob@recv.example"}, "")
	wrongMAC, _ := crypto.FreshKey(f.suite.AEAD())

	pipe := &delivery.Pipeline{
		Suite:         f.suite,
		EnvMAC:        func() []byte { return wrongMAC },
		DomainKeys:    &staticDomainKeys{domain: "send.example", pub: f.senderDomainPub},
		DomainEncFP:   f.serverEncFP,
		DomainEncPriv: f.serverEncPriv,
		IsLocal:       localTo("bob@recv.example"),
		Inbox:         delivery.NewInbox(),
	}
	res, err := pipe.Process(context.Background(), env)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if !res.Rejected() || res.Rejection.Code != semp.ReasonSessionMACInvalid {
		t.Errorf("rejection code = %v, want session_mac_invalid", res.Rejection)
	}
}

// TestPipelineBadSignature confirms step 1 catches a wrong domain key.
func TestPipelineBadSignature(t *testing.T) {
	f := newFixture(t)
	env := f.composeSigned(t, "pm-sig", "alice@send.example", "send.example", []string{"bob@recv.example"}, "")

	otherPub, _, err := f.suite.Signer().GenerateKeyPair()
	if err != nil {
		t.Fatalf("other keypair: %v", err)
	}
	pipe := &delivery.Pipeline{
		Suite:         f.suite,
		EnvMAC:        func() []byte { return f.envMAC },
		DomainKeys:    &staticDomainKeys{domain: "send.example", pub: otherPub},
		DomainEncFP:   f.serverEncFP,
		DomainEncPriv: f.serverEncPriv,
		IsLocal:       localTo("bob@recv.example"),
		Inbox:         delivery.NewInbox(),
	}
	res, err := pipe.Process(context.Background(), env)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if !res.Rejected() || res.Rejection.Code != semp.ReasonSealInvalid {
		t.Errorf("rejection code = %v, want seal_invalid", res.Rejection)
	}
}

// TestPipelineDomainPolicyRejects confirms step 5's hook can short-
// circuit the pipeline with a custom rejection.
func TestPipelineDomainPolicyRejects(t *testing.T) {
	f := newFixture(t)
	env := f.composeSigned(t, "pm-pol", "alice@send.example", "send.example", []string{"bob@recv.example"}, "")

	pipe := &delivery.Pipeline{
		Suite:         f.suite,
		EnvMAC:        func() []byte { return f.envMAC },
		DomainKeys:    &staticDomainKeys{domain: "send.example", pub: f.senderDomainPub},
		DomainEncFP:   f.serverEncFP,
		DomainEncPriv: f.serverEncPriv,
		DomainPolicy: func(_ context.Context, fromDomain, _ string) (semp.Acknowledgment, semp.ReasonCode, string) {
			if fromDomain == "send.example" {
				return semp.AckRejected, semp.ReasonRateLimited, "domain over quota"
			}
			return semp.AckDelivered, "", ""
		},
		IsLocal: localTo("bob@recv.example"),
		Inbox:   delivery.NewInbox(),
	}
	res, err := pipe.Process(context.Background(), env)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if !res.Rejected() {
		t.Fatal("policy hook should have rejected the envelope")
	}
	if res.Rejection.Code != semp.ReasonRateLimited {
		t.Errorf("code = %s, want rate_limited", res.Rejection.Code)
	}
}

// TestPipelineUserBlockListRejects confirms step 8 honors a per-
// recipient block entry on the verified sender address.
func TestPipelineUserBlockListRejects(t *testing.T) {
	f := newFixture(t)
	env := f.composeSigned(t, "pm-block", "alice@send.example", "send.example", []string{"bob@recv.example", "carol@recv.example"}, "")

	bobList := &delivery.BlockList{
		UserID:  "bob@recv.example",
		Entries: []delivery.BlockEntry{userEntry("alice@send.example", semp.AckRejected)},
	}
	pipe := &delivery.Pipeline{
		Suite:         f.suite,
		EnvMAC:        func() []byte { return f.envMAC },
		DomainKeys:    &staticDomainKeys{domain: "send.example", pub: f.senderDomainPub},
		DomainEncFP:   f.serverEncFP,
		DomainEncPriv: f.serverEncPriv,
		BlockList: &delivery.StaticBlockListLookup{Lists: map[string]*delivery.BlockList{
			"bob@recv.example": bobList,
		}},
		IsLocal: localTo("bob@recv.example", "carol@recv.example"),
		Inbox:   delivery.NewInbox(),
	}
	res, err := pipe.Process(context.Background(), env)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if res.Rejected() {
		t.Fatalf("unexpected envelope-wide rejection: %v", res.Rejection)
	}
	if len(res.Results) != 2 {
		t.Fatalf("results = %d, want 2", len(res.Results))
	}
	resByRecipient := map[string]delivery.SubmissionResult{}
	for _, r := range res.Results {
		resByRecipient[r.Recipient] = r
	}
	bob := resByRecipient["bob@recv.example"]
	if bob.Status != semp.StatusRejected {
		t.Errorf("bob status = %s, want rejected", bob.Status)
	}
	if bob.ReasonCode != semp.ReasonBlocked {
		t.Errorf("bob reason_code = %s, want blocked", bob.ReasonCode)
	}
	carol := resByRecipient["carol@recv.example"]
	if carol.Status != semp.StatusDelivered {
		t.Errorf("carol status = %s, want delivered (no block on her list)", carol.Status)
	}
}

// TestPipelineUserBlockSilent confirms a `silent` block entry produces
// StatusSilent for that recipient.
func TestPipelineUserBlockSilent(t *testing.T) {
	f := newFixture(t)
	env := f.composeSigned(t, "pm-silent", "alice@send.example", "send.example", []string{"bob@recv.example"}, "")

	pipe := &delivery.Pipeline{
		Suite:         f.suite,
		EnvMAC:        func() []byte { return f.envMAC },
		DomainKeys:    &staticDomainKeys{domain: "send.example", pub: f.senderDomainPub},
		DomainEncFP:   f.serverEncFP,
		DomainEncPriv: f.serverEncPriv,
		BlockList: &delivery.StaticBlockListLookup{Lists: map[string]*delivery.BlockList{
			"bob@recv.example": {Entries: []delivery.BlockEntry{userEntry("alice@send.example", semp.AckSilent)}},
		}},
		IsLocal: localTo("bob@recv.example"),
		Inbox:   delivery.NewInbox(),
	}
	res, err := pipe.Process(context.Background(), env)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if res.Rejected() {
		t.Fatal("unexpected envelope-wide rejection")
	}
	if res.Results[0].Status != semp.StatusSilent {
		t.Errorf("status = %s, want silent", res.Results[0].Status)
	}
}

// TestPipelineNonLocalRecipient confirms a non-local recipient is
// reported as recipient_not_found and never written to the inbox.
func TestPipelineNonLocalRecipient(t *testing.T) {
	f := newFixture(t)
	env := f.composeSigned(t, "pm-nonlocal", "alice@send.example", "send.example", []string{"remote@elsewhere.example"}, "")

	inbox := delivery.NewInbox()
	pipe := &delivery.Pipeline{
		Suite:         f.suite,
		EnvMAC:        func() []byte { return f.envMAC },
		DomainKeys:    &staticDomainKeys{domain: "send.example", pub: f.senderDomainPub},
		DomainEncFP:   f.serverEncFP,
		DomainEncPriv: f.serverEncPriv,
		IsLocal:       localTo("bob@recv.example"),
		Inbox:         inbox,
	}
	res, err := pipe.Process(context.Background(), env)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if res.Results[0].Status != semp.StatusRecipientNotFound {
		t.Errorf("status = %s, want recipient_not_found", res.Results[0].Status)
	}
	if inbox.Pending("remote@elsewhere.example") != 0 {
		t.Error("non-local recipient should not have anything queued")
	}
}

// TestPipelineSkipsSignatureForClientMode confirms a Pipeline with
// SkipSignatureCheck=true accepts a freshly-signed local envelope
// without needing a DomainKeys lookup.
func TestPipelineSkipsSignatureForClientMode(t *testing.T) {
	f := newFixture(t)
	env := f.composeSigned(t, "pm-client", "alice@send.example", "send.example", []string{"bob@recv.example"}, "")

	pipe := &delivery.Pipeline{
		Suite:               f.suite,
		EnvMAC:              func() []byte { return f.envMAC },
		SkipSignatureCheck:  true,
		SkipSessionMACCheck: true,
		DomainEncFP:         f.serverEncFP,
		DomainEncPriv:       f.serverEncPriv,
		IsLocal:             localTo("bob@recv.example"),
		Inbox:               delivery.NewInbox(),
	}
	res, err := pipe.Process(context.Background(), env)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if res.Rejected() {
		t.Fatalf("client-mode pipeline rejected envelope: %v", res.Rejection)
	}
	if res.Results[0].Status != semp.StatusDelivered {
		t.Errorf("status = %s, want delivered", res.Results[0].Status)
	}
}

// TestPipelineMissingDomainKeysFailsClosed confirms that a Pipeline
// without DomainKeys (and without the skip flag) rejects every
// envelope rather than failing open.
func TestPipelineMissingDomainKeysFailsClosed(t *testing.T) {
	f := newFixture(t)
	env := f.composeSigned(t, "pm-nodomkeys", "alice@send.example", "send.example", []string{"bob@recv.example"}, "")

	pipe := &delivery.Pipeline{
		Suite:         f.suite,
		EnvMAC:        func() []byte { return f.envMAC },
		DomainEncFP:   f.serverEncFP,
		DomainEncPriv: f.serverEncPriv,
		IsLocal:       localTo("bob@recv.example"),
		Inbox:         delivery.NewInbox(),
	}
	res, err := pipe.Process(context.Background(), env)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if !res.Rejected() {
		t.Fatal("missing DomainKeys should fail closed")
	}
}

// TestPipelineBlockListLookupErrorPropagates confirms a real lookup
// error fails the whole call (rather than being silently ignored).
func TestPipelineBlockListLookupErrorPropagates(t *testing.T) {
	f := newFixture(t)
	env := f.composeSigned(t, "pm-blkerr", "alice@send.example", "send.example", []string{"bob@recv.example"}, "")

	pipe := &delivery.Pipeline{
		Suite:         f.suite,
		EnvMAC:        func() []byte { return f.envMAC },
		DomainKeys:    &staticDomainKeys{domain: "send.example", pub: f.senderDomainPub},
		DomainEncFP:   f.serverEncFP,
		DomainEncPriv: f.serverEncPriv,
		BlockList:     &errorBlockList{err: errors.New("lookup boom")},
		IsLocal:       localTo("bob@recv.example"),
		Inbox:         delivery.NewInbox(),
	}
	if _, err := pipe.Process(context.Background(), env); err == nil {
		t.Error("expected error from BlockList lookup failure")
	}
}

// fakeExpiryLog is a tiny in-memory ExpiryLog used by the pipeline tests.
type fakeExpiryLog struct {
	retired map[string]bool
}

func (f *fakeExpiryLog) Retire(_ context.Context, sessionID string, _ time.Time) error {
	if f.retired == nil {
		f.retired = map[string]bool{}
	}
	f.retired[sessionID] = true
	return nil
}

func (f *fakeExpiryLog) Retired(_ context.Context, sessionID string) (bool, error) {
	return f.retired[sessionID], nil
}

func (f *fakeExpiryLog) Sweep(_ context.Context, _ time.Time, _ time.Duration) error {
	return nil
}

// errorBlockList is a BlockListLookup that always returns an error,
// used to confirm the pipeline propagates lookup failures.
type errorBlockList struct{ err error }

func (e *errorBlockList) Lookup(_ context.Context, _ string) (*delivery.BlockList, error) {
	return nil, e.err
}
