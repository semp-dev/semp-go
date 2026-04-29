package envelope_test

import (
	"strings"
	"testing"
	"time"

	"semp.dev/semp-go/brief"
	"semp.dev/semp-go/crypto"
	"semp.dev/semp-go/enclosure"
	"semp.dev/semp-go/envelope"
	"semp.dev/semp-go/keys"
	"semp.dev/semp-go/seal"
)

// composeMultiDevice builds a signed envelope whose brief and
// enclosure are wrapped for both deviceA and deviceB, plus a server
// receiver. Returns the envelope along with the two device private
// keys and their fingerprints so tests can drive OpenBriefAny /
// OpenEnclosureAny.
func composeMultiDevice(t *testing.T) (env *envelope.Envelope, entryA, entryB, entryServer envelope.RecipientPrivateKey) {
	t.Helper()
	suite := crypto.SuiteBaseline

	// Sender domain signing key.
	sigPub, sigPriv, err := suite.Signer().GenerateKeyPair()
	if err != nil {
		t.Fatalf("sign keypair: %v", err)
	}
	sigFP := keys.Compute(sigPub)

	// Server domain enc key.
	srvEncPub, srvEncPriv, err := suite.KEM().GenerateKeyPair()
	if err != nil {
		t.Fatalf("server enc keypair: %v", err)
	}
	srvEncFP := keys.Compute(srvEncPub)

	// Two device encryption keys for the recipient.
	devAEncPub, devAEncPriv, err := suite.KEM().GenerateKeyPair()
	if err != nil {
		t.Fatalf("deviceA keypair: %v", err)
	}
	devAFP := keys.Compute(devAEncPub)

	devBEncPub, devBEncPriv, err := suite.KEM().GenerateKeyPair()
	if err != nil {
		t.Fatalf("deviceB keypair: %v", err)
	}
	devBFP := keys.Compute(devBEncPub)

	// K_env_mac for the sender's session.
	envMAC, _ := crypto.FreshKey(suite.AEAD())

	// Compose with both devices in brief_recipients AND
	// enclosure_recipients (server is only in brief_recipients).
	in := &envelope.ComposeInput{
		Suite: suite,
		Postmark: envelope.Postmark{
			ID:         "01JTESTMULTIDEVICEPOSTMARK001",
			SessionID:  "01JTESTMULTIDEVICESESSION0001",
			FromDomain: "sender.example",
			ToDomain:   "recipient.example",
			Expires:    time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
		},
		Brief: brief.Brief{
			MessageID: "01JTESTMULTIDEVICEMESSAGE0001",
			From:      "alice@sender.example",
			To:        []brief.Address{"bob@recipient.example"},
			SentAt:    time.Now().UTC(),
		},
		Enclosure: enclosure.Enclosure{
			Subject:     "multi-device test",
			ContentType: "text/plain",
			Body:        enclosure.Body{"text/plain": "each device decrypts its own wrap entry"},
		},
		SenderDomainKeyID: sigFP,
		BriefRecipients: []seal.RecipientKey{
			{Fingerprint: srvEncFP, PublicKey: srvEncPub, Kind: seal.KindServerDomain},
			{Fingerprint: devAFP, PublicKey: devAEncPub, Kind: seal.KindUserClient},
			{Fingerprint: devBFP, PublicKey: devBEncPub, Kind: seal.KindUserClient},
		},
		EnclosureRecipients: []seal.RecipientKey{
			{Fingerprint: devAFP, PublicKey: devAEncPub, Kind: seal.KindUserClient},
			{Fingerprint: devBFP, PublicKey: devBEncPub, Kind: seal.KindUserClient},
		},
	}
	envOut, err := envelope.Compose(in)
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	if err := envelope.Sign(envOut, suite, sigPriv, envMAC); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return envOut,
		envelope.RecipientPrivateKey{Fingerprint: devAFP, PrivateKey: devAEncPriv, PublicKey: devAEncPub},
		envelope.RecipientPrivateKey{Fingerprint: devBFP, PrivateKey: devBEncPriv, PublicKey: devBEncPub},
		envelope.RecipientPrivateKey{Fingerprint: srvEncFP, PrivateKey: srvEncPriv, PublicKey: srvEncPub}
}

// TestOpenBriefAnyHappyPath opens a multi-device envelope with a
// candidate list containing both devices plus a distractor. The
// helper should pick the first matching entry and succeed.
func TestOpenBriefAnyHappyPath(t *testing.T) {
	suite := crypto.SuiteBaseline
	env, devA, devB, _ := composeMultiDevice(t)

	candidates := []envelope.RecipientPrivateKey{devA, devB}
	b, err := envelope.OpenBriefAny(env, suite, candidates)
	if err != nil {
		t.Fatalf("OpenBriefAny: %v", err)
	}
	if b.MessageID != "01JTESTMULTIDEVICEMESSAGE0001" {
		t.Errorf("MessageID = %q, unexpected", b.MessageID)
	}
}

// TestOpenBriefAnyDeviceBOnly confirms that a candidate list
// containing ONLY device B still succeeds — the helper iterates and
// finds B's entry on the envelope.
func TestOpenBriefAnyDeviceBOnly(t *testing.T) {
	suite := crypto.SuiteBaseline
	env, _, devB, _ := composeMultiDevice(t)

	b, err := envelope.OpenBriefAny(env, suite, []envelope.RecipientPrivateKey{devB})
	if err != nil {
		t.Fatalf("OpenBriefAny(devB only): %v", err)
	}
	if b == nil {
		t.Fatal("OpenBriefAny returned nil brief")
	}
}

// TestOpenBriefAnyIgnoresUnrelatedCandidates confirms that a
// candidate whose fingerprint is NOT authorized on the envelope is
// silently skipped, not treated as a failure. This is the
// multi-device client passing its full key ring — most keys won't
// have entries on any given envelope.
func TestOpenBriefAnyIgnoresUnrelatedCandidates(t *testing.T) {
	suite := crypto.SuiteBaseline
	env, devA, _, _ := composeMultiDevice(t)

	// Make a junk candidate with a fingerprint that's definitely
	// not on the envelope.
	junkPub, junkPriv, _ := suite.KEM().GenerateKeyPair()
	junk := envelope.RecipientPrivateKey{
		Fingerprint: "junk-fingerprint-000000000000",
		PrivateKey:  junkPriv,
		PublicKey:   junkPub,
	}
	candidates := []envelope.RecipientPrivateKey{junk, devA}
	if _, err := envelope.OpenBriefAny(env, suite, candidates); err != nil {
		t.Errorf("OpenBriefAny should skip unrelated candidate: %v", err)
	}
}

// TestOpenBriefAnyNoMatchingCandidate confirms that a candidate list
// whose fingerprints are all absent from the envelope returns an
// error (not a panic, not a silent nil).
func TestOpenBriefAnyNoMatchingCandidate(t *testing.T) {
	suite := crypto.SuiteBaseline
	env, _, _, _ := composeMultiDevice(t)

	junkPub2, junkPriv2, _ := suite.KEM().GenerateKeyPair()
	candidates := []envelope.RecipientPrivateKey{
		{Fingerprint: "junk-1", PrivateKey: junkPriv2, PublicKey: junkPub2},
		{Fingerprint: "junk-2", PrivateKey: junkPriv2, PublicKey: junkPub2},
	}
	_, err := envelope.OpenBriefAny(env, suite, candidates)
	if err == nil {
		t.Fatal("expected error for no matching candidate")
	}
	if !strings.Contains(err.Error(), "no candidate matches") {
		t.Errorf("error should mention no-match: %v", err)
	}
}

// TestOpenBriefAnyMatchingFingerprintWrongPrivateKey confirms that a
// candidate whose fingerprint matches an envelope entry but whose
// private key can't decrypt it surfaces as an error (not a silent
// success).
func TestOpenBriefAnyMatchingFingerprintWrongPrivateKey(t *testing.T) {
	suite := crypto.SuiteBaseline
	env, devA, _, _ := composeMultiDevice(t)

	// Swap in wrong private key bytes but keep the fingerprint
	// that's actually on the envelope.
	wrongPub, wrongPriv, _ := suite.KEM().GenerateKeyPair()
	bad := envelope.RecipientPrivateKey{
		Fingerprint: devA.Fingerprint,
		PrivateKey:  wrongPriv,
		PublicKey:   wrongPub,
	}
	_, err := envelope.OpenBriefAny(env, suite, []envelope.RecipientPrivateKey{bad})
	if err == nil {
		t.Fatal("expected error for wrong private key")
	}
	if !strings.Contains(err.Error(), "failed to open brief") {
		t.Errorf("error should mention open failure: %v", err)
	}
}

// TestOpenBriefAnyEmptyCandidates confirms that passing an empty
// candidate list is a clean error, not a panic.
func TestOpenBriefAnyEmptyCandidates(t *testing.T) {
	suite := crypto.SuiteBaseline
	env, _, _, _ := composeMultiDevice(t)
	if _, err := envelope.OpenBriefAny(env, suite, nil); err == nil {
		t.Error("expected error for nil candidates")
	}
}

// TestOpenEnclosureAnyHappyPath is the enclosure counterpart to the
// brief happy-path test. Both devices have enclosure entries; the
// helper picks one and decrypts.
func TestOpenEnclosureAnyHappyPath(t *testing.T) {
	suite := crypto.SuiteBaseline
	env, devA, devB, _ := composeMultiDevice(t)

	enc, err := envelope.OpenEnclosureAny(env, suite, []envelope.RecipientPrivateKey{devA, devB})
	if err != nil {
		t.Fatalf("OpenEnclosureAny: %v", err)
	}
	if enc.Subject != "multi-device test" {
		t.Errorf("Subject = %q, unexpected", enc.Subject)
	}
	if enc.Body["text/plain"] != "each device decrypts its own wrap entry" {
		t.Errorf("Body mismatch")
	}
}

// TestOpenEnclosureAnyRejectsServerKey confirms the privacy boundary
// from ENVELOPE.md §10.5 holds when using the multi-candidate helper:
// the server's domain encryption key is NOT in enclosure_recipients,
// so passing it as a candidate returns "no candidate matches".
func TestOpenEnclosureAnyRejectsServerKey(t *testing.T) {
	suite := crypto.SuiteBaseline
	env, _, _, srv := composeMultiDevice(t)

	_, err := envelope.OpenEnclosureAny(env, suite, []envelope.RecipientPrivateKey{srv})
	if err == nil {
		t.Error("OpenEnclosureAny accepted the server's domain key — privacy boundary broken")
	}
	if !strings.Contains(err.Error(), "no candidate matches") {
		t.Errorf("expected 'no candidate matches' error, got: %v", err)
	}
}
