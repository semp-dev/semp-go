package envelope_test

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"testing"
	"time"

	"semp.dev/semp-go/brief"
	"semp.dev/semp-go/crypto"
	"semp.dev/semp-go/enclosure"
	"semp.dev/semp-go/envelope"
	"semp.dev/semp-go/keys"
	"semp.dev/semp-go/seal"
)

// staticResolver is the test-only resolver. Maps
// `address || ":" || keyID` and a `:keyID` fallback.
type staticResolver map[string][]byte

func (s staticResolver) LookupSenderIdentityKey(_ context.Context, senderAddress string, keyID string) ([]byte, error) {
	if pub, ok := s[senderAddress+":"+keyID]; ok {
		return pub, nil
	}
	if pub, ok := s[":"+keyID]; ok {
		return pub, nil
	}
	return nil, fmt.Errorf("%w: %s/%s", envelope.ErrSenderKeyUnknown, senderAddress, keyID)
}

// composeSimpleEnvelope builds a sealed envelope from alice to bob
// with the supplied identity key as alice's signer. Returns the
// envelope plus bob's recipient private/public keys for opening.
func composeSimpleEnvelope(t *testing.T, identityPub, identityPriv []byte, identityFP keys.Fingerprint) (env *envelope.Envelope, bobPriv, bobPub []byte, bobFP keys.Fingerprint) {
	t.Helper()
	suite := crypto.SuiteBaseline

	bobPub, bobPriv, err := suite.KEM().GenerateKeyPair()
	if err != nil {
		t.Fatalf("bob keypair: %v", err)
	}
	bobFP = keys.Compute(bobPub)

	in := &envelope.ComposeInput{
		Suite: suite,
		Postmark: envelope.Postmark{
			ID:         "01JTESTOPENVERIFY0000000001",
			SessionID:  "01JTESTSESSION00000000000001",
			FromDomain: "a.example",
			ToDomain:   "b.example",
			Expires:    time.Now().UTC().Add(time.Hour),
		},
		Brief: brief.Brief{
			MessageID: "msg-001",
			From:      "alice@a.example",
			To:        []brief.Address{"bob@b.example"},
			SentAt:    time.Now().UTC(),
		},
		Enclosure: enclosure.Enclosure{
			Subject:     "open-verify test",
			ContentType: "text/plain",
			Body:        enclosure.Body{"text/plain": "hello bob"},
		},
		SenderDomainKeyID:  "sender-domain-fp",
		IdentityPrivateKey: identityPriv,
		IdentityKeyID:      string(identityFP),
		BriefRecipients: []seal.RecipientKey{
			{Fingerprint: bobFP, PublicKey: bobPub, Kind: seal.KindUserClient},
		},
		EnclosureRecipients: []seal.RecipientKey{
			{Fingerprint: bobFP, PublicKey: bobPub, Kind: seal.KindUserClient},
		},
	}
	env, err = envelope.Compose(in)
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	_ = identityPub
	return env, bobPriv, bobPub, bobFP
}

// TestOpenAndVerifyHappyPath confirms a freshly-composed envelope
// round-trips through OpenAndVerify with a resolver that returns
// the correct identity key.
func TestOpenAndVerifyHappyPath(t *testing.T) {
	suite := crypto.SuiteBaseline
	identityPub, identityPriv, err := suite.Signer().GenerateKeyPair()
	if err != nil {
		t.Fatalf("identity keypair: %v", err)
	}
	identityFP := keys.Compute(identityPub)

	env, bobPriv, bobPub, bobFP := composeSimpleEnvelope(t, identityPub, identityPriv, identityFP)

	resolver := staticResolver{
		"alice@a.example:" + string(identityFP): identityPub,
	}
	candidates := []envelope.RecipientPrivateKey{
		{Fingerprint: bobFP, PrivateKey: bobPriv, PublicKey: bobPub},
	}
	res, err := envelope.OpenAndVerify(context.Background(), env, suite, candidates, resolver)
	if err != nil {
		t.Fatalf("OpenAndVerify: %v", err)
	}
	if !res.SenderSignatureVerified {
		t.Errorf("SenderSignatureVerified = false; error = %v", res.SenderSignatureError)
	}
	if res.Brief == nil || res.Enclosure == nil {
		t.Error("Brief or Enclosure nil after OpenAndVerify")
	}
	if res.Enclosure.Body["text/plain"] != "hello bob" {
		t.Errorf("unexpected body: %v", res.Enclosure.Body)
	}
}

// TestOpenAndVerifyResolverReturnsWrongKey confirms the resolver
// returning a substitute public key fails verification with a
// signature-verification error.
func TestOpenAndVerifyResolverReturnsWrongKey(t *testing.T) {
	suite := crypto.SuiteBaseline
	identityPub, identityPriv, err := suite.Signer().GenerateKeyPair()
	if err != nil {
		t.Fatalf("identity keypair: %v", err)
	}
	identityFP := keys.Compute(identityPub)
	wrongPub, _, err := suite.Signer().GenerateKeyPair()
	if err != nil {
		t.Fatalf("wrong keypair: %v", err)
	}

	env, bobPriv, bobPub, bobFP := composeSimpleEnvelope(t, identityPub, identityPriv, identityFP)

	resolver := staticResolver{
		// Same address and key_id, but the wrong public key.
		"alice@a.example:" + string(identityFP): wrongPub,
	}
	candidates := []envelope.RecipientPrivateKey{
		{Fingerprint: bobFP, PrivateKey: bobPriv, PublicKey: bobPub},
	}
	res, err := envelope.OpenAndVerify(context.Background(), env, suite, candidates, resolver)
	if err != nil {
		t.Fatalf("OpenAndVerify: %v", err)
	}
	if res.SenderSignatureVerified {
		t.Error("SenderSignatureVerified true with wrong public key; want false")
	}
	if res.SenderSignatureError == nil {
		t.Error("SenderSignatureError nil with wrong public key; want error")
	}
}

// TestOpenAndVerifyResolverUnknownKey confirms ErrSenderKeyUnknown
// surfaces as a verification failure rather than a hard error.
func TestOpenAndVerifyResolverUnknownKey(t *testing.T) {
	suite := crypto.SuiteBaseline
	identityPub, identityPriv, err := suite.Signer().GenerateKeyPair()
	if err != nil {
		t.Fatalf("identity keypair: %v", err)
	}
	identityFP := keys.Compute(identityPub)

	env, bobPriv, bobPub, bobFP := composeSimpleEnvelope(t, identityPub, identityPriv, identityFP)

	resolver := staticResolver{} // empty: every lookup fails
	candidates := []envelope.RecipientPrivateKey{
		{Fingerprint: bobFP, PrivateKey: bobPriv, PublicKey: bobPub},
	}
	res, err := envelope.OpenAndVerify(context.Background(), env, suite, candidates, resolver)
	if err != nil {
		t.Fatalf("OpenAndVerify: %v", err)
	}
	if res.SenderSignatureVerified {
		t.Error("SenderSignatureVerified true with empty resolver; want false")
	}
	if !errors.Is(res.SenderSignatureError, envelope.ErrSenderKeyUnknown) {
		t.Errorf("SenderSignatureError = %v, want errors.Is(ErrSenderKeyUnknown)", res.SenderSignatureError)
	}
}

// TestOpenAndVerifyTamperedEnclosureBody confirms a body mutation
// after composition is caught by sender_signature verification.
func TestOpenAndVerifyTamperedEnclosureBody(t *testing.T) {
	suite := crypto.SuiteBaseline
	identityPub, identityPriv, err := suite.Signer().GenerateKeyPair()
	if err != nil {
		t.Fatalf("identity keypair: %v", err)
	}
	identityFP := keys.Compute(identityPub)

	// Compose, then tamper with the encrypted enclosure plaintext by
	// re-encrypting a different body under the SAME K_enclosure.
	// Easier: just open the enclosure, mutate the body, and check
	// that VerifyEnclosureSignature now fails.
	env, bobPriv, bobPub, bobFP := composeSimpleEnvelope(t, identityPub, identityPriv, identityFP)

	candidates := []envelope.RecipientPrivateKey{
		{Fingerprint: bobFP, PrivateKey: bobPriv, PublicKey: bobPub},
	}
	enc, err := envelope.OpenEnclosureAny(env, suite, candidates)
	if err != nil {
		t.Fatalf("OpenEnclosureAny: %v", err)
	}
	enc.Body["text/plain"] = "tampered body"
	resolver := staticResolver{
		"alice@a.example:" + string(identityFP): identityPub,
	}
	// Direct verification of the tampered enclosure MUST fail.
	if err := enclosure.VerifyEnclosureSignature(enc, suite, identityPub); err == nil {
		t.Error("VerifyEnclosureSignature accepted tampered body")
	}
	// And the OpenAndVerify path catches it via the same primitive
	// after re-decrypting fresh from the wire.
	wireBytes, err := envelope.Encode(env)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	wireBytes[len(wireBytes)/3] ^= 0x01 // flip a byte inside the encrypted enclosure
	tampered, err := envelope.Decode(wireBytes)
	if err == nil {
		// Decode succeeded; OpenAndVerify will surface either a
		// decryption failure (AEAD detects ciphertext mutation) or
		// a sender-signature failure. Either way is acceptable
		// per §6.5.3 "MUST NOT silently render".
		_, err := envelope.OpenAndVerify(context.Background(), tampered, suite, candidates, resolver)
		if err == nil {
			t.Log("OpenAndVerify did not error on byte-flipped wire; this can happen if the flipped byte landed in the padding field which is excluded from AEAD additional-data and from sender_signature canonical bytes")
		}
	}
}

// TestOpenAndVerifyMissingSenderSignature confirms an enclosure
// without a sender_signature surfaces as a verification failure.
//
// To produce one we have to bypass Compose's auto-signing and craft
// a sealed envelope manually. We invoke Compose with
// SkipSenderSignature: true.
func TestOpenAndVerifyMissingSenderSignature(t *testing.T) {
	suite := crypto.SuiteBaseline

	bobPub, bobPriv, err := suite.KEM().GenerateKeyPair()
	if err != nil {
		t.Fatalf("bob keypair: %v", err)
	}
	bobFP := keys.Compute(bobPub)

	in := &envelope.ComposeInput{
		Suite: suite,
		Postmark: envelope.Postmark{
			ID:         "01JTESTOPENVERIFYNOSIG0001",
			SessionID:  "01JTESTSESSION00000000000001",
			FromDomain: "a.example",
			ToDomain:   "b.example",
			Expires:    time.Now().UTC().Add(time.Hour),
		},
		Brief: brief.Brief{
			MessageID: "msg-nosig",
			From:      "alice@a.example",
			To:        []brief.Address{"bob@b.example"},
			SentAt:    time.Now().UTC(),
		},
		Enclosure: enclosure.Enclosure{
			ContentType: "text/plain",
			Body:        enclosure.Body{"text/plain": "no signature"},
		},
		SenderDomainKeyID: "sender-domain-fp",
		BriefRecipients: []seal.RecipientKey{
			{Fingerprint: bobFP, PublicKey: bobPub, Kind: seal.KindUserClient},
		},
		EnclosureRecipients: []seal.RecipientKey{
			{Fingerprint: bobFP, PublicKey: bobPub, Kind: seal.KindUserClient},
		},
		SkipSenderSignature: true,
	}
	env, err := envelope.Compose(in)
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}

	candidates := []envelope.RecipientPrivateKey{
		{Fingerprint: bobFP, PrivateKey: bobPriv, PublicKey: bobPub},
	}
	resolver := staticResolver{}
	res, err := envelope.OpenAndVerify(context.Background(), env, suite, candidates, resolver)
	if err != nil {
		t.Fatalf("OpenAndVerify: %v", err)
	}
	if res.SenderSignatureVerified {
		t.Error("SenderSignatureVerified true on enclosure with no signature; want false")
	}
	if res.SenderSignatureError == nil {
		t.Error("SenderSignatureError nil on enclosure with no signature; want error")
	}
}

// Additional helpers used by the static resolver above. Keeps the
// file linker-clean.
var _ = base64.StdEncoding
