package envelope

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"semp.dev/semp-go/brief"
	"semp.dev/semp-go/crypto"
	"semp.dev/semp-go/enclosure"
	"semp.dev/semp-go/keys"
	"semp.dev/semp-go/seal"
)

// ComposeInput is the bundle of inputs the sending client provides to
// Compose to produce a sealed-but-unsigned envelope.
type ComposeInput struct {
	// Suite is the negotiated algorithm suite for this session.
	Suite crypto.Suite

	// Postmark is the routing header. Compose will not modify it; the
	// caller MUST set ID, SessionID, FromDomain, ToDomain, and Expires
	// before calling Compose.
	Postmark Postmark

	// Brief is the inner private header (sender, recipients, threading).
	Brief brief.Brief

	// Enclosure is the message body and attachments.
	Enclosure enclosure.Enclosure

	// SenderDomainKeyID is the fingerprint of the sender domain key that
	// will be used to sign the envelope. The actual signing is done in a
	// separate Sign step performed by the sender's home server. The
	// fingerprint is recorded in seal.key_id at compose time so that
	// canonical bytes are stable.
	SenderDomainKeyID keys.Fingerprint

	// BriefRecipients lists every party that should be able to decrypt
	// K_brief: typically the recipient server's domain key plus the
	// recipient client's encryption key. Per ENVELOPE.md §7.1 steps 6–7.
	BriefRecipients []seal.RecipientKey

	// EnclosureRecipients lists every party that should be able to
	// decrypt K_enclosure: typically only the recipient client's
	// encryption key. Per ENVELOPE.md §7.1 step 8. The recipient server
	// MUST NOT appear in this list.
	EnclosureRecipients []seal.RecipientKey

	// SkipPadding, when true, disables the automatic FillPadding call at
	// the end of Compose. Default (false) pads every composed envelope
	// to a bucket per ENVELOPE.md section 2.4.1. Callers that intend to
	// mutate the envelope before signing (for example, tests that build
	// deterministic vectors) may set this to true and invoke FillPadding
	// themselves.
	SkipPadding bool

	// MaxEnvelopeSize is the session-negotiated ceiling passed through
	// to FillPadding. Zero selects DefaultMaxEnvelopeSize.
	MaxEnvelopeSize int64

	// BucketSequence, if non-empty, overrides the default power-of-two
	// bucket curve and is passed through to FillPadding. See
	// envelope.PadConfig.
	BucketSequence []int64
}

// Compose performs steps 1–9 of the encryption flow in ENVELOPE.md §7.1:
// it generates fresh K_brief and K_enclosure, encrypts the brief and
// enclosure under those keys, wraps the symmetric keys for each recipient,
// assembles the seal, and returns the unsigned envelope.
//
// The returned envelope has Seal.Signature and Seal.SessionMAC empty —
// signing is performed by the sender's home server in a separate step
// using seal.Signer (envelope.Sign in this package).
//
// The fresh K_brief and K_enclosure are erased from memory before Compose
// returns; only their wrapped forms in the seal survive.
func Compose(in *ComposeInput) (*Envelope, error) {
	if in == nil || in.Suite == nil {
		return nil, errors.New("envelope: nil ComposeInput or suite")
	}
	if in.Postmark.SessionID == "" {
		return nil, errors.New("envelope: postmark.session_id is required")
	}
	if len(in.BriefRecipients) == 0 {
		return nil, errors.New("envelope: at least one brief recipient required")
	}
	if len(in.EnclosureRecipients) == 0 {
		return nil, errors.New("envelope: at least one enclosure recipient required")
	}

	aead := in.Suite.AEAD()

	// Step 2: fresh K_brief and K_enclosure.
	kBrief, err := crypto.FreshKey(aead)
	if err != nil {
		return nil, fmt.Errorf("envelope: K_brief: %w", err)
	}
	defer crypto.Zeroize(kBrief)
	kEnclosure, err := crypto.FreshKey(aead)
	if err != nil {
		return nil, fmt.Errorf("envelope: K_enclosure: %w", err)
	}
	defer crypto.Zeroize(kEnclosure)

	// Step 3: encrypt brief.
	briefBytes, err := json.Marshal(in.Brief)
	if err != nil {
		return nil, fmt.Errorf("envelope: marshal brief: %w", err)
	}
	briefNonce, err := crypto.FreshNonce(aead)
	if err != nil {
		return nil, fmt.Errorf("envelope: brief nonce: %w", err)
	}
	envelopeAAD := []byte(in.Postmark.ID)
	briefCT, err := aead.Seal(kBrief, briefNonce, briefBytes, envelopeAAD)
	if err != nil {
		return nil, fmt.Errorf("envelope: encrypt brief: %w", err)
	}
	briefBlob := base64.StdEncoding.EncodeToString(append(briefNonce, briefCT...))

	// Step 4: encrypt enclosure.
	enclBytes, err := json.Marshal(in.Enclosure)
	if err != nil {
		return nil, fmt.Errorf("envelope: marshal enclosure: %w", err)
	}
	enclNonce, err := crypto.FreshNonce(aead)
	if err != nil {
		return nil, fmt.Errorf("envelope: enclosure nonce: %w", err)
	}
	enclCT, err := aead.Seal(kEnclosure, enclNonce, enclBytes, envelopeAAD)
	if err != nil {
		return nil, fmt.Errorf("envelope: encrypt enclosure: %w", err)
	}
	enclBlob := base64.StdEncoding.EncodeToString(append(enclNonce, enclCT...))

	// Steps 6–8: wrap K_brief and K_enclosure for recipients.
	wrapper := seal.NewWrapper(in.Suite)
	if wrapper == nil {
		return nil, errors.New("envelope: nil wrapper for suite")
	}
	briefRecipients, err := seal.WrapForRecipients(wrapper, kBrief, in.BriefRecipients)
	if err != nil {
		return nil, fmt.Errorf("envelope: wrap brief recipients: %w", err)
	}
	enclosureRecipients, err := seal.WrapForRecipients(wrapper, kEnclosure, in.EnclosureRecipients)
	if err != nil {
		return nil, fmt.Errorf("envelope: wrap enclosure recipients: %w", err)
	}

	// Steps 9 + assembly: build the envelope.
	env := New()
	env.Postmark = in.Postmark
	env.Seal = seal.Seal{
		Algorithm:           in.Suite.ID(),
		KeyID:               in.SenderDomainKeyID,
		BriefRecipients:     briefRecipients,
		EnclosureRecipients: enclosureRecipients,
	}
	env.Brief = briefBlob
	env.Enclosure = enclBlob

	// Recipient-count obfuscation (ENVELOPE.md section 4.4.1). Pad
	// the enclosure map to the next power-of-two of the real
	// user-client count, and pad the brief map to enclosure_bucket +
	// domain_bucket. Dummy entries are indistinguishable from real
	// wrappings on the wire.
	enclosureRealCount, err := countByKind(in.EnclosureRecipients, seal.KindUserClient)
	if err != nil {
		return nil, fmt.Errorf("envelope: enclosure recipient count: %w", err)
	}
	if enclosureRealCount != len(in.EnclosureRecipients) {
		return nil, errors.New("envelope: enclosure_recipients MUST contain only user-client entries (ENVELOPE.md section 4.4)")
	}
	briefUserClients, _ := countByKind(in.BriefRecipients, seal.KindUserClient)
	briefServerDomains, _ := countByKind(in.BriefRecipients, seal.KindServerDomain)
	if briefUserClients+briefServerDomains != len(in.BriefRecipients) {
		return nil, errors.New("envelope: every brief_recipients entry MUST set RecipientKey.Kind to KindUserClient or KindServerDomain")
	}
	if err := PadEnclosureRecipients(&env.Seal, enclosureRealCount); err != nil {
		return nil, fmt.Errorf("envelope: pad enclosure recipients: %w", err)
	}
	if err := PadBriefRecipients(&env.Seal, briefUserClients, briefServerDomains); err != nil {
		return nil, fmt.Errorf("envelope: pad brief recipients: %w", err)
	}

	// Size-bucket obfuscation (ENVELOPE.md section 2.4.1). FillPadding
	// runs with placeholder signature and MAC when the envelope is
	// unsigned so the bucket calculation matches the final on-wire size
	// after Sign.
	if !in.SkipPadding {
		cfg := PadConfig{
			MaxEnvelopeSize: in.MaxEnvelopeSize,
			BucketSequence:  in.BucketSequence,
		}
		if err := FillPadding(env, cfg); err != nil {
			return nil, fmt.Errorf("envelope: fill padding: %w", err)
		}
	}

	return env, nil
}

// countByKind returns how many entries in rs have Kind == want, plus
// an error if any entry has an unrecognized Kind. Entries with an
// empty Kind are reported as the zero count and produce no error here;
// the caller distinguishes the unknown-kind case via the count check.
func countByKind(rs []seal.RecipientKey, want seal.RecipientKind) (int, error) {
	n := 0
	for _, r := range rs {
		switch r.Kind {
		case seal.KindUserClient, seal.KindServerDomain:
			if r.Kind == want {
				n++
			}
		default:
			return 0, fmt.Errorf("recipient %q has unrecognized Kind %q", r.Fingerprint, r.Kind)
		}
	}
	return n, nil
}

// Sign performs steps 10–12 of the encryption flow in ENVELOPE.md §7.1:
// it computes the canonical envelope bytes, signs them with the sender
// domain private key, and MACs them with K_env_mac, storing both proofs
// in env.Seal.
//
// Sign is normally called by the sender's home server, after the client
// has called Compose and transmitted the assembled envelope. Clients
// never hold domainPrivateKey or envMAC and therefore never call Sign.
func Sign(env *Envelope, suite crypto.Suite, domainPrivateKey, envMAC []byte) error {
	if env == nil {
		return errors.New("envelope: nil envelope")
	}
	canonicalBytes, err := env.CanonicalBytes()
	if err != nil {
		return fmt.Errorf("envelope: canonical bytes: %w", err)
	}
	signer := &seal.Signer{
		Suite:            suite,
		DomainPrivateKey: domainPrivateKey,
		EnvMAC:           envMAC,
	}
	return signer.Sign(&env.Seal, canonicalBytes)
}

// RebindSessionMAC recomputes seal.session_mac under a fresh K_env_mac
// without touching seal.signature. It is the operation a sending server
// performs when forwarding an already-signed envelope across a federation
// hop: the domain signature stays valid (it's the original sender domain
// proving the envelope's provenance to the world), but the session MAC
// must be re-bound to the federation session that's actually carrying
// the envelope on this hop.
//
// This is safe because the canonical bytes used as input to BOTH proofs
// have signature AND session_mac elided to "" (ENVELOPE.md §4.3), so
// changing one does not invalidate the other.
//
// Reference: ENVELOPE.md §4.3, §4.2; HANDSHAKE.md §1.2 (federation hop).
func RebindSessionMAC(env *Envelope, suite crypto.Suite, envMAC []byte) error {
	if env == nil {
		return errors.New("envelope: nil envelope")
	}
	if len(envMAC) == 0 {
		return errors.New("envelope: empty envMAC for rebind")
	}
	canonicalBytes, err := env.CanonicalBytes()
	if err != nil {
		return fmt.Errorf("envelope: canonical bytes: %w", err)
	}
	mac := crypto.ComputeMAC(envMAC, canonicalBytes)
	env.Seal.SessionMAC = base64.StdEncoding.EncodeToString(mac)
	return nil
}
