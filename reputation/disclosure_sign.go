package reputation

import (
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/semp-dev/semp-go/crypto"
	"github.com/semp-dev/semp-go/canonical"
	"github.com/semp-dev/semp-go/keys"
)


// -----------------------------------------------------------------------------
// DisclosureAuthorization signing
// -----------------------------------------------------------------------------

// canonicalDisclosureAuthorizationBytes returns the canonical JSON
// form of auth with signature.value elided - same elider pattern as
// the observation signer.
func canonicalDisclosureAuthorizationBytes(auth *DisclosureAuthorization) ([]byte, error) {
	if auth == nil {
		return nil, errors.New("reputation: nil disclosure authorization")
	}
	return canonical.MarshalWithElision(auth, func(v any) error {
		m, ok := v.(map[string]any)
		if !ok {
			return fmt.Errorf("reputation: expected top-level object, got %T", v)
		}
		sig, ok := m["signature"].(map[string]any)
		if !ok {
			return errors.New("reputation: disclosure authorization has no signature object")
		}
		sig["value"] = ""
		return nil
	})
}

// SignDisclosureAuthorization computes an Ed25519 signature over the
// canonical form of auth and populates auth.Signature. The user's
// own identity private key is used - this is the proof REPUTATION.md
// §3.7 requires before decrypted content can be included in abuse
// evidence.
func SignDisclosureAuthorization(signer crypto.Signer, privKey []byte, userKeyID keys.Fingerprint, auth *DisclosureAuthorization) error {
	if signer == nil {
		return errors.New("reputation: nil signer")
	}
	if auth == nil {
		return errors.New("reputation: nil disclosure authorization")
	}
	if len(privKey) == 0 {
		return errors.New("reputation: empty signing private key")
	}
	if auth.Scope == "" {
		return errors.New("reputation: disclosure authorization missing scope")
	}
	auth.Signature.Algorithm = keys.SignatureAlgorithmEd25519
	auth.Signature.KeyID = userKeyID
	msg, err := canonicalDisclosureAuthorizationBytes(auth)
	if err != nil {
		return fmt.Errorf("reputation: canonical disclosure authorization: %w", err)
	}
	sigBytes, err := signer.Sign(privKey, msg)
	if err != nil {
		return fmt.Errorf("reputation: sign disclosure authorization: %w", err)
	}
	auth.Signature.Value = base64.StdEncoding.EncodeToString(sigBytes)
	return nil
}

// VerifyDisclosureAuthorization verifies auth.Signature against the
// affected user's published identity key. The handler MUST call this
// before accepting any evidence that includes decrypted content.
func VerifyDisclosureAuthorization(signer crypto.Signer, auth *DisclosureAuthorization, userPub []byte) error {
	if signer == nil {
		return errors.New("reputation: nil signer")
	}
	if auth == nil {
		return errors.New("reputation: nil disclosure authorization")
	}
	if auth.Signature.Value == "" {
		return errors.New("reputation: disclosure authorization is unsigned")
	}
	if len(userPub) == 0 {
		return errors.New("reputation: empty user public key")
	}
	sigBytes, err := base64.StdEncoding.DecodeString(auth.Signature.Value)
	if err != nil {
		return fmt.Errorf("reputation: disclosure authorization signature base64: %w", err)
	}
	msg, err := canonicalDisclosureAuthorizationBytes(auth)
	if err != nil {
		return fmt.Errorf("reputation: canonical disclosure authorization: %w", err)
	}
	if err := signer.Verify(userPub, msg, sigBytes); err != nil {
		return fmt.Errorf("reputation: verify disclosure authorization: %w", err)
	}
	return nil
}

// UserKeyLookup resolves a user's identity public key. Used by
// ValidateEvidence to verify embedded DisclosureAuthorization
// signatures. Returning (nil, nil) means "unknown user" - callers
// MUST treat that as a §3.7 verification failure.
type UserKeyLookup func(ctx any, user string) ([]byte, error)

// validateEvidence walks the evidence payload and enforces the
// REPUTATION.md §3.7 rule: decrypted content requires a valid
// DisclosureAuthorization signed by the affected user.
func ValidateEvidence(ev *Evidence, signer crypto.Signer, userKeys UserKeyLookup, ctx any) error {
	switch ev.Type {
	case "", EvidenceTypeEnvelopeMetadata:
		// Metadata evidence is always acceptable - the postmark +
		// seal evidence can be independently verified by the
		// receiving server from the sender's published domain key,
		// and no user content is disclosed.
		return nil
	case EvidenceTypeSealedEvidence:
		for i, env := range ev.Envelopes {
			discloses := env.DisclosedBrief != nil || env.DisclosedEnclosure != nil
			if !discloses {
				continue
			}
			if env.DisclosureAuthorization == nil {
				return fmt.Errorf("envelope[%d]: decrypted content without disclosure authorization", i)
			}
			auth := env.DisclosureAuthorization
			if env.DisclosedBrief != nil && !auth.AllowsBrief() {
				return fmt.Errorf("envelope[%d]: brief disclosure outside authorized scope %q", i, auth.Scope)
			}
			if env.DisclosedEnclosure != nil && !auth.AllowsEnclosure() {
				return fmt.Errorf("envelope[%d]: enclosure disclosure outside authorized scope %q", i, auth.Scope)
			}
			// If we have a signer and a user key lookup, verify
			// the authorization signature. Callers that run the
			// handler in metadata-only mode may skip this by
			// leaving Signer or UserKeys nil, but they also cannot
			// accept sealed evidence - we check that here.
			if signer == nil || userKeys == nil {
				return fmt.Errorf("envelope[%d]: sealed evidence not accepted (handler lacks signer/user key lookup)", i)
			}
			pub, err := userKeys(ctx, auth.User)
			if err != nil {
				return fmt.Errorf("envelope[%d]: lookup user key for %s: %w", i, auth.User, err)
			}
			if len(pub) == 0 {
				return fmt.Errorf("envelope[%d]: unknown user %s in disclosure authorization", i, auth.User)
			}
			if err := VerifyDisclosureAuthorization(signer, auth, pub); err != nil {
				return fmt.Errorf("envelope[%d]: %w", i, err)
			}
		}
		return nil
	default:
		return fmt.Errorf("unknown evidence type %q", ev.Type)
	}
}