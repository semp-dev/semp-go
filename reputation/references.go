package reputation

import (
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"semp.dev/semp-go/canonical"
	"semp.dev/semp-go/crypto"
	"semp.dev/semp-go/keys"
)

// SEMP_REPUTATION_REFERENCES message constants per
// draft-gokce-semp-delivery §12.2. The record lists third-party
// observers a subject domain points peers at when they want to
// cross-check the subject's reputation. The subject domain signs
// the document with its domain signing key under the
// SEMP-REPUTATION-REFERENCES: prefix; consumers verify against
// the published domain key.
const (
	ReferencesType    = "SEMP_REPUTATION_REFERENCES"
	ReferencesVersion = "1.0.0"
)

// ReferenceEntry is one observer reference in a References
// document. Optional assessment hint lets the subject domain
// indicate the third-party observer's classification at fetch
// time (informational; consumers re-fetch and verify).
type ReferenceEntry struct {
	Observer string `json:"observer"`
	URI      string `json:"uri"`
	// FetchedAt is the timestamp the subject last fetched the
	// referenced observer's published observation.
	FetchedAt time.Time `json:"fetched_at"`
	// Assessment is the optional cached hint.
	Assessment Assessment `json:"assessment,omitempty"`
}

// References is a SEMP_REPUTATION_REFERENCES document per §12.2.
type References struct {
	Type       string                    `json:"type"`
	Version    string                    `json:"version"`
	Domain     string                    `json:"domain"`
	References []ReferenceEntry          `json:"references"`
	Timestamp  time.Time                 `json:"timestamp"`
	Signature  keys.PublicationSignature `json:"signature"`
}

func canonicalReferencesBytes(r *References) ([]byte, error) {
	if r == nil {
		return nil, errors.New("reputation: nil references")
	}
	return canonical.MarshalWithElision(r, func(v any) error {
		root, ok := v.(map[string]any)
		if !ok {
			return fmt.Errorf("reputation: expected top-level object, got %T", v)
		}
		sig, ok := root["signature"].(map[string]any)
		if !ok {
			return errors.New("reputation: references missing signature object")
		}
		sig["value"] = ""
		return nil
	})
}

// SignReferences populates r.Signature with the subject domain
// signing key's signature over the canonical bytes prefixed by
// SEMP-REPUTATION-REFERENCES:.
func SignReferences(signer crypto.Signer, domainPriv []byte, domainKeyID keys.Fingerprint, r *References) error {
	if signer == nil {
		return errors.New("reputation: nil signer")
	}
	if r == nil {
		return errors.New("reputation: nil references")
	}
	if len(domainPriv) == 0 {
		return errors.New("reputation: empty domain private key")
	}
	if domainKeyID == "" {
		return errors.New("reputation: empty domain key fingerprint")
	}
	if r.Type == "" {
		r.Type = ReferencesType
	}
	if r.Version == "" {
		r.Version = ReferencesVersion
	}
	if err := r.Validate(); err != nil {
		return err
	}
	r.Signature.Algorithm = "ed25519"
	r.Signature.KeyID = domainKeyID
	r.Signature.Value = ""
	canonicalBytes, err := canonicalReferencesBytes(r)
	if err != nil {
		return err
	}
	prefixed := crypto.PrefixedMessage(crypto.SigCtxReputationReferences, canonicalBytes)
	sig, err := signer.Sign(domainPriv, prefixed)
	if err != nil {
		return fmt.Errorf("reputation: sign references: %w", err)
	}
	r.Signature.Value = base64.StdEncoding.EncodeToString(sig)
	return nil
}

// VerifyReferences checks r.Signature against domainPub per §12.2.
func VerifyReferences(signer crypto.Signer, domainPub []byte, r *References) error {
	if signer == nil {
		return errors.New("reputation: nil signer")
	}
	if r == nil {
		return errors.New("reputation: nil references")
	}
	if len(domainPub) == 0 {
		return errors.New("reputation: empty domain public key")
	}
	if r.Signature.Value == "" {
		return errors.New("reputation: references is unsigned")
	}
	if err := r.Validate(); err != nil {
		return err
	}
	sig, err := base64.StdEncoding.DecodeString(r.Signature.Value)
	if err != nil {
		return fmt.Errorf("reputation: references signature base64: %w", err)
	}
	canonicalBytes, err := canonicalReferencesBytes(r)
	if err != nil {
		return err
	}
	prefixed := crypto.PrefixedMessage(crypto.SigCtxReputationReferences, canonicalBytes)
	if err := signer.Verify(domainPub, prefixed, sig); err != nil {
		return fmt.Errorf("reputation: verify references: %w", err)
	}
	return nil
}

// Validate reports whether r is structurally well-formed per
// §12.2.
func (r *References) Validate() error {
	if r == nil {
		return errors.New("reputation: nil references")
	}
	if r.Type != ReferencesType {
		return fmt.Errorf("reputation: references type %q, want %q",
			r.Type, ReferencesType)
	}
	if r.Version == "" {
		return errors.New("reputation: references missing version")
	}
	if r.Domain == "" {
		return errors.New("reputation: references missing domain")
	}
	if r.Timestamp.IsZero() {
		return errors.New("reputation: references missing timestamp")
	}
	for i, e := range r.References {
		if e.Observer == "" {
			return fmt.Errorf("reputation: references[%d] missing observer", i)
		}
		if e.URI == "" {
			return fmt.Errorf("reputation: references[%d] missing uri", i)
		}
		if e.FetchedAt.IsZero() {
			return fmt.Errorf("reputation: references[%d] missing fetched_at", i)
		}
	}
	return nil
}
