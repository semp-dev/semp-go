package reputation

import (
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/semp-dev/semp-go/crypto"
	"github.com/semp-dev/semp-go/extensions"
	"github.com/semp-dev/semp-go/internal/canonical"
	"github.com/semp-dev/semp-go/keys"
)

// NewObservation constructs an Observation with the wire-level fields
// populated from the store's current counters for subject. The caller
// supplies the ID, window, assessment, and any evidence hint; the
// store fills metrics. Signature is left zero — the caller signs the
// observation with SignObservation before publishing.
//
// NewObservation is a convenience: operators that build observations
// from a different signal source can construct the struct directly.
func (s *ObservationStore) NewObservation(observer, subject, id string, window Window, assessment Assessment) *Observation {
	if s == nil {
		return nil
	}
	now := s.nowFunc()
	return &Observation{
		Type:       ObservationType,
		Version:    ObservationVersion,
		ID:         id,
		Observer:   observer,
		Subject:    subject,
		Window:     window,
		Metrics:    s.Metrics(subject),
		Assessment: assessment,
		Timestamp:  now,
		// Expires defaults to the end of the window. Callers that
		// want a different expiry set it after this call returns.
		Expires:    window.End,
		Extensions: extensions.Map{},
	}
}

// canonicalObservationBytes returns the canonical JSON form of obs
// with signature.value elided. Same pattern as discovery.SignResponse
// — the algorithm and key_id fields are preserved so an attacker can't
// swap them without invalidating the signature.
func canonicalObservationBytes(obs *Observation) ([]byte, error) {
	if obs == nil {
		return nil, errors.New("reputation: nil observation")
	}
	return canonical.MarshalWithElision(obs, func(v any) error {
		m, ok := v.(map[string]any)
		if !ok {
			return fmt.Errorf("reputation: expected top-level object, got %T", v)
		}
		sig, ok := m["signature"].(map[string]any)
		if !ok {
			return errors.New("reputation: observation has no signature object")
		}
		sig["value"] = ""
		return nil
	})
}

// SignObservation computes an Ed25519 signature over the canonical
// form of obs with signature.value elided, then populates
// obs.Signature with the algorithm, the observer domain's key
// fingerprint, and the base64-encoded signature bytes.
//
// Reference: REPUTATION.md §4.2 + §3.6 step 2 ("the reporting server
// signs the observation record that contains the evidence").
func SignObservation(signer crypto.Signer, privKey []byte, observerKeyID keys.Fingerprint, obs *Observation) error {
	if signer == nil {
		return errors.New("reputation: nil signer")
	}
	if obs == nil {
		return errors.New("reputation: nil observation")
	}
	if len(privKey) == 0 {
		return errors.New("reputation: empty signing private key")
	}
	if obs.Type == "" {
		obs.Type = ObservationType
	}
	if obs.Version == "" {
		obs.Version = ObservationVersion
	}
	if obs.Extensions == nil {
		// Canonicalization emits an explicit `{}` for an empty map
		// but we prefer to allocate rather than rely on serializer
		// behavior — this guarantees the struct is valid even when
		// the caller constructed it without an extensions block.
		obs.Extensions = extensions.Map{}
	}
	obs.Signature.Algorithm = keys.SignatureAlgorithmEd25519
	obs.Signature.KeyID = observerKeyID
	msg, err := canonicalObservationBytes(obs)
	if err != nil {
		return fmt.Errorf("reputation: canonical observation: %w", err)
	}
	sigBytes, err := signer.Sign(privKey, msg)
	if err != nil {
		return fmt.Errorf("reputation: sign observation: %w", err)
	}
	obs.Signature.Value = base64.StdEncoding.EncodeToString(sigBytes)
	return nil
}

// VerifyObservation verifies obs.Signature against the given observer
// domain public key. Per REPUTATION.md §5.2 a fetching server MUST
// verify the signature on every fetched observation before using it;
// unsigned or unverifiable observations MUST be discarded.
func VerifyObservation(signer crypto.Signer, obs *Observation, observerPub []byte) error {
	if signer == nil {
		return errors.New("reputation: nil signer")
	}
	if obs == nil {
		return errors.New("reputation: nil observation")
	}
	if obs.Signature.Value == "" {
		return errors.New("reputation: observation is unsigned")
	}
	if len(observerPub) == 0 {
		return errors.New("reputation: empty observer public key")
	}
	sigBytes, err := base64.StdEncoding.DecodeString(obs.Signature.Value)
	if err != nil {
		return fmt.Errorf("reputation: signature base64: %w", err)
	}
	msg, err := canonicalObservationBytes(obs)
	if err != nil {
		return fmt.Errorf("reputation: canonical observation: %w", err)
	}
	if err := signer.Verify(observerPub, msg, sigBytes); err != nil {
		return fmt.Errorf("reputation: verify observation signature: %w", err)
	}
	return nil
}
