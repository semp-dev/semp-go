// Package closure implements SEMP_ACCOUNT_CLOSURE record types and
// signing primitives per CLOSURE.md.
//
// A closure is a two-step lifecycle: a full-access device submits a
// `request` with a grace period; during the grace period any
// full-access device may submit a `cancel` to abort. At
// requested_at + grace_period_seconds the home server finalizes
// per CLOSURE.md §4.
//
// This package covers the wire records and their signing/verifying
// primitives. Home-server orchestration (closure_pending state,
// finalization atomic effects, ingress handling after finalization,
// local-part reassignment) is operational and lives in a
// future server-side commit.
package closure

import (
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/semp-dev/semp-go/crypto"
	"github.com/semp-dev/semp-go/canonical"
)

// Wire-level constants per CLOSURE.md §2.1.
const (
	RecordType    = "SEMP_ACCOUNT_CLOSURE"
	RecordVersion = "1.0.0"
)

// Step is the request step discriminator per CLOSURE.md §2.2.
type Step string

// Closure steps.
const (
	StepRequest Step = "request"
	StepCancel  Step = "cancel"
)

// Grace-period bounds per CLOSURE.md §3.1. Operators MAY enforce a
// narrower range within these bounds but MUST NOT exceed them.
const (
	// MinGracePeriod is the spec's hard lower bound: less than 7
	// days gives the user insufficient time to discover an
	// unauthorized closure attempt.
	MinGracePeriod = 7 * 24 * time.Hour

	// MaxGracePeriod is the spec's hard upper bound: longer ties up
	// the local-part and prolongs user uncertainty.
	MaxGracePeriod = 90 * 24 * time.Hour

	// RecommendedGracePeriod is the §3.1 default.
	RecommendedGracePeriod = 30 * 24 * time.Hour
)

// SignatureAlgorithmEd25519 is the only signature algorithm
// defined for closure records in the current spec.
const SignatureAlgorithmEd25519 = "ed25519"

// Signature is the reusable signature block.
type Signature struct {
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"key_id"`
	Value     string `json:"value"`
}

// Record is a SEMP_ACCOUNT_CLOSURE request or cancel record per
// CLOSURE.md §2.1. The same shape covers both steps; Step
// disambiguates.
//
// GracePeriodSeconds is exposed as a typed time.Duration internally
// but marshals as the spec's integer-seconds form via the JSON
// helper below.
type Record struct {
	Type               string        `json:"type"`
	Step               Step          `json:"step"`
	Version            string        `json:"version"`
	UserID             string        `json:"user_id"`
	RequestedAt        time.Time     `json:"requested_at"`
	GracePeriodSeconds int64         `json:"grace_period_seconds"`
	IssuedBy           string        `json:"issued_by"`
	Signature          Signature     `json:"signature"`
}

// GracePeriod returns the grace period as a time.Duration.
func (r *Record) GracePeriod() time.Duration {
	if r == nil {
		return 0
	}
	return time.Duration(r.GracePeriodSeconds) * time.Second
}

// FinalizationAt returns the wall-clock time at which the home
// server MUST finalize per §4.1: requested_at +
// grace_period_seconds.
func (r *Record) FinalizationAt() time.Time {
	if r == nil {
		return time.Time{}
	}
	return r.RequestedAt.Add(r.GracePeriod())
}

// canonicalBytes returns the canonical JSON form of r with
// signature.value elided to "".
func canonicalBytes(r *Record) ([]byte, error) {
	if r == nil {
		return nil, errors.New("closure: nil record")
	}
	return canonical.MarshalWithElision(r, func(v any) error {
		m, ok := v.(map[string]any)
		if !ok {
			return fmt.Errorf("closure: expected top-level object, got %T", v)
		}
		sig, ok := m["signature"].(map[string]any)
		if !ok {
			return errors.New("closure: record missing signature object")
		}
		sig["value"] = ""
		return nil
	})
}

// SignRecord populates r.Signature with the full-access device's
// signature over the canonical record bytes per CLOSURE.md §2.3.
// devicePriv is the issuing device's private key; deviceKeyID is
// its fingerprint and MUST appear in r.IssuedBy / signature.key_id.
func SignRecord(signer crypto.Signer, devicePriv []byte, deviceKeyID string, r *Record) error {
	if signer == nil {
		return errors.New("closure: nil signer")
	}
	if r == nil {
		return errors.New("closure: nil record")
	}
	if len(devicePriv) == 0 {
		return errors.New("closure: empty device private key")
	}
	if deviceKeyID == "" {
		return errors.New("closure: empty device key fingerprint")
	}
	if r.Type == "" {
		r.Type = RecordType
	}
	if r.Version == "" {
		r.Version = RecordVersion
	}
	if err := r.Validate(); err != nil {
		return err
	}
	r.Signature.Algorithm = SignatureAlgorithmEd25519
	r.Signature.KeyID = deviceKeyID
	r.Signature.Value = ""
	bytes, err := canonicalBytes(r)
	if err != nil {
		return err
	}
	prefixed := crypto.PrefixedMessage(crypto.SigCtxAccountClosure, bytes)
	sig, err := signer.Sign(devicePriv, prefixed)
	if err != nil {
		return fmt.Errorf("closure: sign record: %w", err)
	}
	r.Signature.Value = base64.StdEncoding.EncodeToString(sig)
	return nil
}

// VerifyRecord checks r.Signature against devicePub per CLOSURE.md
// §2.3.
//
// VerifyRecord does NOT enforce the §2.3 authority rule (the
// signing device MUST be a current full-access device of the
// account); the home server applies that check via the device
// directory.
func VerifyRecord(signer crypto.Signer, devicePub []byte, r *Record) error {
	if signer == nil {
		return errors.New("closure: nil signer")
	}
	if r == nil {
		return errors.New("closure: nil record")
	}
	if len(devicePub) == 0 {
		return errors.New("closure: empty device public key")
	}
	if r.Signature.Value == "" {
		return errors.New("closure: record is unsigned")
	}
	if err := r.Validate(); err != nil {
		return err
	}
	sig, err := base64.StdEncoding.DecodeString(r.Signature.Value)
	if err != nil {
		return fmt.Errorf("closure: signature base64: %w", err)
	}
	bytes, err := canonicalBytes(r)
	if err != nil {
		return err
	}
	prefixed := crypto.PrefixedMessage(crypto.SigCtxAccountClosure, bytes)
	if err := signer.Verify(devicePub, prefixed, sig); err != nil {
		return fmt.Errorf("closure: verify record: %w", err)
	}
	return nil
}

// Validate reports whether r is structurally well-formed per
// CLOSURE.md §2.2. Cancel records skip the grace-period bound
// check because §3.2 cancellation does not introduce a new grace
// period; the request being canceled already validated its bound.
func (r *Record) Validate() error {
	if r == nil {
		return errors.New("closure: nil record")
	}
	if r.Type != RecordType {
		return fmt.Errorf("closure: type %q, want %q", r.Type, RecordType)
	}
	switch r.Step {
	case StepRequest, StepCancel:
		// ok
	case "":
		return errors.New("closure: missing step")
	default:
		return fmt.Errorf("closure: step %q is not request or cancel", r.Step)
	}
	if r.UserID == "" {
		return errors.New("closure: missing user_id")
	}
	if r.RequestedAt.IsZero() {
		return errors.New("closure: missing requested_at")
	}
	if r.IssuedBy == "" {
		return errors.New("closure: missing issued_by")
	}
	if r.Step == StepRequest {
		grace := r.GracePeriod()
		if grace < MinGracePeriod {
			return fmt.Errorf("closure: grace_period_seconds %d below minimum %d (7 days)",
				r.GracePeriodSeconds, int64(MinGracePeriod.Seconds()))
		}
		if grace > MaxGracePeriod {
			return fmt.Errorf("closure: grace_period_seconds %d exceeds maximum %d (90 days)",
				r.GracePeriodSeconds, int64(MaxGracePeriod.Seconds()))
		}
	}
	return nil
}

// IsFinalizable reports whether now has reached or passed the
// finalization timestamp per §4.1. Returns false for cancel records
// (only requests finalize).
func (r *Record) IsFinalizable(now time.Time) bool {
	if r == nil || r.Step != StepRequest {
		return false
	}
	return !now.Before(r.FinalizationAt())
}
