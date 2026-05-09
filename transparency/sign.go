package transparency

import (
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"semp.dev/semp-go/clockskew"
	"semp.dev/semp-go/crypto"
	"semp.dev/semp-go/canonical"
)

// SignatureAlgorithmEd25519 is the only signature algorithm
// defined for transparency STH signatures.
const SignatureAlgorithmEd25519 = "ed25519"

// canonicalSTHBytes returns the canonical JSON form of s with
// signature.value elided to "" per TRANSPARENCY.md §2.3.
func canonicalSTHBytes(s *SignedTreeHead) ([]byte, error) {
	if s == nil {
		return nil, errors.New("transparency: nil STH")
	}
	return canonical.MarshalWithElision(s, func(v any) error {
		m, ok := v.(map[string]any)
		if !ok {
			return fmt.Errorf("transparency: expected top-level object, got %T", v)
		}
		sig, ok := m["signature"].(map[string]any)
		if !ok {
			return errors.New("transparency: STH missing signature object")
		}
		sig["value"] = ""
		return nil
	})
}

// SignSTH populates s.Signature with the domain signing key's
// signature over the canonical STH bytes per TRANSPARENCY.md §2.3.
// domainPriv is the domain's signing private key; domainKeyID is
// its fingerprint as published per KEY.md §2.
func SignSTH(signer crypto.Signer, domainPriv []byte, domainKeyID string, s *SignedTreeHead) error {
	if signer == nil {
		return errors.New("transparency: nil signer")
	}
	if s == nil {
		return errors.New("transparency: nil STH")
	}
	if len(domainPriv) == 0 {
		return errors.New("transparency: empty domain private key")
	}
	if domainKeyID == "" {
		return errors.New("transparency: empty domain key fingerprint")
	}
	if err := s.Validate(); err != nil {
		return err
	}
	s.Signature.Algorithm = SignatureAlgorithmEd25519
	s.Signature.KeyID = domainKeyID
	s.Signature.Value = ""
	bytes, err := canonicalSTHBytes(s)
	if err != nil {
		return err
	}
	prefixed := crypto.PrefixedMessage(crypto.SigCtxTransparencySTH, bytes)
	sig, err := signer.Sign(domainPriv, prefixed)
	if err != nil {
		return fmt.Errorf("transparency: sign STH: %w", err)
	}
	s.Signature.Value = base64.StdEncoding.EncodeToString(sig)
	return nil
}

// VerifySTH checks s.Signature against domainPub. Does NOT enforce
// staleness; pair with CheckSTHFresh for the §2.3 1-hour bound.
func VerifySTH(signer crypto.Signer, domainPub []byte, s *SignedTreeHead) error {
	if signer == nil {
		return errors.New("transparency: nil signer")
	}
	if s == nil {
		return errors.New("transparency: nil STH")
	}
	if len(domainPub) == 0 {
		return errors.New("transparency: empty domain public key")
	}
	if s.Signature.Value == "" {
		return errors.New("transparency: STH is unsigned")
	}
	if err := s.Validate(); err != nil {
		return err
	}
	sig, err := base64.StdEncoding.DecodeString(s.Signature.Value)
	if err != nil {
		return fmt.Errorf("transparency: STH signature base64: %w", err)
	}
	bytes, err := canonicalSTHBytes(s)
	if err != nil {
		return err
	}
	prefixed := crypto.PrefixedMessage(crypto.SigCtxTransparencySTH, bytes)
	if err := signer.Verify(domainPub, prefixed, sig); err != nil {
		return fmt.Errorf("transparency: verify STH: %w", err)
	}
	return nil
}

// CheckSTHFresh enforces TRANSPARENCY.md §2.3: an STH with a
// timestamp older than 1 hour is unacceptable. Uses
// clockskew.CheckExpiry against (s.Timestamp + MaxSTHFreshness).
func CheckSTHFresh(s *SignedTreeHead, now time.Time) error {
	if s == nil {
		return errors.New("transparency: nil STH")
	}
	if s.Timestamp.IsZero() {
		return errors.New("transparency: STH missing timestamp")
	}
	freshUntil := s.Timestamp.Add(MaxSTHFreshness)
	return clockskew.CheckExpiry(freshUntil, now, clockskew.Default())
}

// Validate reports whether s is structurally well-formed per
// TRANSPARENCY.md §2.3.
func (s *SignedTreeHead) Validate() error {
	if s == nil {
		return errors.New("transparency: nil STH")
	}
	if s.LogSize < 0 {
		return fmt.Errorf("transparency: STH log_size %d MUST be >= 0", s.LogSize)
	}
	if s.RootHash == "" {
		return errors.New("transparency: STH missing root_hash")
	}
	if _, err := decodeHash(s.RootHash, "root_hash"); err != nil {
		return err
	}
	if s.Timestamp.IsZero() {
		return errors.New("transparency: STH missing timestamp")
	}
	return nil
}

// Validate reports whether e is structurally well-formed per
// TRANSPARENCY.md §2.2.
func (e *LogEntry) Validate() error {
	if e == nil {
		return errors.New("transparency: nil log entry")
	}
	switch e.Event {
	case EventPublish, EventRotate, EventRevoke:
		// ok
	case "":
		return errors.New("transparency: log entry missing event")
	default:
		return fmt.Errorf("transparency: log entry event %q is not a valid event", e.Event)
	}
	if e.UserID == "" {
		return errors.New("transparency: log entry missing user_id")
	}
	if e.KeyID == "" {
		return errors.New("transparency: log entry missing key_id")
	}
	switch e.KeyType {
	case KeyTypeIdentity, KeyTypeEncryption:
		// ok
	default:
		return fmt.Errorf("transparency: log entry key_type %q is not a valid type", e.KeyType)
	}
	if e.Algorithm == "" {
		return errors.New("transparency: log entry missing algorithm")
	}
	if e.PublicKey == "" {
		return errors.New("transparency: log entry missing public_key")
	}
	if e.Created.IsZero() {
		return errors.New("transparency: log entry missing created")
	}
	if e.LogTimestamp.IsZero() {
		return errors.New("transparency: log entry missing log_timestamp")
	}
	switch e.Event {
	case EventRotate:
		if e.Supersedes == nil || *e.Supersedes == "" {
			return errors.New("transparency: rotate event MUST set supersedes")
		}
	case EventPublish:
		if e.Supersedes != nil && *e.Supersedes != "" {
			return errors.New("transparency: publish event MUST NOT set supersedes")
		}
	case EventRevoke:
		if e.RevokedAt == nil || e.RevokedAt.IsZero() {
			return errors.New("transparency: revoke event MUST set revoked_at")
		}
		if e.RevokedReason == nil || *e.RevokedReason == "" {
			return errors.New("transparency: revoke event MUST set revoked_reason")
		}
	}
	return nil
}
