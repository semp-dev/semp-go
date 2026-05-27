package keys

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	semp "github.com/semp-dev/semp-go"
	"github.com/semp-dev/semp-go/crypto"
)

// ScopeResourceKind names which Scope.{Blocklist,Keys,Devices}
// resource a CheckResource* call addresses. Matches the §10.3.3.2
// resource-shape table.
type ScopeResourceKind string

// ScopeResourceKind values.
const (
	ScopeResourceBlocklist ScopeResourceKind = "blocklist"
	ScopeResourceKeys      ScopeResourceKind = "keys"
	ScopeResourceDevices   ScopeResourceKind = "devices"
)

// CheckResourceRead reports whether scope grants read access to
// kind per KEY.md §10.3.4. Returns nil on permitted, *semp.Error
// with Code == ReasonScopeExceeded on denied. The reason wraps a
// human-readable message identifying the resource so operator logs
// surface "blocklist read denied" rather than just "scope_exceeded".
//
// Full-access devices (no certificate) are not subject to scope
// gating; callers MUST check the device role before calling and
// SHOULD short-circuit for full-access devices.
func CheckResourceRead(scope Scope, kind ScopeResourceKind) error {
	r, err := pickResource(scope, kind)
	if err != nil {
		return err
	}
	if !r.Read {
		return semp.Errorf(semp.ReasonScopeExceeded,
			"keys: scope.%s.read is false; read denied", kind)
	}
	return nil
}

// CheckResourceWrite mirrors CheckResourceRead for write
// permissions per KEY.md §10.3.4. Returns nil on permitted,
// *semp.Error with Code == ReasonScopeExceeded on denied.
func CheckResourceWrite(scope Scope, kind ScopeResourceKind) error {
	r, err := pickResource(scope, kind)
	if err != nil {
		return err
	}
	if !r.Write {
		return semp.Errorf(semp.ReasonScopeExceeded,
			"keys: scope.%s.write is false; write denied", kind)
	}
	return nil
}

// pickResource returns the ScopeResource for kind, or an error for
// an unknown kind.
func pickResource(scope Scope, kind ScopeResourceKind) (ScopeResource, error) {
	switch kind {
	case ScopeResourceBlocklist:
		return scope.Blocklist, nil
	case ScopeResourceKeys:
		return scope.Keys, nil
	case ScopeResourceDevices:
		return scope.Devices, nil
	default:
		return ScopeResource{}, fmt.Errorf("keys: unknown scope resource kind %q", kind)
	}
}

// RateLimitCounter is the rolling-window counter store the home
// server consults per KEY.md §10.3.3.3. Implementations track
// per-(device_id, scope_field) counters and answer:
//
//   - Allow(...): does this operation fit within every tier of the
//     supplied tier set? On allow=true the implementation MUST
//     have recorded the operation toward the relevant counters per
//     §10.3.4 "evaluates the scope field's rate_limits array. If
//     any tier would be exceeded, the server MUST reject with
//     reason_code rate_limited and MUST NOT record the operation
//     against the counters". On allow=false the operation is NOT
//     counted.
//
// Tiers with `amount_allowed: 0` are absolute prohibitions
// (RECOMMENDED only for short-lived suspensions; equivalent to
// mode:"none" expressed as a rate). All tiers in the array are
// evaluated independently - an operation must fit within EVERY
// tier to be permitted.
type RateLimitCounter interface {
	Allow(ctx context.Context, key string, tiers []RateLimitTier, now time.Time) (bool, error)
}

// CheckRateLimit evaluates tiers against the counter and returns
// nil on allow, *semp.Error with Code == ReasonRateLimited on
// reject per KEY.md §10.3.4.
//
// key is the operator's per-(device, scope-field) bucket
// identifier; in practice the home server constructs it from
// (device_id, scope-field-name) so each scope field has its own
// counter, isolated from siblings. An empty tier set is
// unconditionally permitted (no rate cap declared).
func CheckRateLimit(ctx context.Context, counter RateLimitCounter, key string, tiers []RateLimitTier, now time.Time) error {
	if len(tiers) == 0 {
		return nil
	}
	if counter == nil {
		return errors.New("keys: nil rate-limit counter")
	}
	allowed, err := counter.Allow(ctx, key, tiers, now)
	if err != nil {
		return fmt.Errorf("keys: rate-limit counter: %w", err)
	}
	if !allowed {
		return semp.Errorf(semp.ReasonRateLimited,
			"keys: rate limit exceeded for %q", key)
	}
	return nil
}

// inMemoryRateLimitCounter is the reference RateLimitCounter
// implementation. It tracks per-key timestamp lists and trims
// outside the longest tier's window on every Allow call. Adequate
// for tests, demos, and modest deployments; production-scale
// servers plug in a Redis/SQL/durable backend.
type inMemoryRateLimitCounter struct {
	mu sync.Mutex
	// per-key sorted list of operation timestamps.
	hits map[string][]time.Time
}

// NewInMemoryRateLimitCounter returns a fresh in-memory counter.
func NewInMemoryRateLimitCounter() RateLimitCounter {
	return &inMemoryRateLimitCounter{hits: make(map[string][]time.Time)}
}

// Allow evaluates every tier and records the hit when permitted.
func (c *inMemoryRateLimitCounter) Allow(_ context.Context, key string, tiers []RateLimitTier, now time.Time) (bool, error) {
	if len(tiers) == 0 {
		return true, nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	// Trim to the longest tier's window so we keep enough history.
	maxWindow := time.Duration(0)
	for _, t := range tiers {
		w := time.Duration(t.PeriodSeconds) * time.Second
		if w > maxWindow {
			maxWindow = w
		}
	}
	cutoff := now.Add(-maxWindow)
	hits := c.hits[key]
	idx := sort.Search(len(hits), func(i int) bool { return !hits[i].Before(cutoff) })
	if idx > 0 {
		hits = hits[idx:]
	}

	// For each tier, count hits inside its window. Tier rejected
	// when count + 1 (the proposed operation) > amount_allowed.
	for _, t := range tiers {
		if t.AmountAllowed == 0 {
			c.hits[key] = hits
			return false, nil
		}
		windowStart := now.Add(-time.Duration(t.PeriodSeconds) * time.Second)
		// Count hits at or after windowStart.
		count := 0
		for i := len(hits) - 1; i >= 0; i-- {
			if hits[i].Before(windowStart) {
				break
			}
			count++
		}
		if count+1 > t.AmountAllowed {
			c.hits[key] = hits
			return false, nil
		}
	}

	// Record the hit; binary-insert to keep the slice sorted.
	hits = append(hits, now)
	for i := len(hits) - 1; i > 0; i-- {
		if hits[i].Before(hits[i-1]) {
			hits[i], hits[i-1] = hits[i-1], hits[i]
			continue
		}
		break
	}
	c.hits[key] = hits
	return true, nil
}

// IssuerInfo is the lookup hook ValidateIssuance calls to learn
// about the device that issued a SEMP_DEVICE_CERTIFICATE. The
// home server holds the full device directory; this interface
// decouples issuance validation from any particular directory
// implementation.
type IssuerInfo interface {
	// IssuerLookup returns (publicKey, role, revoked, found).
	// publicKey is the issuer's device key bytes for signature
	// verification; role is "full_access" or "delegated"; revoked
	// is true if the issuer has been revoked. found is false if
	// the issuer is unknown to the directory.
	IssuerLookup(ctx context.Context, deviceID string) (publicKey []byte, role DeviceRole, revoked bool, found bool, err error)
}

// IssuerInfoFunc lets a plain function satisfy IssuerInfo.
type IssuerInfoFunc func(ctx context.Context, deviceID string) ([]byte, DeviceRole, bool, bool, error)

// IssuerLookup implements IssuerInfo.
func (f IssuerInfoFunc) IssuerLookup(ctx context.Context, deviceID string) ([]byte, DeviceRole, bool, bool, error) {
	return f(ctx, deviceID)
}

// ValidateIssuance implements KEY.md §10.3.5 step 6: the home
// server's certificate-issuance verification. Runs the spec's
// six per-step checks:
//
//  1. Signature verifies against the issuer's registered device
//     key (the body bytes are reconstructed using
//     SignDeviceCertificate's canonical-bytes routine).
//  2. Issuer is a full-access device of the account
//     (delegated devices MUST NOT issue certificates per §10.3.9).
//  3. Issuer is not revoked.
//  4. All required fields are present (covered by
//     DeviceCertificate.Validate).
//  5. allow / deny lists are within the 10,000-entry cap (covered
//     by DeviceCertificate.Validate).
//  6. expires_at is within the §10.3.8 lifetime bounds (covered by
//     DeviceCertificate.Validate).
//
// signer is the cryptographic signer for the issuer's algorithm
// (typically suite.Signer()).
//
// Returns nil on successful issuance verification, or *semp.Error
// with the appropriate ReasonCode on failure: ReasonAuthFailed for
// signature mismatch, ReasonScopeExceeded for issuer-role failures,
// ReasonScopeInvalid for structural issues from Validate, and
// ReasonCertificateExpired when expires_at has already passed.
func ValidateIssuance(ctx context.Context, signer crypto.Signer, info IssuerInfo, cert *DeviceCertificate, now time.Time) error {
	if signer == nil {
		return errors.New("keys: nil signer")
	}
	if info == nil {
		return errors.New("keys: nil issuer info")
	}
	if cert == nil {
		return errors.New("keys: nil certificate")
	}
	// Run Validate first - it covers steps 4, 5, 6 (structural,
	// allow/deny cap, lifetime cap).
	if err := cert.Validate(); err != nil {
		return semp.WrapErr(semp.ReasonScopeInvalid, err, "keys: certificate failed validation")
	}
	if !now.Before(cert.ExpiresAt) {
		return semp.Errorf(semp.ReasonCertificateExpired,
			"keys: certificate expires_at %s is at or before now %s",
			cert.ExpiresAt.Format(time.RFC3339), now.Format(time.RFC3339))
	}
	// Step 2 + 3: issuer is full-access and not revoked.
	pub, role, revoked, found, err := info.IssuerLookup(ctx, cert.IssuedBy)
	if err != nil {
		return fmt.Errorf("keys: issuer lookup: %w", err)
	}
	if !found {
		return semp.Errorf(semp.ReasonAuthFailed,
			"keys: issuer %q not found in directory", cert.IssuedBy)
	}
	if role != DeviceRoleFullAccess {
		return semp.Errorf(semp.ReasonScopeExceeded,
			"keys: issuer %q has role %q; only full-access devices may issue certificates per §10.3.9",
			cert.IssuedBy, role)
	}
	if revoked {
		return semp.Errorf(semp.ReasonAuthFailed,
			"keys: issuer %q is revoked", cert.IssuedBy)
	}
	// Step 1: signature.
	if err := VerifyDeviceCertificate(signer, cert, pub); err != nil {
		return semp.WrapErr(semp.ReasonAuthFailed, err, "keys: certificate signature does not verify")
	}
	return nil
}
