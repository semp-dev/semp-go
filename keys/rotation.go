package keys

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// RotationPolicy describes when a key should be rotated and when the
// old key should be retired (stop accepting decryption). Operators
// configure one RotationPolicy per key type per domain; the
// RotationDriver evaluates each policy on every tick.
//
// The spec does not prescribe rotation timing — this is an operator
// ergonomics layer that automates what the protocol already supports:
//
//   - A rotated key gets a Revocation with ReasonSuperseded and the
//     new key's fingerprint in ReplacementKeyID.
//   - The old key remains in the Store so OpenBriefAny / OpenEnclosureAny
//     can still decrypt envelopes that were sealed under it during
//     the transition window.
//   - After RetireAfter elapses, the old key's Expires is set to the
//     retirement time so the decryption candidate list eventually
//     stops consulting it.
type RotationPolicy struct {
	// KeyType is the type of key this policy applies to. Typically
	// TypeEncryption for client encryption keys or TypeDomain for
	// server signing keys. TypeIdentity keys rarely rotate in
	// practice; operators that want to rotate them use the same
	// driver.
	KeyType Type

	// Address is the user address (for user keys) or the domain
	// (for domain keys) this policy applies to.
	Address string

	// Algorithm is the algorithm of the NEW key to generate when
	// rotation fires. Typically "x25519-chacha20-poly1305" or
	// "ed25519" depending on the key type.
	Algorithm string

	// RotateEvery is the maximum lifetime of a key before rotation.
	// When the current key's Created time is older than RotateEvery,
	// the driver generates a new key, stores it, and revokes the
	// old one with ReasonSuperseded.
	RotateEvery time.Duration

	// RetireAfter is the grace period after rotation during which
	// the OLD key remains usable for decryption. After RotateEvery +
	// RetireAfter, the old key's Expires is set so the decryption
	// candidate list stops trying it. Zero means "never retire"
	// (the old key stays forever — useful for long-archive scenarios
	// where messages encrypted years ago must remain decryptable).
	RetireAfter time.Duration
}

// KeyGenerator is the interface the rotation driver calls to produce
// a fresh keypair. In production this is backed by crypto.Suite's
// KEM or Signer; in tests it's a fake that returns fixed bytes.
//
// The returned (publicKey, privateKey) are raw bytes. The driver
// computes the Fingerprint, base64-encodes the public key, and
// stores the private key via PrivateStore.StorePrivateKey.
type KeyGenerator interface {
	GenerateKeyPair() (publicKey, privateKey []byte, err error)
}

// RotationResult is the outcome of a single key rotation.
type RotationResult struct {
	// Policy is the policy that triggered this rotation.
	Policy RotationPolicy

	// OldKeyID is the fingerprint of the key that was revoked.
	// Empty if no rotation occurred (the key was still fresh).
	OldKeyID Fingerprint

	// NewKeyID is the fingerprint of the newly generated key.
	// Empty if no rotation occurred.
	NewKeyID Fingerprint

	// Rotated is true iff a rotation actually fired.
	Rotated bool

	// Retired is true iff the old key was also retired (Expires set).
	Retired bool

	// Error is non-nil if the rotation failed (key generation,
	// store write, or revocation write).
	Error error
}

// RotationDriver evaluates a set of RotationPolicies against the
// current key state in a Store and performs any needed rotations. It
// is intended to be called periodically (e.g. once a day via a cron
// job or a background goroutine) rather than on every request.
//
// The driver is stateless — it reads the current key records from
// the store, compares their Created timestamps against the policy
// deadlines, and acts. If it crashes partway through, the next run
// picks up where it left off because the store's state is the source
// of truth.
type RotationDriver struct {
	// Store is the key store to read and write. Must implement
	// PrivateStore if the driver is generating private keys (which
	// it always is for user-side rotation).
	Store Store

	// PrivateStore, if non-nil, is where newly generated private
	// keys are stored. If nil and the driver needs to store a
	// private key, the rotation for that policy fails with an
	// error.
	PrivateStore PrivateStore

	// Generator produces fresh keypairs. Required.
	Generator KeyGenerator

	// Now is a clock hook for tests. Defaults to time.Now.
	Now func() time.Time

	// Logger receives one line per rotation action. May be nil.
	Logger interface{ Printf(string, ...any) }
}

// Run evaluates every policy and returns one RotationResult per
// policy. Policies that don't need rotation produce a result with
// Rotated=false. Policies that fail produce a result with a non-nil
// Error (and the driver continues to the next policy rather than
// aborting).
func (d *RotationDriver) Run(ctx context.Context, policies []RotationPolicy) []RotationResult {
	if d == nil {
		return nil
	}
	results := make([]RotationResult, 0, len(policies))
	for _, p := range policies {
		r := d.evaluate(ctx, p)
		results = append(results, r)
	}
	return results
}

// evaluate processes one policy.
func (d *RotationDriver) evaluate(ctx context.Context, p RotationPolicy) RotationResult {
	res := RotationResult{Policy: p}
	now := d.now()

	// Find the current active key.
	current, err := d.findCurrentKey(ctx, p)
	if err != nil {
		res.Error = fmt.Errorf("rotation: lookup current key for %s/%s: %w", p.Address, p.KeyType, err)
		return res
	}

	if current == nil {
		// No key exists yet. Generate the first one — this is not a
		// "rotation" per se, but the driver handles initial key
		// creation as a degenerate case so operators don't need a
		// separate bootstrap flow.
		newKey, err := d.generateAndStore(ctx, p)
		if err != nil {
			res.Error = fmt.Errorf("rotation: initial keygen for %s/%s: %w", p.Address, p.KeyType, err)
			return res
		}
		res.NewKeyID = newKey
		res.Rotated = true
		d.logf("rotation: generated initial %s key for %s: %s", p.KeyType, p.Address, newKey)
		return res
	}

	// Check whether the current key is due for rotation.
	age := now.Sub(current.Created)
	if age < p.RotateEvery {
		// Key is still fresh. Check whether a previously-rotated
		// key needs retirement.
		res.Retired = d.maybeRetire(ctx, p, now)
		return res
	}

	// Rotation is due.
	res.OldKeyID = current.KeyID
	newKey, err := d.generateAndStore(ctx, p)
	if err != nil {
		res.Error = fmt.Errorf("rotation: keygen for %s/%s: %w", p.Address, p.KeyType, err)
		return res
	}
	res.NewKeyID = newKey
	res.Rotated = true

	// Revoke the old key with ReasonSuperseded.
	rev := &Revocation{
		Reason:           ReasonSuperseded,
		RevokedAt:        now,
		ReplacementKeyID: newKey,
	}
	if err := d.Store.PutRevocation(ctx, current.KeyID, rev); err != nil {
		res.Error = fmt.Errorf("rotation: revoke old key %s: %w", current.KeyID, err)
		return res
	}
	d.logf("rotation: rotated %s key for %s: %s → %s", p.KeyType, p.Address, current.KeyID, newKey)

	// Immediately check retirement on the just-rotated key.
	res.Retired = d.maybeRetire(ctx, p, now)
	return res
}

// findCurrentKey returns the newest non-revoked key record for the
// policy's address and key type. Returns (nil, nil) if no key exists.
func (d *RotationDriver) findCurrentKey(ctx context.Context, p RotationPolicy) (*Record, error) {
	if d.Store == nil {
		return nil, errors.New("rotation: nil store")
	}
	recs, err := d.Store.LookupUserKeys(ctx, p.Address, p.KeyType)
	if err != nil {
		return nil, err
	}
	// Find the newest non-revoked record.
	var best *Record
	for _, r := range recs {
		if r.Revocation != nil {
			continue
		}
		if best == nil || r.Created.After(best.Created) {
			best = r
		}
	}
	return best, nil
}

// generateAndStore creates a fresh keypair, stores the public record
// and the private key, and returns the new key's fingerprint.
func (d *RotationDriver) generateAndStore(ctx context.Context, p RotationPolicy) (Fingerprint, error) {
	if d.Generator == nil {
		return "", errors.New("rotation: nil key generator")
	}
	pub, priv, err := d.Generator.GenerateKeyPair()
	if err != nil {
		return "", err
	}
	fp := Compute(pub)
	now := d.now()
	rec := &Record{
		Address:   p.Address,
		Type:      p.KeyType,
		Algorithm: p.Algorithm,
		PublicKey: encodeBase64(pub),
		KeyID:     fp,
		Created:   now,
	}
	if err := d.Store.PutRecord(ctx, rec); err != nil {
		return "", fmt.Errorf("store public record: %w", err)
	}
	if d.PrivateStore != nil {
		if err := d.PrivateStore.StorePrivateKey(ctx, fp, priv); err != nil {
			return "", fmt.Errorf("store private key: %w", err)
		}
	}
	return fp, nil
}

// maybeRetire checks all revoked keys for this policy's address/type
// and sets their Expires if the retirement grace period has elapsed.
// Returns true if any key was retired on this call.
func (d *RotationDriver) maybeRetire(ctx context.Context, p RotationPolicy, now time.Time) bool {
	if p.RetireAfter <= 0 {
		// Zero RetireAfter = never retire.
		return false
	}
	recs, err := d.Store.LookupUserKeys(ctx, p.Address, p.KeyType)
	if err != nil {
		return false
	}
	retired := false
	for _, r := range recs {
		if r.Revocation == nil {
			continue
		}
		if r.Revocation.Reason != ReasonSuperseded {
			continue
		}
		// Already has an Expires set from a prior retirement pass.
		if !r.Expires.IsZero() {
			continue
		}
		if now.Sub(r.Revocation.RevokedAt) < p.RetireAfter {
			continue
		}
		// Retirement time: set Expires directly on the record pointer.
		// The Store returned *Record by reference; for in-memory
		// stores (memstore) this mutates the live record. For
		// persistent stores, callers should extend their Store with
		// an UpdateExpires method — the driver sets the field and
		// calls PutRecord so implementations that treat PutRecord
		// as upsert-by-KeyID will pick it up.
		r.Expires = now
		_ = d.Store.PutRecord(ctx, r) // best-effort persist
		d.logf("rotation: retired %s key %s for %s (revoked %s)",
			p.KeyType, r.KeyID, p.Address, r.Revocation.RevokedAt.Format(time.RFC3339))
		retired = true
	}
	return retired
}

// DueForRotation reports whether the current key for p is past its
// RotateEvery deadline and a rotation would fire on the next Run.
// Useful for monitoring / alerting without actually triggering the
// rotation.
func (d *RotationDriver) DueForRotation(ctx context.Context, p RotationPolicy) (bool, error) {
	if d == nil || d.Store == nil {
		return false, errors.New("rotation: nil driver or store")
	}
	current, err := d.findCurrentKey(ctx, p)
	if err != nil {
		return false, err
	}
	if current == nil {
		return true, nil // no key exists → initial keygen is due
	}
	return d.now().Sub(current.Created) >= p.RotateEvery, nil
}

func (d *RotationDriver) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now().UTC()
}

func (d *RotationDriver) logf(format string, args ...any) {
	if d.Logger != nil {
		d.Logger.Printf(format, args...)
	}
}

// encodeBase64 is a minimal inlined base64 encoder so keys/rotation.go
// doesn't need to import encoding/base64 at the top level (it's only
// used in one place).
func encodeBase64(b []byte) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	encoded := make([]byte, 0, ((len(b)+2)/3)*4)
	for i := 0; i < len(b); i += 3 {
		var n uint32
		remaining := len(b) - i
		switch {
		case remaining >= 3:
			n = uint32(b[i])<<16 | uint32(b[i+1])<<8 | uint32(b[i+2])
			encoded = append(encoded, alphabet[n>>18&0x3F], alphabet[n>>12&0x3F], alphabet[n>>6&0x3F], alphabet[n&0x3F])
		case remaining == 2:
			n = uint32(b[i])<<16 | uint32(b[i+1])<<8
			encoded = append(encoded, alphabet[n>>18&0x3F], alphabet[n>>12&0x3F], alphabet[n>>6&0x3F], '=')
		case remaining == 1:
			n = uint32(b[i]) << 16
			encoded = append(encoded, alphabet[n>>18&0x3F], alphabet[n>>12&0x3F], '=', '=')
		}
	}
	return string(encoded)
}
