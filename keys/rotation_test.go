package keys_test

import (
	"context"
	"crypto/rand"
	"testing"
	"time"

	"semp.dev/semp-go/keys"
	"semp.dev/semp-go/keys/memstore"
)

// fakeGen is a KeyGenerator that produces 32-byte random keypairs.
type fakeGen struct{}

func (fakeGen) GenerateKeyPair() ([]byte, []byte, error) {
	pub := make([]byte, 32)
	priv := make([]byte, 32)
	if _, err := rand.Read(pub); err != nil {
		return nil, nil, err
	}
	if _, err := rand.Read(priv); err != nil {
		return nil, nil, err
	}
	return pub, priv, nil
}

// newDriver is a convenience that wires a RotationDriver with a
// memstore and a controllable clock.
func newDriver(t *testing.T, clock *time.Time) (*keys.RotationDriver, *memstore.Store) {
	t.Helper()
	store := memstore.New()
	return &keys.RotationDriver{
		Store:        store,
		PrivateStore: store,
		Generator:    fakeGen{},
		Now:          func() time.Time { return *clock },
	}, store
}

// TestRotationDriverInitialKeygenCreatesKey confirms the degenerate
// case: no key exists yet, so the driver creates the first one.
func TestRotationDriverInitialKeygenCreatesKey(t *testing.T) {
	now := time.Date(2026, 4, 12, 12, 0, 0, 0, time.UTC)
	driver, store := newDriver(t, &now)
	policy := keys.RotationPolicy{
		KeyType:     keys.TypeEncryption,
		Address:     "alice@example.com",
		Algorithm:   "x25519-chacha20-poly1305",
		RotateEvery: 30 * 24 * time.Hour,
	}
	results := driver.Run(context.Background(), []keys.RotationPolicy{policy})
	if len(results) != 1 {
		t.Fatalf("results = %d, want 1", len(results))
	}
	r := results[0]
	if r.Error != nil {
		t.Fatalf("Error: %v", r.Error)
	}
	if !r.Rotated {
		t.Error("Rotated = false, want true (initial keygen)")
	}
	if r.NewKeyID == "" {
		t.Error("NewKeyID is empty")
	}
	// Store should now have the key.
	recs, err := store.LookupUserKeys(context.Background(), "alice@example.com", keys.TypeEncryption)
	if err != nil {
		t.Fatalf("LookupUserKeys: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("expected 1 key record, got %d", len(recs))
	}
	if recs[0].KeyID != r.NewKeyID {
		t.Errorf("stored key %s != result key %s", recs[0].KeyID, r.NewKeyID)
	}
}

// TestRotationDriverFreshKeySkips confirms that a key younger than
// RotateEvery does not trigger rotation.
func TestRotationDriverFreshKeySkips(t *testing.T) {
	now := time.Date(2026, 4, 12, 12, 0, 0, 0, time.UTC)
	driver, _ := newDriver(t, &now)
	policy := keys.RotationPolicy{
		KeyType:     keys.TypeEncryption,
		Address:     "alice@example.com",
		Algorithm:   "x25519-chacha20-poly1305",
		RotateEvery: 30 * 24 * time.Hour,
	}
	// Create the initial key.
	driver.Run(context.Background(), []keys.RotationPolicy{policy})
	// Advance 10 days — still fresh.
	now = now.Add(10 * 24 * time.Hour)
	results := driver.Run(context.Background(), []keys.RotationPolicy{policy})
	if results[0].Rotated {
		t.Error("key should not have rotated (only 10 days old)")
	}
}

// TestRotationDriverRotatesExpiredKey confirms that a key older than
// RotateEvery triggers rotation: the old key gets a Revocation with
// ReasonSuperseded and ReplacementKeyID pointing to the new key.
func TestRotationDriverRotatesExpiredKey(t *testing.T) {
	now := time.Date(2026, 4, 12, 12, 0, 0, 0, time.UTC)
	driver, store := newDriver(t, &now)
	policy := keys.RotationPolicy{
		KeyType:     keys.TypeEncryption,
		Address:     "alice@example.com",
		Algorithm:   "x25519-chacha20-poly1305",
		RotateEvery: 30 * 24 * time.Hour,
		RetireAfter: 60 * 24 * time.Hour,
	}
	// Create initial key.
	r1 := driver.Run(context.Background(), []keys.RotationPolicy{policy})
	oldKeyID := r1[0].NewKeyID

	// Advance 31 days — past rotation deadline.
	now = now.Add(31 * 24 * time.Hour)
	r2 := driver.Run(context.Background(), []keys.RotationPolicy{policy})
	if !r2[0].Rotated {
		t.Fatal("key should have rotated after 31 days")
	}
	if r2[0].OldKeyID != oldKeyID {
		t.Errorf("OldKeyID = %s, want %s", r2[0].OldKeyID, oldKeyID)
	}
	newKeyID := r2[0].NewKeyID
	if newKeyID == "" || newKeyID == oldKeyID {
		t.Errorf("NewKeyID = %q, want a different key", newKeyID)
	}

	// The old key should have a Revocation with ReasonSuperseded.
	recs, err := store.LookupUserKeys(context.Background(), "alice@example.com", keys.TypeEncryption)
	if err != nil {
		t.Fatalf("LookupUserKeys: %v", err)
	}
	var oldRec *keys.Record
	for _, r := range recs {
		if r.KeyID == oldKeyID {
			oldRec = r
			break
		}
	}
	if oldRec == nil {
		t.Fatal("old key record not found in store")
	}
	if oldRec.Revocation == nil {
		t.Fatal("old key should have a Revocation")
	}
	if oldRec.Revocation.Reason != keys.ReasonSuperseded {
		t.Errorf("Revocation.Reason = %s, want superseded", oldRec.Revocation.Reason)
	}
	if oldRec.Revocation.ReplacementKeyID != newKeyID {
		t.Errorf("ReplacementKeyID = %s, want %s", oldRec.Revocation.ReplacementKeyID, newKeyID)
	}
}

// TestRotationDriverRetiresAfterGracePeriod confirms that after
// RotateEvery + RetireAfter, the old key's Expires field is set.
func TestRotationDriverRetiresAfterGracePeriod(t *testing.T) {
	now := time.Date(2026, 4, 12, 12, 0, 0, 0, time.UTC)
	driver, store := newDriver(t, &now)
	policy := keys.RotationPolicy{
		KeyType:     keys.TypeEncryption,
		Address:     "alice@example.com",
		Algorithm:   "x25519-chacha20-poly1305",
		RotateEvery: 30 * 24 * time.Hour,
		RetireAfter: 60 * 24 * time.Hour,
	}
	// Create + rotate.
	driver.Run(context.Background(), []keys.RotationPolicy{policy})
	now = now.Add(31 * 24 * time.Hour)
	r2 := driver.Run(context.Background(), []keys.RotationPolicy{policy})
	oldKeyID := r2[0].OldKeyID
	if !r2[0].Rotated {
		t.Fatal("expected rotation")
	}
	// At this point the old key is revoked but NOT retired.
	if r2[0].Retired {
		t.Error("should not be retired yet (grace period not elapsed)")
	}

	// Advance 61 more days (total 92 from creation: 31 rotation +
	// 61 retirement grace). The retirement grace is 60 days after
	// REVOCATION, so we need 60 days past the revocation timestamp.
	now = now.Add(61 * 24 * time.Hour)
	r3 := driver.Run(context.Background(), []keys.RotationPolicy{policy})
	if !r3[0].Retired {
		t.Error("old key should be retired after 60-day grace period")
	}

	// The old key record should now have a non-zero Expires.
	recs, _ := store.LookupUserKeys(context.Background(), "alice@example.com", keys.TypeEncryption)
	for _, r := range recs {
		if r.KeyID == oldKeyID && r.Revocation != nil {
			if r.Expires.IsZero() {
				t.Error("retired key Expires should be non-zero")
			}
			break
		}
	}
}

// TestRotationDriverZeroRetireAfterNeverRetires confirms that a
// RetireAfter of zero means "keep old keys forever."
func TestRotationDriverZeroRetireAfterNeverRetires(t *testing.T) {
	now := time.Date(2026, 4, 12, 12, 0, 0, 0, time.UTC)
	driver, store := newDriver(t, &now)
	policy := keys.RotationPolicy{
		KeyType:     keys.TypeEncryption,
		Address:     "alice@example.com",
		Algorithm:   "x25519-chacha20-poly1305",
		RotateEvery: 30 * 24 * time.Hour,
		RetireAfter: 0, // never retire
	}
	driver.Run(context.Background(), []keys.RotationPolicy{policy})
	now = now.Add(31 * 24 * time.Hour)
	driver.Run(context.Background(), []keys.RotationPolicy{policy})
	// Even 1000 days later, the old key should not have Expires set.
	now = now.Add(1000 * 24 * time.Hour)
	results := driver.Run(context.Background(), []keys.RotationPolicy{policy})
	if results[0].Retired {
		t.Error("zero RetireAfter should never retire")
	}
	recs, _ := store.LookupUserKeys(context.Background(), "alice@example.com", keys.TypeEncryption)
	for _, r := range recs {
		if r.Revocation != nil && !r.Expires.IsZero() {
			t.Errorf("revoked key %s should never have Expires set with RetireAfter=0", r.KeyID)
		}
	}
}

// TestRotationDriverMultiplePolicies runs two policies in one call
// and confirms each is evaluated independently.
func TestRotationDriverMultiplePolicies(t *testing.T) {
	now := time.Date(2026, 4, 12, 12, 0, 0, 0, time.UTC)
	driver, _ := newDriver(t, &now)
	policies := []keys.RotationPolicy{
		{KeyType: keys.TypeEncryption, Address: "alice@example.com", Algorithm: "x25519", RotateEvery: 30 * 24 * time.Hour},
		{KeyType: keys.TypeEncryption, Address: "bob@example.com", Algorithm: "x25519", RotateEvery: 30 * 24 * time.Hour},
	}
	results := driver.Run(context.Background(), policies)
	if len(results) != 2 {
		t.Fatalf("results = %d, want 2", len(results))
	}
	for i, r := range results {
		if r.Error != nil {
			t.Errorf("policy[%d] error: %v", i, r.Error)
		}
		if !r.Rotated {
			t.Errorf("policy[%d] should have created initial key", i)
		}
	}
	if results[0].NewKeyID == results[1].NewKeyID {
		t.Error("different users should have different keys")
	}
}

// TestRotationDriverDueForRotation confirms the diagnostic helper.
func TestRotationDriverDueForRotation(t *testing.T) {
	now := time.Date(2026, 4, 12, 12, 0, 0, 0, time.UTC)
	driver, _ := newDriver(t, &now)
	policy := keys.RotationPolicy{
		KeyType:     keys.TypeEncryption,
		Address:     "alice@example.com",
		Algorithm:   "x25519",
		RotateEvery: 30 * 24 * time.Hour,
	}
	// No key exists → due.
	due, err := driver.DueForRotation(context.Background(), policy)
	if err != nil {
		t.Fatalf("DueForRotation: %v", err)
	}
	if !due {
		t.Error("no key exists, should be due")
	}
	// Create key.
	driver.Run(context.Background(), []keys.RotationPolicy{policy})
	// Still fresh → not due.
	due, _ = driver.DueForRotation(context.Background(), policy)
	if due {
		t.Error("fresh key should not be due")
	}
	// Advance past deadline → due.
	now = now.Add(31 * 24 * time.Hour)
	due, _ = driver.DueForRotation(context.Background(), policy)
	if !due {
		t.Error("expired key should be due")
	}
}

// TestRotationDriverNilDriverAndStore confirms nil safety.
func TestRotationDriverNilDriverAndStore(t *testing.T) {
	var d *keys.RotationDriver
	if results := d.Run(context.Background(), nil); results != nil {
		t.Errorf("nil driver Run = %v, want nil", results)
	}
	if _, err := d.DueForRotation(context.Background(), keys.RotationPolicy{}); err == nil {
		t.Error("nil driver DueForRotation should error")
	}
}

// TestRotationDriverPrivateKeyStored confirms the private key is
// written to PrivateStore after generation.
func TestRotationDriverPrivateKeyStored(t *testing.T) {
	now := time.Date(2026, 4, 12, 12, 0, 0, 0, time.UTC)
	driver, store := newDriver(t, &now)
	policy := keys.RotationPolicy{
		KeyType:   keys.TypeEncryption,
		Address:   "alice@example.com",
		Algorithm: "x25519",
		RotateEvery: 30 * 24 * time.Hour,
	}
	results := driver.Run(context.Background(), []keys.RotationPolicy{policy})
	fp := results[0].NewKeyID
	priv, err := store.LoadPrivateKey(context.Background(), fp)
	if err != nil {
		t.Fatalf("LoadPrivateKey: %v", err)
	}
	if len(priv) == 0 {
		t.Error("private key not stored")
	}
}
