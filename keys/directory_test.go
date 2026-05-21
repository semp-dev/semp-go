package keys_test

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"semp.dev/semp-go/crypto"
	"semp.dev/semp-go/keys"
)

func newDirectoryState(t *testing.T) (*keys.DirectoryState, []byte, keys.Fingerprint) {
	t.Helper()
	signer := crypto.SuiteBaseline.Signer()
	pub, priv, err := signer.GenerateKeyPair()
	if err != nil {
		t.Fatalf("identity keypair: %v", err)
	}
	fp := keys.Compute(pub)
	state, err := keys.NewDirectoryState(keys.DirectoryStateConfig{
		UserID:        "alice@example.com",
		Suite:         crypto.SuiteBaseline,
		IdentityPriv:  priv,
		IdentityKeyID: fp,
	})
	if err != nil {
		t.Fatalf("NewDirectoryState: %v", err)
	}
	return state, pub, fp
}

func mkEntry(t *testing.T, deviceID string, role keys.DeviceRole, certID *string) keys.DeviceDirectoryEntry {
	t.Helper()
	pub, _, err := crypto.SuiteBaseline.Signer().GenerateKeyPair()
	if err != nil {
		t.Fatalf("device keypair: %v", err)
	}
	return keys.DeviceDirectoryEntry{
		DeviceID:                      deviceID,
		DevicePublicKey:               base64.StdEncoding.EncodeToString(pub),
		DeviceIdentityPubkeyAlgorithm: "ed25519",
		Role:                          role,
		CertificateID:                 certID,
		EnrolledAt:                    time.Now().UTC(),
		DeviceName:                    deviceID,
		DeviceType:                    "test",
	}
}

// TestDirectoryStateAddEmitsRevision confirms each AddDevice bumps
// the revision and produces a freshly signed directory.
func TestDirectoryStateAddEmitsRevision(t *testing.T) {
	state, _, _ := newDirectoryState(t)
	if state.Revision() != 0 {
		t.Errorf("initial revision = %d, want 0", state.Revision())
	}
	if state.Current() != nil {
		t.Error("Current() non-nil before any Add")
	}

	dir1, err := state.AddDevice(context.Background(), mkEntry(t, "d-1", keys.DeviceRoleFullAccess, nil))
	if err != nil {
		t.Fatalf("AddDevice 1: %v", err)
	}
	if dir1.Revision != 1 {
		t.Errorf("after first add: revision = %d, want 1", dir1.Revision)
	}
	if len(dir1.Devices) != 1 {
		t.Errorf("devices count = %d, want 1", len(dir1.Devices))
	}

	dir2, err := state.AddDevice(context.Background(), mkEntry(t, "d-2", keys.DeviceRoleFullAccess, nil))
	if err != nil {
		t.Fatalf("AddDevice 2: %v", err)
	}
	if dir2.Revision != 2 {
		t.Errorf("after second add: revision = %d, want 2", dir2.Revision)
	}
}

// TestDirectoryStateAddRejectsDuplicate confirms a duplicate
// device_id is rejected at the state layer.
func TestDirectoryStateAddRejectsDuplicate(t *testing.T) {
	state, _, _ := newDirectoryState(t)
	entry := mkEntry(t, "d-1", keys.DeviceRoleFullAccess, nil)
	if _, err := state.AddDevice(context.Background(), entry); err != nil {
		t.Fatalf("AddDevice: %v", err)
	}
	if _, err := state.AddDevice(context.Background(), entry); err == nil {
		t.Error("AddDevice accepted duplicate device_id")
	}
}

// TestDirectoryStateRevoke confirms removing a device emits a
// new revision; a revoke for an unknown device is a no-op.
func TestDirectoryStateRevoke(t *testing.T) {
	state, _, _ := newDirectoryState(t)
	if _, err := state.AddDevice(context.Background(), mkEntry(t, "d-1", keys.DeviceRoleFullAccess, nil)); err != nil {
		t.Fatalf("AddDevice: %v", err)
	}
	if _, err := state.AddDevice(context.Background(), mkEntry(t, "d-2", keys.DeviceRoleFullAccess, nil)); err != nil {
		t.Fatalf("AddDevice: %v", err)
	}

	dir, removed, err := state.RevokeDevice(context.Background(), "d-1")
	if err != nil {
		t.Fatalf("RevokeDevice: %v", err)
	}
	if !removed {
		t.Error("RevokeDevice returned removed=false for known device")
	}
	if dir.Revision != 3 {
		t.Errorf("after revoke: revision = %d, want 3", dir.Revision)
	}
	if len(dir.Devices) != 1 {
		t.Errorf("devices count after revoke = %d, want 1", len(dir.Devices))
	}

	// Revoke an unknown device: no-op, no new revision.
	prevRev := state.Revision()
	_, removed, err = state.RevokeDevice(context.Background(), "ghost")
	if err != nil {
		t.Fatalf("RevokeDevice (ghost): %v", err)
	}
	if removed {
		t.Error("RevokeDevice returned removed=true for unknown device")
	}
	if state.Revision() != prevRev {
		t.Errorf("revision changed on no-op revoke: was %d, now %d", prevRev, state.Revision())
	}
}

// TestDirectoryStateInitialSeed confirms NewDirectoryState's
// initial seed emits revision 1 immediately.
func TestDirectoryStateInitialSeed(t *testing.T) {
	signer := crypto.SuiteBaseline.Signer()
	_, priv, err := signer.GenerateKeyPair()
	if err != nil {
		t.Fatalf("identity keypair: %v", err)
	}
	pubBytes, _, _ := signer.GenerateKeyPair()
	idFP := keys.Compute(pubBytes)
	seed := []keys.DeviceDirectoryEntry{
		mkEntry(t, "seed-1", keys.DeviceRoleFullAccess, nil),
		mkEntry(t, "seed-2", keys.DeviceRoleFullAccess, nil),
	}
	state, err := keys.NewDirectoryState(keys.DirectoryStateConfig{
		UserID:        "alice@example.com",
		Suite:         crypto.SuiteBaseline,
		IdentityPriv:  priv,
		IdentityKeyID: idFP,
		Initial:       seed,
	})
	if err != nil {
		t.Fatalf("NewDirectoryState: %v", err)
	}
	dir := state.Current()
	if dir == nil {
		t.Fatal("Current() nil after initial seed")
	}
	if dir.Revision != 1 {
		t.Errorf("initial seed revision = %d, want 1", dir.Revision)
	}
	if len(dir.Devices) != 2 {
		t.Errorf("devices count = %d, want 2", len(dir.Devices))
	}
}

// TestDirectoryStoreLookup confirms the multi-user wrapper.
func TestDirectoryStoreLookup(t *testing.T) {
	store := keys.NewDirectoryStore()
	state, _, _ := newDirectoryState(t)
	if err := store.Register("alice@example.com", state); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if got := store.Lookup("alice@example.com"); got != state {
		t.Error("Lookup returned wrong state")
	}
	if got := store.Lookup("bob@example.com"); got != nil {
		t.Errorf("Lookup for unknown user returned non-nil: %v", got)
	}
	if err := store.Register("alice@example.com", state); err == nil {
		t.Error("Register accepted duplicate user_id")
	}
}

// TestDirectoryCacheVerifyAndCacheHappyPath drives the consumer
// flow: verify a fresh directory, cache its revision, accept a
// later revision, reject an older revision.
func TestDirectoryCacheVerifyAndCacheHappyPath(t *testing.T) {
	state, identityPub, _ := newDirectoryState(t)
	dir1, err := state.AddDevice(context.Background(), mkEntry(t, "d-1", keys.DeviceRoleFullAccess, nil))
	if err != nil {
		t.Fatalf("AddDevice: %v", err)
	}
	cache := keys.NewDirectoryCache()
	if err := cache.VerifyAndCache(crypto.SuiteBaseline, dir1, identityPub, nil); err != nil {
		t.Errorf("VerifyAndCache rev1: %v", err)
	}
	if cache.Highest("alice@example.com") != 1 {
		t.Errorf("highest = %d, want 1", cache.Highest("alice@example.com"))
	}

	// Add another device -> revision 2; cache accepts.
	dir2, err := state.AddDevice(context.Background(), mkEntry(t, "d-2", keys.DeviceRoleFullAccess, nil))
	if err != nil {
		t.Fatalf("AddDevice: %v", err)
	}
	if err := cache.VerifyAndCache(crypto.SuiteBaseline, dir2, identityPub, nil); err != nil {
		t.Errorf("VerifyAndCache rev2: %v", err)
	}
	if cache.Highest("alice@example.com") != 2 {
		t.Errorf("highest = %d, want 2", cache.Highest("alice@example.com"))
	}

	// Re-presenting rev1 (lower than cache) is a §10.6.2 rollback.
	if err := cache.VerifyAndCache(crypto.SuiteBaseline, dir1, identityPub, nil); err == nil {
		t.Error("VerifyAndCache accepted a lower revision; rollback not detected")
	}
}

// TestDirectoryCacheRejectsTamperedSignature confirms the
// signature verification gates revision caching.
func TestDirectoryCacheRejectsTamperedSignature(t *testing.T) {
	state, identityPub, _ := newDirectoryState(t)
	dir, err := state.AddDevice(context.Background(), mkEntry(t, "d-1", keys.DeviceRoleFullAccess, nil))
	if err != nil {
		t.Fatalf("AddDevice: %v", err)
	}
	// Mutate the user_id (covered by signature) so verification fails.
	tampered := *dir
	tampered.UserID = "mallory@attacker.example"
	cache := keys.NewDirectoryCache()
	if err := cache.VerifyAndCache(crypto.SuiteBaseline, &tampered, identityPub, nil); err == nil {
		t.Error("VerifyAndCache accepted tampered directory")
	}
	if cache.Highest("mallory@attacker.example") != 0 {
		t.Error("revision cached for tampered user_id; verification should gate caching")
	}
}

// TestDirectoryCacheCertCheck confirms the certificate-presence
// callback is consulted for every delegated entry.
func TestDirectoryCacheCertCheck(t *testing.T) {
	state, identityPub, _ := newDirectoryState(t)
	certID := "01JCERT00000000000000000001"
	if _, err := state.AddDevice(context.Background(), mkEntry(t, "d-1", keys.DeviceRoleDelegated, &certID)); err != nil {
		t.Fatalf("AddDevice: %v", err)
	}
	dir := state.Current()
	cache := keys.NewDirectoryCache()

	called := false
	check := keys.CertificateCheck(func(id string) error {
		called = true
		if id != certID {
			t.Errorf("CertCheck called with %q, want %q", id, certID)
		}
		return nil
	})
	if err := cache.VerifyAndCache(crypto.SuiteBaseline, dir, identityPub, check); err != nil {
		t.Errorf("VerifyAndCache with passing cert check: %v", err)
	}
	if !called {
		t.Error("CertCheck not called on delegated entry")
	}

	// Failing cert check fails the whole verification.
	failing := keys.CertificateCheck(func(_ string) error { return errors.New("certificate revoked") })
	if err := cache.VerifyAndCache(crypto.SuiteBaseline, dir, identityPub, failing); err == nil {
		t.Error("VerifyAndCache accepted a directory with failing cert check")
	}
}

// TestDirectoryCacheReset confirms the manual override clears
// cached state.
func TestDirectoryCacheReset(t *testing.T) {
	cache := keys.NewDirectoryCache()
	state, identityPub, _ := newDirectoryState(t)
	dir, _ := state.AddDevice(context.Background(), mkEntry(t, "d-1", keys.DeviceRoleFullAccess, nil))
	if err := cache.VerifyAndCache(crypto.SuiteBaseline, dir, identityPub, nil); err != nil {
		t.Fatalf("VerifyAndCache: %v", err)
	}
	if cache.Highest("alice@example.com") != 1 {
		t.Errorf("highest = %d, want 1", cache.Highest("alice@example.com"))
	}
	cache.Reset("alice@example.com")
	if cache.Highest("alice@example.com") != 0 {
		t.Errorf("after Reset: highest = %d, want 0", cache.Highest("alice@example.com"))
	}
}
