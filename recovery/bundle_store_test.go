package recovery_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"semp.dev/semp-go/recovery"
)

func mkBundle(t *testing.T, userID, bundleID string, supersedes *string) *recovery.BackupBundle {
	t.Helper()
	return &recovery.BackupBundle{
		Type:             recovery.BundleType,
		Version:          recovery.RecordVersion,
		UserID:           userID,
		BundleID:         bundleID,
		CreatedAt:        time.Now().UTC().Truncate(time.Second),
		Supersedes:       supersedes,
		PayloadAlgorithm: recovery.BundlePayloadAEAD,
		PayloadNonce:     "AAAAAAAAAAAAAAAAAAAAAAA=",
		EncryptedPayload: "Y2lwaGVydGV4dA==",
	}
}

func ptr(s string) *string { return &s }

// TestBundleStoreInitialPutCurrent confirms the first-ever bundle
// for a user is accepted with a nil supersedes pointer.
func TestBundleStoreInitialPutCurrent(t *testing.T) {
	store := recovery.NewInMemoryBundleStore()
	b := mkBundle(t, "alice@example.com", "bundle-1", nil)
	if err := store.PutCurrent(context.Background(), "alice@example.com", b, time.Now().UTC()); err != nil {
		t.Fatalf("PutCurrent: %v", err)
	}
	got, err := store.GetCurrent(context.Background(), "alice@example.com")
	if err != nil {
		t.Fatalf("GetCurrent: %v", err)
	}
	if got.BundleID != "bundle-1" {
		t.Errorf("BundleID = %q, want bundle-1", got.BundleID)
	}
}

// TestBundleStoreSupersedesChainAccepted confirms a follow-up
// bundle with supersedes pointing at the prior current is accepted.
func TestBundleStoreSupersedesChainAccepted(t *testing.T) {
	store := recovery.NewInMemoryBundleStore()
	b1 := mkBundle(t, "alice@example.com", "bundle-1", nil)
	if err := store.PutCurrent(context.Background(), "alice@example.com", b1, time.Now().UTC()); err != nil {
		t.Fatalf("Put 1: %v", err)
	}
	b2 := mkBundle(t, "alice@example.com", "bundle-2", ptr("bundle-1"))
	if err := store.PutCurrent(context.Background(), "alice@example.com", b2, time.Now().UTC()); err != nil {
		t.Fatalf("Put 2: %v", err)
	}
	got, _ := store.GetCurrent(context.Background(), "alice@example.com")
	if got.BundleID != "bundle-2" {
		t.Errorf("current BundleID = %q, want bundle-2", got.BundleID)
	}
	hist, _ := store.History(context.Background(), "alice@example.com")
	if len(hist) != 2 {
		t.Errorf("History len = %d, want 2", len(hist))
	}
	if hist[0].BundleID != "bundle-2" {
		t.Errorf("History[0] = %q, want bundle-2 (current)", hist[0].BundleID)
	}
}

// TestBundleStoreSupersedesMismatchRejected confirms a stale
// supersedes pointer is rejected per §4.2 step 3.
func TestBundleStoreSupersedesMismatchRejected(t *testing.T) {
	store := recovery.NewInMemoryBundleStore()
	b1 := mkBundle(t, "alice@example.com", "bundle-1", nil)
	if err := store.PutCurrent(context.Background(), "alice@example.com", b1, time.Now().UTC()); err != nil {
		t.Fatalf("Put 1: %v", err)
	}
	// Wrong supersedes pointer.
	b2 := mkBundle(t, "alice@example.com", "bundle-2", ptr("non-existent"))
	err := store.PutCurrent(context.Background(), "alice@example.com", b2, time.Now().UTC())
	if !errors.Is(err, recovery.ErrSupersedesMismatch) {
		t.Errorf("got %v, want ErrSupersedesMismatch", err)
	}
}

// TestBundleStoreInitialPutWithSupersedesRejected confirms the
// first-ever bundle MUST have nil/empty supersedes.
func TestBundleStoreInitialPutWithSupersedesRejected(t *testing.T) {
	store := recovery.NewInMemoryBundleStore()
	b := mkBundle(t, "alice@example.com", "bundle-1", ptr("ghost"))
	err := store.PutCurrent(context.Background(), "alice@example.com", b, time.Now().UTC())
	if !errors.Is(err, recovery.ErrSupersedesMismatch) {
		t.Errorf("got %v, want ErrSupersedesMismatch on first-ever with non-nil supersedes", err)
	}
}

// TestBundleStoreGetCurrentNotFound confirms an unknown user
// returns ErrBundleNotFound.
func TestBundleStoreGetCurrentNotFound(t *testing.T) {
	store := recovery.NewInMemoryBundleStore()
	_, err := store.GetCurrent(context.Background(), "ghost@example.com")
	if !errors.Is(err, recovery.ErrBundleNotFound) {
		t.Errorf("got %v, want ErrBundleNotFound", err)
	}
}

// TestBundleStoreUserIDMismatch confirms PutCurrent rejects a
// bundle whose UserID does not match the userID arg.
func TestBundleStoreUserIDMismatch(t *testing.T) {
	store := recovery.NewInMemoryBundleStore()
	b := mkBundle(t, "alice@example.com", "bundle-1", nil)
	if err := store.PutCurrent(context.Background(), "bob@example.com", b, time.Now().UTC()); err == nil {
		t.Error("PutCurrent accepted user_id mismatch")
	}
}

// TestBundleStoreDeleteAll confirms the §4.1 DELETE wipes the
// user's records.
func TestBundleStoreDeleteAll(t *testing.T) {
	store := recovery.NewInMemoryBundleStore()
	_ = store.PutCurrent(context.Background(), "alice@example.com",
		mkBundle(t, "alice@example.com", "bundle-1", nil), time.Now().UTC())
	if err := store.DeleteAll(context.Background(), "alice@example.com"); err != nil {
		t.Fatalf("DeleteAll: %v", err)
	}
	if _, err := store.GetCurrent(context.Background(), "alice@example.com"); !errors.Is(err, recovery.ErrBundleNotFound) {
		t.Error("DeleteAll did not remove current bundle")
	}
}

// TestBundleStorePruneSupersededRespectsRetention confirms the
// §4.4 30-day floor is enforced and that bundles past the floor
// ARE pruned.
func TestBundleStorePruneSupersededRespectsRetention(t *testing.T) {
	now := time.Date(2026, 5, 7, 12, 0, 0, 0, time.UTC)
	clock := now
	store := recovery.NewInMemoryBundleStoreWithClock(func() time.Time { return clock })

	b1 := mkBundle(t, "alice@example.com", "bundle-1", nil)
	if err := store.PutCurrent(context.Background(), "alice@example.com", b1, now); err != nil {
		t.Fatalf("Put 1: %v", err)
	}
	// Supersede 90 days ago; it should be retained for at least 30
	// days but evictable past that.
	supersededAt := now.Add(-90 * 24 * time.Hour)
	b2 := mkBundle(t, "alice@example.com", "bundle-2", ptr("bundle-1"))
	if err := store.PutCurrent(context.Background(), "alice@example.com", b2, supersededAt); err != nil {
		t.Fatalf("Put 2: %v", err)
	}

	// Right at the 30-day floor: bundle-1 (superseded 90 days ago)
	// is past the floor; must be pruned.
	removed, err := store.PruneSuperseded(context.Background(), 30*24*time.Hour)
	if err != nil {
		t.Fatalf("PruneSuperseded: %v", err)
	}
	if removed != 1 {
		t.Errorf("removed = %d, want 1", removed)
	}
	hist, _ := store.History(context.Background(), "alice@example.com")
	if len(hist) != 1 {
		t.Errorf("History len after prune = %d, want 1", len(hist))
	}
}

// TestBundleStorePruneSupersededFloorClamp confirms a sub-30-day
// retain window is clamped UP to 30 days.
func TestBundleStorePruneSupersededFloorClamp(t *testing.T) {
	now := time.Date(2026, 5, 7, 12, 0, 0, 0, time.UTC)
	store := recovery.NewInMemoryBundleStoreWithClock(func() time.Time { return now })

	b1 := mkBundle(t, "alice@example.com", "bundle-1", nil)
	_ = store.PutCurrent(context.Background(), "alice@example.com", b1, now)
	// Supersede 10 days ago - within both the 30-day spec floor and
	// the caller's 1-hour value. The caller's value is clamped UP
	// to 30 days, so the bundle is NOT pruned.
	b2 := mkBundle(t, "alice@example.com", "bundle-2", ptr("bundle-1"))
	_ = store.PutCurrent(context.Background(), "alice@example.com", b2, now.Add(-10*24*time.Hour))

	removed, err := store.PruneSuperseded(context.Background(), time.Hour)
	if err != nil {
		t.Fatalf("PruneSuperseded: %v", err)
	}
	if removed != 0 {
		t.Errorf("removed = %d, want 0 (sub-floor retainFor must be clamped to 30d)", removed)
	}
}

// TestBundleStoreHistoryOrder confirms History returns current
// first then superseded newest-first.
func TestBundleStoreHistoryOrder(t *testing.T) {
	store := recovery.NewInMemoryBundleStore()
	now := time.Now().UTC()
	_ = store.PutCurrent(context.Background(), "alice@example.com",
		mkBundle(t, "alice@example.com", "bundle-1", nil), now.Add(-3*time.Hour))
	_ = store.PutCurrent(context.Background(), "alice@example.com",
		mkBundle(t, "alice@example.com", "bundle-2", ptr("bundle-1")), now.Add(-2*time.Hour))
	_ = store.PutCurrent(context.Background(), "alice@example.com",
		mkBundle(t, "alice@example.com", "bundle-3", ptr("bundle-2")), now.Add(-time.Hour))

	hist, _ := store.History(context.Background(), "alice@example.com")
	if len(hist) != 3 {
		t.Fatalf("History len = %d, want 3", len(hist))
	}
	if hist[0].BundleID != "bundle-3" {
		t.Errorf("History[0] = %q, want bundle-3 (current)", hist[0].BundleID)
	}
	// Superseded order: bundle-2 superseded most recently (when
	// bundle-3 went current); bundle-1 superseded earlier.
	if hist[1].BundleID != "bundle-2" {
		t.Errorf("History[1] = %q, want bundle-2 (most-recently superseded)", hist[1].BundleID)
	}
	if hist[2].BundleID != "bundle-1" {
		t.Errorf("History[2] = %q, want bundle-1 (oldest)", hist[2].BundleID)
	}
}
