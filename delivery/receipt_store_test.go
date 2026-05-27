package delivery_test

import (
	"context"
	"testing"
	"time"

	"github.com/semp-dev/semp-go/delivery"
)

func newReceipt(envelopeID string) *delivery.DeliveryReceipt {
	return &delivery.DeliveryReceipt{
		Type:            "SEMP_DELIVERY_RECEIPT",
		Version:         "1.0.0",
		EnvelopeHash:    delivery.EnvelopeHash{Algorithm: "sha-256", Value: envelopeID},
		RecipientDomain: "example.com",
		AcceptedAt:      time.Now().UTC(),
	}
}

// TestReceiptStoreAcknowledgeDrops confirms the §1.1.1.6 happy path:
// after Acknowledge, the receipt is no longer retained.
func TestReceiptStoreAcknowledgeDrops(t *testing.T) {
	store := delivery.NewInMemoryReceiptStore()
	ctx := context.Background()
	if err := store.Put(ctx, "env-1", "alice@example.com", newReceipt("env-1"), time.Now().UTC()); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if got, err := store.Get(ctx, "env-1", "alice@example.com"); err != nil || got == nil {
		t.Fatalf("Get pre-ack: got=%v err=%v", got, err)
	}
	if err := store.Acknowledge(ctx, "env-1", "alice@example.com"); err != nil {
		t.Fatalf("Acknowledge: %v", err)
	}
	got, err := store.Get(ctx, "env-1", "alice@example.com")
	if err != nil {
		t.Fatalf("Get post-ack: %v", err)
	}
	if got != nil {
		t.Errorf("receipt still retained after Acknowledge: %+v", got)
	}
}

// TestReceiptStorePruneUnacknowledged confirms receipts past the
// configured retention window are dropped.
func TestReceiptStorePruneUnacknowledged(t *testing.T) {
	store := delivery.NewInMemoryReceiptStore()
	ctx := context.Background()
	stored := time.Date(2026, 5, 7, 10, 0, 0, 0, time.UTC)
	if err := store.Put(ctx, "env-1", "alice@example.com", newReceipt("env-1"), stored); err != nil {
		t.Fatalf("Put: %v", err)
	}
	// Prune well past the storedAt: drop.
	cutoff := stored.Add(72 * time.Hour)
	removed, err := store.PruneUnacknowledged(ctx, cutoff)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if removed != 1 {
		t.Errorf("removed = %d, want 1", removed)
	}
	if got, _ := store.Get(ctx, "env-1", "alice@example.com"); got != nil {
		t.Errorf("receipt still present after prune: %+v", got)
	}
}

// TestReceiptStorePruneRespectsCutoff confirms records younger
// than the cutoff are NOT pruned.
func TestReceiptStorePruneRespectsCutoff(t *testing.T) {
	store := delivery.NewInMemoryReceiptStore()
	ctx := context.Background()
	stored := time.Date(2026, 5, 7, 10, 0, 0, 0, time.UTC)
	if err := store.Put(ctx, "env-1", "alice@example.com", newReceipt("env-1"), stored); err != nil {
		t.Fatalf("Put: %v", err)
	}
	cutoff := stored.Add(-time.Hour)
	removed, _ := store.PruneUnacknowledged(ctx, cutoff)
	if removed != 0 {
		t.Errorf("removed = %d, want 0 (record younger than cutoff)", removed)
	}
	if got, _ := store.Get(ctx, "env-1", "alice@example.com"); got == nil {
		t.Error("record was dropped despite being younger than cutoff")
	}
}

// TestReceiptStoreRejectsDuplicate confirms a double Put for the
// same key is rejected (the at-most-once wire semantics already
// preclude this; the store enforces it as a defense-in-depth).
func TestReceiptStoreRejectsDuplicate(t *testing.T) {
	store := delivery.NewInMemoryReceiptStore()
	ctx := context.Background()
	now := time.Now().UTC()
	if err := store.Put(ctx, "env-1", "alice@example.com", newReceipt("env-1"), now); err != nil {
		t.Fatalf("Put 1: %v", err)
	}
	if err := store.Put(ctx, "env-1", "alice@example.com", newReceipt("env-1"), now); err == nil {
		t.Error("Put accepted duplicate")
	}
}

// TestReceiptStoreAcknowledgeUnknownIsNoop confirms acknowledging
// an unknown (envelope, recipient) does not fail.
func TestReceiptStoreAcknowledgeUnknownIsNoop(t *testing.T) {
	store := delivery.NewInMemoryReceiptStore()
	if err := store.Acknowledge(context.Background(), "env-ghost", "nobody@example.com"); err != nil {
		t.Errorf("Acknowledge on unknown: %v", err)
	}
}
