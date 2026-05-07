package delivery

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

// ReceiptStore is the home-server's transient holding area for
// delivery receipts pending client acknowledgment per DELIVERY.md
// §1.1.1.6. The sending server retains a receipt only until at
// least one authenticated client device of the sending user has
// acknowledged the delivery event carrying it; after that
// acknowledgment, the server SHOULD drop the receipt so it does
// not accumulate a long-term receipts archive (which would conflict
// with the §2.5 correspondent-graph privacy posture).
//
// Production deployments plug in a durable backend; tests and
// demos use NewInMemoryReceiptStore. The interface is deliberately
// small: Put a freshly-issued receipt, Acknowledge after a client
// device has consumed the corresponding delivery event, Prune
// after the configured push-notification retention window.
type ReceiptStore interface {
	// Put inserts a receipt issued by the recipient server,
	// keyed by (envelope_id, recipient). storedAt is the
	// wall-clock time the receipt entered the store; the prune
	// path uses it to enforce the push-notification retention
	// window for receipts that no client ever acknowledged.
	Put(ctx context.Context, envelopeID, recipient string, receipt *DeliveryReceipt, storedAt time.Time) error

	// Get fetches the receipt for (envelope_id, recipient).
	// Returns nil for unknown records (callers distinguish via
	// the returned error).
	Get(ctx context.Context, envelopeID, recipient string) (*DeliveryReceipt, error)

	// Acknowledge marks the receipt for (envelope_id, recipient)
	// as having been delivered to a client device per §1.1.1.6.
	// The implementation MAY drop the receipt immediately on
	// Acknowledge (the spec's "MAY drop" allowance), or retain
	// it briefly for cross-device propagation. The reference
	// in-memory implementation drops on Acknowledge.
	Acknowledge(ctx context.Context, envelopeID, recipient string) error

	// PruneUnacknowledged removes receipts whose storedAt is
	// older than cutoff and that have not been acknowledged.
	// The §1.1.1.6 retention rule says receipts MAY be dropped
	// on the same schedule as undelivered notifications; this
	// method implements that pruning.
	PruneUnacknowledged(ctx context.Context, cutoff time.Time) (int, error)
}

// inMemoryReceiptStore is the reference ReceiptStore. Concurrency-
// safe; Acknowledge drops the receipt immediately so no plaintext
// archive accumulates.
type inMemoryReceiptStore struct {
	mu sync.Mutex
	// records keyed by envelope_id + "\x00" + recipient.
	records map[string]receiptRecord
}

type receiptRecord struct {
	receipt  *DeliveryReceipt
	storedAt time.Time
}

// NewInMemoryReceiptStore returns a fresh in-memory ReceiptStore.
func NewInMemoryReceiptStore() ReceiptStore {
	return &inMemoryReceiptStore{records: make(map[string]receiptRecord)}
}

func receiptKey(envelopeID, recipient string) string {
	return envelopeID + "\x00" + recipient
}

// Put inserts a receipt. Returns an error if (envelope_id,
// recipient) is already present (callers MUST NOT double-Put a
// receipt; the recipient server's at-most-once delivery semantics
// already preclude this on the wire).
func (s *inMemoryReceiptStore) Put(_ context.Context, envelopeID, recipient string, receipt *DeliveryReceipt, storedAt time.Time) error {
	if envelopeID == "" || recipient == "" {
		return errors.New("delivery: receipt store put requires envelope_id and recipient")
	}
	if receipt == nil {
		return errors.New("delivery: receipt store put nil receipt")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	k := receiptKey(envelopeID, recipient)
	if _, exists := s.records[k]; exists {
		return fmt.Errorf("delivery: receipt already stored for (%s, %s)", envelopeID, recipient)
	}
	s.records[k] = receiptRecord{receipt: receipt, storedAt: storedAt}
	return nil
}

// Get fetches a receipt. Returns (nil, nil) for unknown.
func (s *inMemoryReceiptStore) Get(_ context.Context, envelopeID, recipient string) (*DeliveryReceipt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.records[receiptKey(envelopeID, recipient)]
	if !ok {
		return nil, nil
	}
	return rec.receipt, nil
}

// Acknowledge drops the receipt per §1.1.1.6 "MAY drop after
// acknowledgment". A no-op on unknown records: the §1.1.1.6
// retention rule does not require acknowledgment to be exact-once,
// only that the server eventually drop the receipt.
func (s *inMemoryReceiptStore) Acknowledge(_ context.Context, envelopeID, recipient string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.records, receiptKey(envelopeID, recipient))
	return nil
}

// PruneUnacknowledged removes receipts older than cutoff.
func (s *inMemoryReceiptStore) PruneUnacknowledged(_ context.Context, cutoff time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	type doomed struct {
		key string
	}
	var stale []doomed
	for k, rec := range s.records {
		if rec.storedAt.Before(cutoff) || rec.storedAt.Equal(cutoff) {
			stale = append(stale, doomed{key: k})
		}
	}
	// Sort for deterministic iteration during prune (helps tests).
	sort.Slice(stale, func(i, j int) bool { return stale[i].key < stale[j].key })
	for _, d := range stale {
		delete(s.records, d.key)
	}
	return len(stale), nil
}

// DefaultReceiptRetention is the default push-notification window
// the §1.1.1.6 prune path uses when the operator has not configured
// a tighter value. Three days matches the 72h server_max_retry_horizon
// default per §2.4: any envelope that hits the queue's hard
// deadline cannot have a delivered acknowledgment past that point,
// so retaining receipts longer offers no value.
const DefaultReceiptRetention = 72 * time.Hour
