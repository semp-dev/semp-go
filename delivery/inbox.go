package delivery

import "sync"

// Inbox is a minimal in-memory per-user envelope queue. It is intended for
// the cmd/semp-server demo binary and for in-process tests; it is NOT a
// production storage layer.
//
// The store is keyed by recipient address (the canonical user@domain
// string from `brief.to`). Each address has its own FIFO queue of
// envelope payloads. Production deployments would back this with a
// durable store, retention rules, fairness controls, and per-address
// access control — none of which are present here.
// DefaultMaxQueueDepth is the default per-address maximum queue depth.
const DefaultMaxQueueDepth = 10000

type Inbox struct {
	mu            sync.Mutex
	queue         map[string][][]byte
	maxQueueDepth int
}

// NewInbox returns a fresh empty inbox with DefaultMaxQueueDepth.
func NewInbox() *Inbox {
	return &Inbox{queue: make(map[string][][]byte), maxQueueDepth: DefaultMaxQueueDepth}
}

// NewInboxWithLimit returns an inbox with a custom per-address queue depth limit.
func NewInboxWithLimit(maxDepth int) *Inbox {
	if maxDepth <= 0 {
		maxDepth = DefaultMaxQueueDepth
	}
	return &Inbox{queue: make(map[string][][]byte), maxQueueDepth: maxDepth}
}

// Store appends payload to the queue for address. If the queue has reached
// its maximum depth, the oldest entry is dropped to make room.
func (i *Inbox) Store(address string, payload []byte) {
	i.mu.Lock()
	defer i.mu.Unlock()
	q := i.queue[address]
	if len(q) >= i.maxQueueDepth {
		q = q[1:] // drop oldest
	}
	i.queue[address] = append(q, payload)
}

// Drain returns every queued envelope for address and clears the queue.
// Returns nil if the address has no waiting envelopes.
func (i *Inbox) Drain(address string) [][]byte {
	i.mu.Lock()
	defer i.mu.Unlock()
	out := i.queue[address]
	delete(i.queue, address)
	return out
}

// Pending reports the number of waiting envelopes for address without
// modifying the queue.
func (i *Inbox) Pending(address string) int {
	i.mu.Lock()
	defer i.mu.Unlock()
	return len(i.queue[address])
}
