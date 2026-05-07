package largeattachment

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
)

// Store is the storage-backend abstraction for large-attachment
// ciphertexts. The protocol carries only metadata (id, url,
// ciphertext_hash, aead_nonce) inside the envelope; the bytes
// themselves live at the URL behind a backend the operator chooses
// (S3, IPFS, local disk, custom CDN).
//
// Store decouples the wire-level Item from the storage layer so
// the same ATTACHMENTS.md §3.2 round-trip applies regardless of
// backend. Implementations MUST:
//
//   - Store opaque ciphertext bytes by attachment id.
//   - Return the bytes by id without inspecting them; the bytes
//     are AEAD-encrypted under a per-attachment key the storage
//     server cannot derive.
//   - NOT log, mutate, or transform the ciphertext. The stored
//     blob is byte-exact; ciphertext_hash on the wire pins the
//     bytes the recipient expects.
//
// Stat reports the size and presence of an attachment without
// returning bytes; useful for clients that want to surface an
// availability indicator before fetching.
type Store interface {
	// Put stores the ciphertext bytes for id. Returns
	// ErrAttachmentExists if id is already present (writes are
	// at-most-once; ATTACHMENTS.md §4 lays out a put-once,
	// fetch-many model).
	Put(ctx context.Context, id string, ciphertext io.Reader, size int64) error

	// Get returns a Reader over the ciphertext bytes for id.
	// Returns ErrAttachmentNotFound when id is not present. The
	// caller MUST close the returned Reader.
	Get(ctx context.Context, id string) (io.ReadCloser, error)

	// Stat reports the ciphertext size in bytes and whether the
	// attachment is present. Returns (-1, false, nil) for unknown
	// ids and (size, true, nil) for present ones.
	Stat(ctx context.Context, id string) (size int64, present bool, err error)

	// Delete removes the ciphertext for id. A no-op for unknown
	// ids per ATTACHMENTS.md §4.4 (storage providers SHOULD treat
	// repeat-deletes as idempotent).
	Delete(ctx context.Context, id string) error
}

// Sentinel errors. Implementations SHOULD return these wrapped
// when the corresponding condition holds so callers can branch via
// errors.Is.
var (
	// ErrAttachmentNotFound is returned by Get and Stat when the
	// attachment id is not stored.
	ErrAttachmentNotFound = errors.New("largeattachment: attachment not found")

	// ErrAttachmentExists is returned by Put when the attachment id
	// is already present and the implementation enforces put-once
	// semantics.
	ErrAttachmentExists = errors.New("largeattachment: attachment already exists")

	// ErrCiphertextSizeMismatch is returned when a Put declared a
	// size that does not match the bytes actually consumed from the
	// reader.
	ErrCiphertextSizeMismatch = errors.New("largeattachment: declared size does not match streamed bytes")
)

// inMemoryStore is the reference Store implementation used by tests
// and demos. Production deployments plug in a durable backend; the
// in-memory store is concurrency-safe but holds every ciphertext
// in process memory.
type inMemoryStore struct {
	mu      sync.Mutex
	records map[string][]byte
}

// NewInMemoryStore returns a fresh in-memory Store.
func NewInMemoryStore() Store {
	return &inMemoryStore{records: make(map[string][]byte)}
}

// Put copies the entire reader into memory. If declaredSize is
// non-negative and the stream length differs, returns
// ErrCiphertextSizeMismatch and the entry is NOT inserted.
func (s *inMemoryStore) Put(_ context.Context, id string, ciphertext io.Reader, size int64) error {
	if id == "" {
		return errors.New("largeattachment: put empty id")
	}
	if ciphertext == nil {
		return errors.New("largeattachment: put nil ciphertext reader")
	}
	s.mu.Lock()
	if _, exists := s.records[id]; exists {
		s.mu.Unlock()
		return fmt.Errorf("%w: %s", ErrAttachmentExists, id)
	}
	s.mu.Unlock()
	buf, err := io.ReadAll(ciphertext)
	if err != nil {
		return fmt.Errorf("largeattachment: read ciphertext: %w", err)
	}
	if size >= 0 && int64(len(buf)) != size {
		return fmt.Errorf("%w: declared %d, got %d", ErrCiphertextSizeMismatch, size, len(buf))
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// Re-check after the read in case a concurrent Put won the race.
	if _, exists := s.records[id]; exists {
		return fmt.Errorf("%w: %s", ErrAttachmentExists, id)
	}
	s.records[id] = buf
	return nil
}

// Get returns a ReadCloser over a copy of the stored bytes; the
// copy isolates callers from concurrent Delete.
func (s *inMemoryStore) Get(_ context.Context, id string) (io.ReadCloser, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.records[id]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrAttachmentNotFound, id)
	}
	cp := make([]byte, len(v))
	copy(cp, v)
	return readCloser{r: bytesReaderOf(cp)}, nil
}

// Stat returns the size and presence flag.
func (s *inMemoryStore) Stat(_ context.Context, id string) (int64, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.records[id]
	if !ok {
		return -1, false, nil
	}
	return int64(len(v)), true, nil
}

// Delete removes the entry; idempotent on unknown ids.
func (s *inMemoryStore) Delete(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.records, id)
	return nil
}

// bytesReader is a small Reader over a byte slice. We intentionally
// avoid bytes.Buffer to keep the package import-light (no bytes
// pulled in transitively).
type bytesReader []byte

func (b *bytesReader) Read(p []byte) (int, error) {
	if len(*b) == 0 {
		return 0, io.EOF
	}
	n := copy(p, *b)
	*b = (*b)[n:]
	return n, nil
}

// We need the receiver on a value (slice header) for io.ReadAll to
// see EOF; provide a small helper that allocates the slice header
// per Get call.
func bytesReaderOf(b []byte) *bytesReader {
	r := bytesReader(b)
	return &r
}

// readCloser wraps a Reader to satisfy io.ReadCloser without an
// actual close-side resource.
type readCloser struct {
	r io.Reader
}

func (rc readCloser) Read(p []byte) (int, error) { return rc.r.Read(p) }
func (rc readCloser) Close() error               { return nil }
