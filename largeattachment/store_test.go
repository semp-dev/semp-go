package largeattachment_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	"github.com/semp-dev/semp-go/largeattachment"
)

func TestInMemoryStorePutGetRoundTrip(t *testing.T) {
	store := largeattachment.NewInMemoryStore()
	ctx := context.Background()
	want := []byte("ciphertext-bytes")
	if err := store.Put(ctx, "att-1", bytes.NewReader(want), int64(len(want))); err != nil {
		t.Fatalf("Put: %v", err)
	}
	rc, err := store.Get(ctx, "att-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer rc.Close()
	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("round-trip = %q, want %q", got, want)
	}
}

func TestInMemoryStorePutRejectsDuplicate(t *testing.T) {
	store := largeattachment.NewInMemoryStore()
	ctx := context.Background()
	if err := store.Put(ctx, "att-1", bytes.NewReader([]byte("a")), 1); err != nil {
		t.Fatalf("Put 1: %v", err)
	}
	err := store.Put(ctx, "att-1", bytes.NewReader([]byte("b")), 1)
	if !errors.Is(err, largeattachment.ErrAttachmentExists) {
		t.Errorf("Put dup: got %v, want ErrAttachmentExists", err)
	}
}

func TestInMemoryStorePutSizeMismatchRejected(t *testing.T) {
	store := largeattachment.NewInMemoryStore()
	err := store.Put(context.Background(), "att-1", bytes.NewReader([]byte("hi")), 4)
	if !errors.Is(err, largeattachment.ErrCiphertextSizeMismatch) {
		t.Errorf("size mismatch: got %v, want ErrCiphertextSizeMismatch", err)
	}
}

func TestInMemoryStorePutNegativeSizeAccepted(t *testing.T) {
	// size = -1 disables the size check (caller does not know
	// the streamed length up front).
	store := largeattachment.NewInMemoryStore()
	if err := store.Put(context.Background(), "att-1", bytes.NewReader([]byte("hi")), -1); err != nil {
		t.Errorf("Put with size=-1: %v", err)
	}
}

func TestInMemoryStoreGetNotFound(t *testing.T) {
	_, err := largeattachment.NewInMemoryStore().Get(context.Background(), "ghost")
	if !errors.Is(err, largeattachment.ErrAttachmentNotFound) {
		t.Errorf("Get unknown: got %v, want ErrAttachmentNotFound", err)
	}
}

func TestInMemoryStoreStat(t *testing.T) {
	store := largeattachment.NewInMemoryStore()
	ctx := context.Background()
	if size, present, err := store.Stat(ctx, "ghost"); err != nil || present || size != -1 {
		t.Errorf("Stat unknown: size=%d present=%v err=%v, want -1/false/nil", size, present, err)
	}
	if err := store.Put(ctx, "att-1", bytes.NewReader([]byte("12345")), 5); err != nil {
		t.Fatalf("Put: %v", err)
	}
	size, present, err := store.Stat(ctx, "att-1")
	if err != nil || !present || size != 5 {
		t.Errorf("Stat present: size=%d present=%v err=%v, want 5/true/nil", size, present, err)
	}
}

func TestInMemoryStoreDeleteIsIdempotent(t *testing.T) {
	store := largeattachment.NewInMemoryStore()
	ctx := context.Background()
	if err := store.Delete(ctx, "ghost"); err != nil {
		t.Errorf("Delete unknown: %v", err)
	}
	_ = store.Put(ctx, "att-1", bytes.NewReader([]byte("a")), 1)
	if err := store.Delete(ctx, "att-1"); err != nil {
		t.Errorf("Delete present: %v", err)
	}
	if _, err := store.Get(ctx, "att-1"); !errors.Is(err, largeattachment.ErrAttachmentNotFound) {
		t.Errorf("Get after Delete: got %v, want ErrAttachmentNotFound", err)
	}
}

func TestInMemoryStoreGetBytesAreIsolatedCopy(t *testing.T) {
	// Mutating the bytes returned by Get MUST NOT affect the
	// stored entry. The reference Store returns a copy per Get;
	// this test pins that contract.
	store := largeattachment.NewInMemoryStore()
	ctx := context.Background()
	original := []byte{1, 2, 3, 4}
	if err := store.Put(ctx, "att-1", bytes.NewReader(original), int64(len(original))); err != nil {
		t.Fatalf("Put: %v", err)
	}
	rc, _ := store.Get(ctx, "att-1")
	got, _ := io.ReadAll(rc)
	rc.Close()
	got[0] = 0xFF
	rc2, _ := store.Get(ctx, "att-1")
	defer rc2.Close()
	got2, _ := io.ReadAll(rc2)
	if got2[0] != 1 {
		t.Errorf("stored byte mutated by caller: got2[0] = %d", got2[0])
	}
}
