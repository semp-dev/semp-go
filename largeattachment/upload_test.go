package largeattachment_test

import (
	"bytes"
	"crypto/rand"
	"errors"
	"strings"
	"testing"

	"github.com/semp-dev/semp-go/crypto"
	"github.com/semp-dev/semp-go/largeattachment"
)

func makeKEnclosure(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return k
}

// TestUploadDownloadRoundTrip exercises the §5/§6 happy path: a
// fresh upload encrypts to a Item + ciphertext, and the inverse
// download recovers the original bytes.
func TestUploadDownloadRoundTrip(t *testing.T) {
	plaintext := []byte("hello, attached world")
	k := makeKEnclosure(t)
	res, err := largeattachment.Encrypt(largeattachment.EncryptInput{
		Suite:      crypto.SuiteBaseline,
		KEnclosure: k,
		Plaintext:  plaintext,
		Filename:   "report.pdf",
		MimeType:   "application/pdf",
		URL:        "https://blobs.example.com/att-1",
	})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if res.Item.ID == "" || res.Item.AEADNonce == "" || res.Item.CiphertextHash == "" {
		t.Fatalf("Encrypt did not populate required fields: %+v", res.Item)
	}
	if res.Item.AEADAlgorithm != largeattachment.AEADChaCha20Poly1305 {
		t.Errorf("AEADAlgorithm = %q, want %q", res.Item.AEADAlgorithm, largeattachment.AEADChaCha20Poly1305)
	}
	if res.Item.PlaintextSize != int64(len(plaintext)) {
		t.Errorf("PlaintextSize = %d, want %d", res.Item.PlaintextSize, len(plaintext))
	}
	if err := res.Item.Validate(); err != nil {
		t.Errorf("Item.Validate: %v", err)
	}

	got, err := largeattachment.Decrypt(crypto.SuiteBaseline, k, res.Item, res.Ciphertext)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("round-trip plaintext mismatch")
	}
}

// TestEncryptIDIsULIDShape confirms the auto-generated id is a 26-
// character Crockford-base32 string. This is a §5 RECOMMENDED
// shape; tests pin it so a future refactor can't silently shift to
// a different id format.
func TestEncryptIDIsULIDShape(t *testing.T) {
	res, err := largeattachment.Encrypt(largeattachment.EncryptInput{
		Suite:      crypto.SuiteBaseline,
		KEnclosure: makeKEnclosure(t),
		Plaintext:  []byte("x"),
		Filename:   "x",
		MimeType:   "text/plain",
		URL:        "https://example.com/x",
	})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if len(res.Item.ID) != 26 {
		t.Errorf("ID length = %d, want 26", len(res.Item.ID))
	}
	for _, r := range res.Item.ID {
		if !strings.ContainsRune("0123456789ABCDEFGHJKMNPQRSTVWXYZ", r) {
			t.Errorf("ID contains non-Crockford-base32 rune %q", r)
		}
	}
}

// TestEncryptCallerSuppliedIDAndNonce confirms tests can drive
// deterministic output by pre-supplying id and nonce.
func TestEncryptCallerSuppliedIDAndNonce(t *testing.T) {
	nonce := make([]byte, 12)
	for i := range nonce {
		nonce[i] = byte(i + 1)
	}
	res, err := largeattachment.Encrypt(largeattachment.EncryptInput{
		Suite:      crypto.SuiteBaseline,
		KEnclosure: makeKEnclosure(t),
		Plaintext:  []byte("data"),
		Filename:   "x",
		MimeType:   "text/plain",
		URL:        "https://example.com/x",
		ID:         "01J0FIXEDIDFORTESTING01234",
		AEADNonce:  nonce,
	})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if res.Item.ID != "01J0FIXEDIDFORTESTING01234" {
		t.Errorf("ID = %q, want fixed value", res.Item.ID)
	}
}

// TestDecryptRejectsCiphertextTamper confirms a single-byte
// modification of the ciphertext fails the AEAD-open with a §7.3
// integrity failure.
func TestDecryptRejectsCiphertextTamper(t *testing.T) {
	k := makeKEnclosure(t)
	res, err := largeattachment.Encrypt(largeattachment.EncryptInput{
		Suite:      crypto.SuiteBaseline,
		KEnclosure: k,
		Plaintext:  []byte("plaintext"),
		Filename:   "x",
		MimeType:   "text/plain",
		URL:        "https://example.com/x",
	})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	tampered := make([]byte, len(res.Ciphertext))
	copy(tampered, res.Ciphertext)
	tampered[0] ^= 0x01
	// The hash check fires first; if we update the hash to match
	// the tampered bytes, the AEAD-open then fails. Test both:

	// 1) raw tamper (hash mismatch path)
	if _, err := largeattachment.Decrypt(crypto.SuiteBaseline, k, res.Item, tampered); err == nil {
		t.Error("Decrypt accepted ciphertext with tampered byte (hash check missed)")
	} else if !errors.Is(err, largeattachment.ErrCiphertextHashMismatch) {
		t.Errorf("expected ErrCiphertextHashMismatch, got %v", err)
	}

	// 2) update hash to match tampered bytes; AEAD-open path catches it.
	tamperedItem := res.Item
	tamperedItem.CiphertextHash = largeattachment.CiphertextHash(tampered)
	if _, err := largeattachment.Decrypt(crypto.SuiteBaseline, k, tamperedItem, tampered); err == nil {
		t.Error("Decrypt accepted ciphertext after rehashing (AEAD-open should catch authentication failure)")
	}
}

// TestDecryptRejectsAADTamper confirms a metadata change (filename,
// mime_type) breaks AEAD authentication. This is the §3.2 binding.
func TestDecryptRejectsAADTamper(t *testing.T) {
	k := makeKEnclosure(t)
	res, _ := largeattachment.Encrypt(largeattachment.EncryptInput{
		Suite:      crypto.SuiteBaseline,
		KEnclosure: k,
		Plaintext:  []byte("plaintext"),
		Filename:   "report.pdf",
		MimeType:   "application/pdf",
		URL:        "https://example.com/x",
	})
	tampered := res.Item
	tampered.Filename = "innocent.txt"
	if _, err := largeattachment.Decrypt(crypto.SuiteBaseline, k, tampered, res.Ciphertext); err == nil {
		t.Error("Decrypt accepted item with mutated filename (AAD binding broken)")
	}
}

// TestDecryptRejectsKEnclosureMismatch confirms a wrong K_enclosure
// fails AEAD-open.
func TestDecryptRejectsKEnclosureMismatch(t *testing.T) {
	k1 := makeKEnclosure(t)
	k2 := makeKEnclosure(t)
	res, _ := largeattachment.Encrypt(largeattachment.EncryptInput{
		Suite:      crypto.SuiteBaseline,
		KEnclosure: k1,
		Plaintext:  []byte("x"),
		Filename:   "x",
		MimeType:   "text/plain",
		URL:        "https://example.com/x",
	})
	if _, err := largeattachment.Decrypt(crypto.SuiteBaseline, k2, res.Item, res.Ciphertext); err == nil {
		t.Error("Decrypt accepted ciphertext under wrong K_enclosure")
	}
}

// TestEncryptValidatesURL confirms a non-HTTPS URL is rejected up
// front.
func TestEncryptValidatesURL(t *testing.T) {
	_, err := largeattachment.Encrypt(largeattachment.EncryptInput{
		Suite:      crypto.SuiteBaseline,
		KEnclosure: makeKEnclosure(t),
		Plaintext:  []byte("x"),
		Filename:   "x",
		MimeType:   "text/plain",
		URL:        "http://insecure.example.com/x", // plain HTTP
	})
	if err == nil {
		t.Error("Encrypt accepted plain-HTTP URL")
	}
}

// TestEncryptPQSuiteUsesXChaCha confirms the PQ suite generates an
// xchacha20-poly1305-encrypted item per §3.2.
func TestEncryptPQSuiteUsesXChaCha(t *testing.T) {
	k := makeKEnclosure(t)
	res, err := largeattachment.Encrypt(largeattachment.EncryptInput{
		Suite:      crypto.SuitePQ,
		KEnclosure: k,
		Plaintext:  []byte("pq-encrypted"),
		Filename:   "x",
		MimeType:   "text/plain",
		URL:        "https://example.com/x",
	})
	if err != nil {
		t.Fatalf("Encrypt PQ: %v", err)
	}
	if res.Item.AEADAlgorithm != largeattachment.AEADXChaCha20Poly1305 {
		t.Errorf("AEADAlgorithm = %q, want %q", res.Item.AEADAlgorithm, largeattachment.AEADXChaCha20Poly1305)
	}
	got, err := largeattachment.Decrypt(crypto.SuitePQ, k, res.Item, res.Ciphertext)
	if err != nil {
		t.Fatalf("Decrypt PQ: %v", err)
	}
	if !bytes.Equal(got, []byte("pq-encrypted")) {
		t.Error("PQ round-trip plaintext mismatch")
	}
}

// TestDecryptRejectsAlgoMismatch confirms a suite-vs-item algorithm
// mismatch is caught before any AEAD work.
func TestDecryptRejectsAlgoMismatch(t *testing.T) {
	k := makeKEnclosure(t)
	res, _ := largeattachment.Encrypt(largeattachment.EncryptInput{
		Suite:      crypto.SuiteBaseline,
		KEnclosure: k,
		Plaintext:  []byte("x"),
		Filename:   "x",
		MimeType:   "text/plain",
		URL:        "https://example.com/x",
	})
	// Decrypt with the PQ suite; the item declares chacha20-poly1305
	// but the suite expects xchacha20-poly1305 attachments per §3.2.
	if _, err := largeattachment.Decrypt(crypto.SuitePQ, k, res.Item, res.Ciphertext); err == nil {
		t.Error("Decrypt accepted suite-vs-item algorithm mismatch")
	}
}
