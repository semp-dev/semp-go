package largeattachment_test

import (
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"

	"semp.dev/semp-go/crypto"
	"semp.dev/semp-go/largeattachment"
)

func TestDeriveAttachmentKeyDeterministic(t *testing.T) {
	suite := crypto.SuiteBaseline
	kdf := suite.KDF()
	kEnclosure := make([]byte, 32)
	for i := range kEnclosure {
		kEnclosure[i] = byte(i)
	}
	keyA, err := largeattachment.DeriveAttachmentKey(kdf, kEnclosure, "01JATTACH00000000000000001", suite.AEAD().KeySize())
	if err != nil {
		t.Fatalf("DeriveAttachmentKey A: %v", err)
	}
	keyA2, err := largeattachment.DeriveAttachmentKey(kdf, kEnclosure, "01JATTACH00000000000000001", suite.AEAD().KeySize())
	if err != nil {
		t.Fatalf("DeriveAttachmentKey A2: %v", err)
	}
	if string(keyA) != string(keyA2) {
		t.Error("DeriveAttachmentKey not deterministic for same inputs")
	}
	keyB, err := largeattachment.DeriveAttachmentKey(kdf, kEnclosure, "01JATTACH00000000000000002", suite.AEAD().KeySize())
	if err != nil {
		t.Fatalf("DeriveAttachmentKey B: %v", err)
	}
	if string(keyA) == string(keyB) {
		t.Error("different attachment_id MUST produce different K_attachment")
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	suite := crypto.SuiteBaseline
	aead := suite.AEAD()
	kdf := suite.KDF()

	kEnclosure := make([]byte, aead.KeySize())
	if _, err := rand.Read(kEnclosure); err != nil {
		t.Fatalf("rand: %v", err)
	}

	plaintext := []byte("the brown dog jumps over the lazy fox")
	item := largeattachment.Item{
		ID:            "01JATTACH00000000000000001",
		Filename:      "notes.txt",
		MimeType:      "text/plain",
		PlaintextSize: int64(len(plaintext)),
		URL:           "https://blobs.example.com/a/abcd",
		AEADAlgorithm: largeattachment.AEADChaCha20Poly1305,
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("rand: %v", err)
	}
	item.AEADNonce = base64.StdEncoding.EncodeToString(nonce)

	key, err := largeattachment.DeriveAttachmentKey(kdf, kEnclosure, item.ID, aead.KeySize())
	if err != nil {
		t.Fatalf("DeriveAttachmentKey: %v", err)
	}
	aad, err := largeattachment.AdditionalData(item)
	if err != nil {
		t.Fatalf("AdditionalData: %v", err)
	}
	ciphertext, err := aead.Seal(key, nonce, plaintext, aad)
	if err != nil {
		t.Fatalf("aead.Seal: %v", err)
	}
	item.CiphertextHash = largeattachment.CiphertextHash(ciphertext)

	if err := item.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if err := largeattachment.VerifyCiphertextHash(item, ciphertext); err != nil {
		t.Errorf("VerifyCiphertextHash: %v", err)
	}

	// Decrypt round-trip.
	got, err := aead.Open(key, nonce, ciphertext, aad)
	if err != nil {
		t.Fatalf("aead.Open: %v", err)
	}
	if string(got) != string(plaintext) {
		t.Errorf("decrypted = %q, want %q", got, plaintext)
	}
}

// TestAdditionalDataBindsMetadata confirms that a tampered filename
// or mime_type produces a different additional-data input, which an
// AEAD verifier rejects per §3.2.
func TestAdditionalDataBindsMetadata(t *testing.T) {
	original := largeattachment.Item{
		ID:            "01JATTACH",
		Filename:      "notes.txt",
		MimeType:      "text/plain",
		PlaintextSize: 100,
		URL:           "https://blobs.example.com/a/abcd",
		AEADAlgorithm: largeattachment.AEADChaCha20Poly1305,
	}
	originalAD, _ := largeattachment.AdditionalData(original)

	// Same item, different filename: AD differs.
	tampered := original
	tampered.Filename = "evil.exe"
	tamperedAD, _ := largeattachment.AdditionalData(tampered)
	if string(originalAD) == string(tamperedAD) {
		t.Error("AdditionalData unchanged when filename changed")
	}

	// Same item, different mime_type: AD differs.
	tampered = original
	tampered.MimeType = "application/octet-stream"
	tamperedAD, _ = largeattachment.AdditionalData(tampered)
	if string(originalAD) == string(tamperedAD) {
		t.Error("AdditionalData unchanged when mime_type changed")
	}

	// Same item, different ciphertext_hash / aead_nonce / extensions:
	// AD MUST be unchanged because those fields are excluded from
	// the binding per §3.2.
	tampered = original
	tampered.CiphertextHash = "sha256:" + strings.Repeat("ff", 32)
	tamperedAD, _ = largeattachment.AdditionalData(tampered)
	if string(originalAD) != string(tamperedAD) {
		t.Error("AdditionalData changed when ciphertext_hash mutated; spec excludes this field from AAD")
	}
	tampered = original
	tampered.AEADNonce = "some-nonce-bytes"
	tamperedAD, _ = largeattachment.AdditionalData(tampered)
	if string(originalAD) != string(tamperedAD) {
		t.Error("AdditionalData changed when aead_nonce mutated; spec excludes this field from AAD")
	}
}

func TestVerifyCiphertextHashDetectsMismatch(t *testing.T) {
	item := largeattachment.Item{CiphertextHash: largeattachment.CiphertextHash([]byte("real ciphertext"))}
	if err := largeattachment.VerifyCiphertextHash(item, []byte("real ciphertext")); err != nil {
		t.Errorf("matching hash: got %v, want nil", err)
	}
	if err := largeattachment.VerifyCiphertextHash(item, []byte("attacker substitute")); err == nil {
		t.Error("VerifyCiphertextHash accepted mismatched ciphertext")
	}
}

func TestValidateURL(t *testing.T) {
	cases := []struct {
		url string
		ok  bool
	}{
		{"https://blobs.example.com/a/abcd", true},
		{"https://[2001:db8::1]:443/blob", true},
		{"https://[2001:db8::1]/blob", true},
		// Spec-violating cases.
		{"http://blobs.example.com/a", false},
		{"https://192.0.2.1/blob", false},
		{"https://192.0.2.1:443/blob", false},
		{"https://localhost/blob", false},
		{"", false},
		{"not-a-url", false},
	}
	for _, tc := range cases {
		t.Run(tc.url, func(t *testing.T) {
			err := largeattachment.ValidateURL(tc.url)
			if tc.ok && err != nil {
				t.Errorf("got %v, want nil", err)
			}
			if !tc.ok && err == nil {
				t.Error("want error, got nil")
			}
		})
	}
}

func TestItemValidateRejects(t *testing.T) {
	good := func() largeattachment.Item {
		return largeattachment.Item{
			ID:             "01JATT",
			Filename:       "notes.txt",
			MimeType:       "text/plain",
			PlaintextSize:  100,
			URL:            "https://blobs.example.com/a/abcd",
			CiphertextHash: "sha256:" + strings.Repeat("00", 32),
			AEADAlgorithm:  largeattachment.AEADChaCha20Poly1305,
			AEADNonce:      "AAAAAAAAAAAAAAAAAAAAAAA=",
		}
	}
	if err := good().Validate(); err != nil {
		t.Fatalf("good item: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(*largeattachment.Item)
	}{
		{"missing id", func(it *largeattachment.Item) { it.ID = "" }},
		{"missing filename", func(it *largeattachment.Item) { it.Filename = "" }},
		{"path separator in filename", func(it *largeattachment.Item) { it.Filename = "../../etc/passwd" }},
		{"missing mime_type", func(it *largeattachment.Item) { it.MimeType = "" }},
		{"negative plaintext size", func(it *largeattachment.Item) { it.PlaintextSize = -1 }},
		{"missing url", func(it *largeattachment.Item) { it.URL = "" }},
		{"missing ciphertext_hash", func(it *largeattachment.Item) { it.CiphertextHash = "" }},
		{"missing aead_algorithm", func(it *largeattachment.Item) { it.AEADAlgorithm = "" }},
		{"missing aead_nonce", func(it *largeattachment.Item) { it.AEADNonce = "" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			it := good()
			tc.mutate(&it)
			if err := it.Validate(); err == nil {
				t.Error("want error")
			}
		})
	}
}
