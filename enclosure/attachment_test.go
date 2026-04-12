package enclosure_test

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"semp.dev/semp-go/enclosure"
)

// -----------------------------------------------------------------------------
// ComputeHash + ParseHash
// -----------------------------------------------------------------------------

// TestComputeHashSHA256MatchesStdlib confirms the default algorithm
// is sha256 and that its output matches crypto/sha256 byte-for-byte.
// If this test breaks, either the algorithm changed or the wire
// format is wrong — both are big deals.
func TestComputeHashSHA256MatchesStdlib(t *testing.T) {
	plaintext := []byte("The quick brown fox jumps over the lazy dog.")
	tag, err := enclosure.ComputeHash("", plaintext)
	if err != nil {
		t.Fatalf("ComputeHash: %v", err)
	}
	want := sha256.Sum256(plaintext)
	wantTag := "sha256:" + hex.EncodeToString(want[:])
	if tag != wantTag {
		t.Errorf("ComputeHash = %q, want %q", tag, wantTag)
	}
}

// TestComputeHashExplicitSHA512 confirms the optional stronger
// algorithm is wired up and that the returned tag uses the correct
// prefix.
func TestComputeHashExplicitSHA512(t *testing.T) {
	plaintext := []byte("payload")
	tag, err := enclosure.ComputeHash(enclosure.HashAlgorithmSHA512, plaintext)
	if err != nil {
		t.Fatalf("ComputeHash: %v", err)
	}
	want := sha512.Sum512(plaintext)
	wantTag := "sha512:" + hex.EncodeToString(want[:])
	if tag != wantTag {
		t.Errorf("ComputeHash sha512 = %q, want %q", tag, wantTag)
	}
}

// TestComputeHashRejectsUnknownAlgorithm confirms the forward-
// compatibility guard.
func TestComputeHashRejectsUnknownAlgorithm(t *testing.T) {
	_, err := enclosure.ComputeHash("sha3-512", []byte("x"))
	if err == nil {
		t.Error("ComputeHash with unknown algorithm should error")
	}
}

// TestComputeHashReaderMatchesComputeHash confirms the streaming
// variant produces the same output as the all-in-memory variant.
func TestComputeHashReaderMatchesComputeHash(t *testing.T) {
	plaintext := bytes.Repeat([]byte("abcdefghij"), 1024) // 10 KiB
	inMem, err := enclosure.ComputeHash("", plaintext)
	if err != nil {
		t.Fatalf("ComputeHash: %v", err)
	}
	stream, size, err := enclosure.ComputeHashReader("", bytes.NewReader(plaintext))
	if err != nil {
		t.Fatalf("ComputeHashReader: %v", err)
	}
	if stream != inMem {
		t.Errorf("streaming hash = %q, want %q", stream, inMem)
	}
	if size != int64(len(plaintext)) {
		t.Errorf("streaming size = %d, want %d", size, len(plaintext))
	}
}

// TestComputeHashReaderNilReader confirms nil input is rejected
// rather than panicking.
func TestComputeHashReaderNilReader(t *testing.T) {
	_, _, err := enclosure.ComputeHashReader("sha256", nil)
	if err == nil {
		t.Error("nil reader should return an error")
	}
}

// TestParseHashValidInputs confirms ParseHash extracts both fields
// correctly for well-formed inputs.
func TestParseHashValidInputs(t *testing.T) {
	tests := []struct {
		in      string
		algo    string
		hexWant string
	}{
		{"sha256:abc123", "sha256", "abc123"},
		{"SHA256:ABCD", "sha256", "ABCD"}, // algorithm lowercased; hex preserved verbatim
		{"sha512:00112233445566778899aabbccddeeff", "sha512", "00112233445566778899aabbccddeeff"},
	}
	for _, tc := range tests {
		algo, hx, err := enclosure.ParseHash(tc.in)
		if err != nil {
			t.Errorf("ParseHash(%q): %v", tc.in, err)
			continue
		}
		if algo != tc.algo {
			t.Errorf("ParseHash(%q) algo = %q, want %q", tc.in, algo, tc.algo)
		}
		if hx != tc.hexWant {
			t.Errorf("ParseHash(%q) hex = %q, want %q", tc.in, hx, tc.hexWant)
		}
	}
}

// TestParseHashRejectsMalformed confirms the error paths.
func TestParseHashRejectsMalformed(t *testing.T) {
	bad := []string{
		"",
		"sha256",       // no colon
		":abc123",      // empty algorithm
		"sha256:",      // empty hex
		"sha256:zzzz",  // non-hex
		"sha256:abc12", // odd-length hex (Go's hex.DecodeString rejects)
	}
	for _, in := range bad {
		if _, _, err := enclosure.ParseHash(in); err == nil {
			t.Errorf("ParseHash(%q) = nil, want error", in)
		}
	}
}

// -----------------------------------------------------------------------------
// Attachment.VerifyHash
// -----------------------------------------------------------------------------

// TestVerifyHashHappyPath confirms a hash computed by ComputeHash
// verifies cleanly against the same bytes.
func TestVerifyHashHappyPath(t *testing.T) {
	plaintext := []byte("some attachment contents")
	tag, _ := enclosure.ComputeHash("", plaintext)
	a := &enclosure.Attachment{Hash: tag}
	if err := a.VerifyHash(plaintext); err != nil {
		t.Errorf("VerifyHash: %v", err)
	}
}

// TestVerifyHashRejectsTamper confirms a single-bit flip in the
// plaintext causes the hash check to fail.
func TestVerifyHashRejectsTamper(t *testing.T) {
	plaintext := []byte("some attachment contents")
	tag, _ := enclosure.ComputeHash("", plaintext)
	a := &enclosure.Attachment{Hash: tag}
	tampered := append([]byte{}, plaintext...)
	tampered[0] ^= 0x01
	if err := a.VerifyHash(tampered); err == nil {
		t.Error("VerifyHash should reject tampered plaintext")
	}
}

// TestVerifyHashEmptyHash returns an error for an attachment that
// has no hash set.
func TestVerifyHashEmptyHash(t *testing.T) {
	a := &enclosure.Attachment{}
	if err := a.VerifyHash([]byte("x")); err == nil {
		t.Error("VerifyHash on attachment with no hash should error")
	}
}

// TestVerifyHashNilAttachment confirms nil-safety.
func TestVerifyHashNilAttachment(t *testing.T) {
	var a *enclosure.Attachment
	if err := a.VerifyHash([]byte("x")); err == nil {
		t.Error("VerifyHash on nil attachment should error")
	}
}

// TestVerifyHashUnknownAlgorithm returns an error for an attachment
// whose hash tag advertises an algorithm we don't support.
func TestVerifyHashUnknownAlgorithm(t *testing.T) {
	a := &enclosure.Attachment{
		Hash: "sha3-256:abc123",
	}
	if err := a.VerifyHash([]byte("x")); err == nil {
		t.Error("VerifyHash with unknown algorithm should error")
	}
}

// -----------------------------------------------------------------------------
// NewAttachment + Plaintext round-trip
// -----------------------------------------------------------------------------

// TestNewAttachmentPopulatesFields confirms the convenience
// constructor sets every wire-level field and produces a tag that
// VerifyHash accepts.
func TestNewAttachmentPopulatesFields(t *testing.T) {
	plaintext := []byte("PDF bytes goes here")
	a, err := enclosure.NewAttachment("01JATTACHMENT0001", "report.pdf", "application/pdf", "", plaintext)
	if err != nil {
		t.Fatalf("NewAttachment: %v", err)
	}
	if a.ID != "01JATTACHMENT0001" {
		t.Errorf("ID = %q, want 01JATTACHMENT0001", a.ID)
	}
	if a.Filename != "report.pdf" {
		t.Errorf("Filename = %q, want report.pdf", a.Filename)
	}
	if a.MimeType != "application/pdf" {
		t.Errorf("MimeType = %q, want application/pdf", a.MimeType)
	}
	if a.Size != int64(len(plaintext)) {
		t.Errorf("Size = %d, want %d", a.Size, len(plaintext))
	}
	if !strings.HasPrefix(a.Hash, "sha256:") {
		t.Errorf("Hash = %q, want sha256: prefix", a.Hash)
	}
	// Content should base64-decode back to the original plaintext.
	decoded, err := base64.StdEncoding.DecodeString(a.Content)
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}
	if !bytes.Equal(decoded, plaintext) {
		t.Error("decoded content does not match plaintext")
	}
	// Hash should verify against the original plaintext.
	if err := a.VerifyHash(plaintext); err != nil {
		t.Errorf("VerifyHash: %v", err)
	}
}

// TestNewAttachmentExplicitSHA512 confirms the algorithm parameter
// is honored.
func TestNewAttachmentExplicitSHA512(t *testing.T) {
	a, err := enclosure.NewAttachment("id1", "file.txt", "text/plain", enclosure.HashAlgorithmSHA512, []byte("x"))
	if err != nil {
		t.Fatalf("NewAttachment: %v", err)
	}
	if !strings.HasPrefix(a.Hash, "sha512:") {
		t.Errorf("Hash = %q, want sha512: prefix", a.Hash)
	}
}

// TestNewAttachmentValidation confirms the required-field checks.
func TestNewAttachmentValidation(t *testing.T) {
	tests := []struct {
		name                 string
		id, filename, mime   string
	}{
		{"empty id", "", "f.txt", "text/plain"},
		{"empty filename", "id", "", "text/plain"},
		{"empty mime", "id", "f.txt", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := enclosure.NewAttachment(tc.id, tc.filename, tc.mime, "", []byte("x")); err == nil {
				t.Errorf("NewAttachment(%s) should have errored", tc.name)
			}
		})
	}
}

// TestNewAttachmentRejectsOversized confirms the size cap is enforced.
func TestNewAttachmentRejectsOversized(t *testing.T) {
	huge := make([]byte, enclosure.MaxAttachmentBytes+1)
	_, err := enclosure.NewAttachment("id", "f.bin", "application/octet-stream", "", huge)
	if err == nil {
		t.Error("NewAttachment with oversized plaintext should error")
	}
}

// TestPlaintextRoundTrip confirms Plaintext returns the original
// bytes and passes the integrity check.
func TestPlaintextRoundTrip(t *testing.T) {
	original := []byte("round-trip attachment content")
	a, err := enclosure.NewAttachment("id", "file.txt", "text/plain", "", original)
	if err != nil {
		t.Fatalf("NewAttachment: %v", err)
	}
	got, err := a.Plaintext()
	if err != nil {
		t.Fatalf("Plaintext: %v", err)
	}
	if !bytes.Equal(got, original) {
		t.Errorf("Plaintext = %q, want %q", got, original)
	}
}

// TestPlaintextRejectsTamperedContent confirms that mutating the
// Content field after NewAttachment causes Plaintext to fail.
func TestPlaintextRejectsTamperedContent(t *testing.T) {
	a, _ := enclosure.NewAttachment("id", "file.txt", "text/plain", "", []byte("original bytes"))
	// Replace Content with a base64 encoding of different bytes.
	a.Content = base64.StdEncoding.EncodeToString([]byte("attacker bytes"))
	_, err := a.Plaintext()
	if err == nil {
		t.Error("Plaintext should reject content that doesn't match stored hash")
	}
}

// TestPlaintextRejectsTamperedHash confirms that mutating the Hash
// field to a new valid tag that doesn't match the Content causes
// Plaintext to fail.
func TestPlaintextRejectsTamperedHash(t *testing.T) {
	a, _ := enclosure.NewAttachment("id", "file.txt", "text/plain", "", []byte("original bytes"))
	// Recompute a hash over DIFFERENT bytes and inject it.
	forged, _ := enclosure.ComputeHash("", []byte("attacker bytes"))
	a.Hash = forged
	_, err := a.Plaintext()
	if err == nil {
		t.Error("Plaintext should reject hash that doesn't match content")
	}
}

// TestPlaintextRejectsEmptyContent confirms a blank Content field
// is rejected.
func TestPlaintextRejectsEmptyContent(t *testing.T) {
	a := &enclosure.Attachment{
		ID:      "id",
		Hash:    "sha256:00",
		Content: "",
	}
	if _, err := a.Plaintext(); err == nil {
		t.Error("Plaintext on empty content should error")
	}
}

// TestPlaintextRejectsBadBase64 confirms a malformed Content field
// produces a descriptive error.
func TestPlaintextRejectsBadBase64(t *testing.T) {
	a := &enclosure.Attachment{
		Hash:    "sha256:abc",
		Content: "!!!not base64!!!",
	}
	if _, err := a.Plaintext(); err == nil {
		t.Error("Plaintext on invalid base64 should error")
	}
}

// TestPlaintextRejectsSizeMismatch confirms Plaintext catches a
// header that claims a different size than the decoded bytes.
func TestPlaintextRejectsSizeMismatch(t *testing.T) {
	a, _ := enclosure.NewAttachment("id", "file.txt", "text/plain", "", []byte("original"))
	a.Size = 9999
	if _, err := a.Plaintext(); err == nil {
		t.Error("Plaintext should reject size mismatch")
	}
}

// TestComputeHashReaderLargeFile exercises a 1 MiB streaming hash
// through bytes.NewReader and confirms it matches the in-memory
// computation.
func TestComputeHashReaderLargeFile(t *testing.T) {
	plaintext := make([]byte, 1<<20)
	for i := range plaintext {
		plaintext[i] = byte(i % 251)
	}
	inMem, err := enclosure.ComputeHash("", plaintext)
	if err != nil {
		t.Fatalf("ComputeHash: %v", err)
	}
	stream, size, err := enclosure.ComputeHashReader("", bytes.NewReader(plaintext))
	if err != nil {
		t.Fatalf("ComputeHashReader: %v", err)
	}
	if stream != inMem {
		t.Errorf("streaming hash differs from in-memory hash")
	}
	if size != int64(len(plaintext)) {
		t.Errorf("streaming size = %d, want %d", size, len(plaintext))
	}
}
