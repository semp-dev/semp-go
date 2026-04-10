package transport_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/semp-dev/semp-go/transport"
)

// TestLengthPrefixRoundTrip writes three messages into a buffer with
// the length-prefix framer and reads them back, confirming each frame
// boundary is honored.
func TestLengthPrefixRoundTrip(t *testing.T) {
	framer := transport.LengthPrefix()
	messages := [][]byte{
		[]byte(`{"type":"SEMP_HANDSHAKE","step":"init"}`),
		[]byte(`{"a":1}`),
		[]byte(strings.Repeat("A", 4096)), // large-ish
	}
	var buf bytes.Buffer
	for _, msg := range messages {
		if err := framer.WriteMessage(&buf, msg); err != nil {
			t.Fatalf("WriteMessage: %v", err)
		}
	}
	for i, want := range messages {
		got, err := framer.ReadMessage(&buf)
		if err != nil {
			t.Fatalf("ReadMessage[%d]: %v", i, err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("ReadMessage[%d] = %q, want %q", i, got, want)
		}
	}
	// Clean EOF at a frame boundary.
	if _, err := framer.ReadMessage(&buf); err != io.EOF {
		t.Errorf("final ReadMessage = %v, want io.EOF", err)
	}
}

// TestLengthPrefixEmptyMessage confirms that a zero-length message
// round-trips as a valid frame rather than being elided or rejected.
func TestLengthPrefixEmptyMessage(t *testing.T) {
	framer := transport.LengthPrefix()
	var buf bytes.Buffer
	if err := framer.WriteMessage(&buf, nil); err != nil {
		t.Fatalf("WriteMessage(nil): %v", err)
	}
	if buf.Len() != 4 {
		t.Errorf("empty message should produce a 4-byte header, got %d bytes", buf.Len())
	}
	got, err := framer.ReadMessage(&buf)
	if err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("ReadMessage returned %d bytes, want 0", len(got))
	}
}

// TestLengthPrefixTruncatedHeader confirms that a stream whose
// header is cut short returns io.ErrUnexpectedEOF (not io.EOF).
func TestLengthPrefixTruncatedHeader(t *testing.T) {
	framer := transport.LengthPrefix()
	// Two bytes of a 4-byte header.
	buf := bytes.NewReader([]byte{0x00, 0x00})
	_, err := framer.ReadMessage(buf)
	if err != io.ErrUnexpectedEOF {
		t.Errorf("got %v, want io.ErrUnexpectedEOF", err)
	}
}

// TestLengthPrefixTruncatedBody confirms that a complete header
// followed by a short body returns io.ErrUnexpectedEOF.
func TestLengthPrefixTruncatedBody(t *testing.T) {
	framer := transport.LengthPrefix()
	// Header says 10 bytes, body provides 4.
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], 10)
	buf := bytes.NewReader(append(header[:], []byte("abcd")...))
	_, err := framer.ReadMessage(buf)
	if err != io.ErrUnexpectedEOF {
		t.Errorf("got %v, want io.ErrUnexpectedEOF", err)
	}
}

// TestLengthPrefixOversizedWrite confirms that writing a message
// larger than the framer's limit returns an error without writing
// anything to the underlying writer.
func TestLengthPrefixOversizedWrite(t *testing.T) {
	framer := transport.LengthPrefixWithLimit(16)
	var buf bytes.Buffer
	err := framer.WriteMessage(&buf, make([]byte, 17))
	if err == nil {
		t.Fatal("expected error for oversized message, got nil")
	}
	if !strings.Contains(err.Error(), "exceeds max") {
		t.Errorf("error should mention the size limit: %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("writer should be empty after rejected write, got %d bytes", buf.Len())
	}
}

// TestLengthPrefixOversizedRead confirms that a header claiming more
// bytes than the framer's limit is rejected without allocating a
// huge buffer.
func TestLengthPrefixOversizedRead(t *testing.T) {
	framer := transport.LengthPrefixWithLimit(100)
	var header [4]byte
	// Claim 1 MiB.
	binary.BigEndian.PutUint32(header[:], 1024*1024)
	buf := bytes.NewReader(header[:])
	_, err := framer.ReadMessage(buf)
	if err == nil {
		t.Fatal("expected error for oversized header, got nil")
	}
	if !strings.Contains(err.Error(), "exceeds max") {
		t.Errorf("error should mention the size limit: %v", err)
	}
}

// TestLengthPrefixNilArgs covers defensive nil-pointer handling.
func TestLengthPrefixNilArgs(t *testing.T) {
	framer := transport.LengthPrefix()
	if err := framer.WriteMessage(nil, []byte("x")); err == nil {
		t.Error("WriteMessage(nil writer) should error")
	}
	if _, err := framer.ReadMessage(nil); err == nil {
		t.Error("ReadMessage(nil reader) should error")
	}
}

// TestLengthPrefixWithLimitZeroFallsBack confirms that a zero or
// negative limit falls back to MaxMessageSize.
func TestLengthPrefixWithLimitZeroFallsBack(t *testing.T) {
	framer := transport.LengthPrefixWithLimit(0)
	// Writing a reasonable-sized message should succeed, proving
	// the limit fell back to the default (not zero).
	var buf bytes.Buffer
	if err := framer.WriteMessage(&buf, []byte("hello")); err != nil {
		t.Errorf("WriteMessage with fallback limit: %v", err)
	}
}

// TestLengthPrefixWrapsWriteErrors confirms that an underlying
// io.Writer error is wrapped (not swallowed) by WriteMessage.
func TestLengthPrefixWrapsWriteErrors(t *testing.T) {
	framer := transport.LengthPrefix()
	w := &errWriter{err: errors.New("disk full")}
	err := framer.WriteMessage(w, []byte("x"))
	if err == nil || !strings.Contains(err.Error(), "disk full") {
		t.Errorf("expected wrapped 'disk full' error, got: %v", err)
	}
}

// errWriter is an io.Writer that always returns a fixed error.
type errWriter struct{ err error }

func (e *errWriter) Write(_ []byte) (int, error) { return 0, e.err }
