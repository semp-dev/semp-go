package transport

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Framer is the message framing helper for stream-oriented transports.
// Custom transport bindings that lack native message framing MUST use
// the length-prefix scheme defined in TRANSPORT.md §7.3:
//
//	[4 bytes: message length in network byte order][message bytes]
//
// The three core bindings (ws, h2, quic) all provide their own framing
// and do not use this helper. LengthPrefix is for custom bindings like
// plain TCP, UDP-based transports that rebuild streams themselves, or
// bespoke IPC channels.
type Framer interface {
	// WriteMessage writes one length-prefixed message to w. Returns
	// an error if w.Write returns an error or if len(msg) does not
	// fit in a uint32.
	WriteMessage(w io.Writer, msg []byte) error

	// ReadMessage reads one length-prefixed message from r. Returns
	// io.EOF when the stream ends cleanly at a frame boundary.
	// Returns io.ErrUnexpectedEOF when the stream ends mid-frame.
	ReadMessage(r io.Reader) ([]byte, error)
}

// MaxEnvelopeSize is the ceiling the length-prefix framer enforces on
// a single message's length, preventing a hostile peer from tricking
// the reader into allocating gigabytes. Defaults to 25 MiB, matching
// the DISCOVERY.md §3.1 default for max_envelope_size.
const MaxEnvelopeSize = 25 * 1024 * 1024

// LengthPrefix returns a Framer implementing the TRANSPORT.md §7.3
// length-prefix scheme with the default message size ceiling. Each
// frame is a 4-byte big-endian length followed by that many bytes of
// message body.
func LengthPrefix() Framer {
	return lengthPrefix{maxEnvelopeSize: MaxEnvelopeSize}
}

// LengthPrefixWithLimit is the same as LengthPrefix but lets the
// caller set a custom message size ceiling. Values <= 0 fall back to
// MaxEnvelopeSize.
func LengthPrefixWithLimit(limit int) Framer {
	if limit <= 0 {
		limit = MaxEnvelopeSize
	}
	return lengthPrefix{maxEnvelopeSize: limit}
}

type lengthPrefix struct {
	maxEnvelopeSize int
}

// WriteMessage writes a single length-prefixed frame. The header is
// a 4-byte big-endian uint32 carrying the message length. Zero-
// length messages are permitted (they become a 4-byte header with
// length 0).
func (f lengthPrefix) WriteMessage(w io.Writer, msg []byte) error {
	if w == nil {
		return errors.New("transport: nil writer")
	}
	if int64(len(msg)) > int64(f.maxEnvelopeSize) {
		return fmt.Errorf("transport: message length %d exceeds max %d", len(msg), f.maxEnvelopeSize)
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(msg)))
	if _, err := w.Write(header[:]); err != nil {
		return fmt.Errorf("transport: write header: %w", err)
	}
	if len(msg) == 0 {
		return nil
	}
	if _, err := w.Write(msg); err != nil {
		return fmt.Errorf("transport: write body: %w", err)
	}
	return nil
}

// ReadMessage reads one complete frame from r. Returns io.EOF if r
// is at a clean frame boundary; io.ErrUnexpectedEOF if r ends
// mid-frame.
func (f lengthPrefix) ReadMessage(r io.Reader) ([]byte, error) {
	if r == nil {
		return nil, errors.New("transport: nil reader")
	}
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		if err == io.EOF {
			return nil, io.EOF
		}
		if err == io.ErrUnexpectedEOF {
			return nil, io.ErrUnexpectedEOF
		}
		return nil, fmt.Errorf("transport: read header: %w", err)
	}
	length := binary.BigEndian.Uint32(header[:])
	if int(length) > f.maxEnvelopeSize {
		return nil, fmt.Errorf("transport: incoming message length %d exceeds max %d", length, f.maxEnvelopeSize)
	}
	if length == 0 {
		return []byte{}, nil
	}
	buf := make([]byte, length)
	if _, err := io.ReadFull(r, buf); err != nil {
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return nil, io.ErrUnexpectedEOF
		}
		return nil, fmt.Errorf("transport: read body: %w", err)
	}
	return buf, nil
}
