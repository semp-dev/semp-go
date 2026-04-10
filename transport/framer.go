package transport

import "io"

// Framer is the message framing helper for stream-oriented transports.
// Custom transport bindings that lack native message framing MUST use the
// length-prefix scheme defined in TRANSPORT.md §7.3:
//
//	[4 bytes: message length in network byte order][message bytes]
//
// The three core bindings (ws, h2, quic) all provide their own framing and
// do not use this helper.
type Framer interface {
	// WriteMessage writes one length-prefixed message to w.
	WriteMessage(w io.Writer, msg []byte) error

	// ReadMessage reads one length-prefixed message from r. Returns
	// io.EOF when the stream ends cleanly.
	ReadMessage(r io.Reader) ([]byte, error)
}

// LengthPrefix returns a Framer that implements the TRANSPORT.md §7.3
// length-prefix scheme.
//
// TODO(TRANSPORT.md §7.3): implement using encoding/binary.BigEndian.
func LengthPrefix() Framer {
	return nil
}
