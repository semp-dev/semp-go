package h2

// SessionStream is the long-lived POST to /v1/session/{id} that the server
// uses to push asynchronous messages to a connected client (delivery event
// notifications, server-initiated rekeying). The body is encoded as
// Server-Sent Events: each `data: <json>` line is one complete SEMP
// message, with blank lines as event delimiters.
//
// The client sends messages on the same session by issuing additional
// POSTs to the same path; the long-lived POST is one-directional
// (server → client).
//
// Reference: TRANSPORT.md §4.2.4.
type SessionStream struct {
	// SessionID is the session_id this stream is bound to.
	SessionID string
}

// WriteEvent serializes a single SEMP message as an SSE event line. The
// returned bytes include the trailing blank line that marks the end of
// the event per RFC 8895 / WHATWG SSE spec.
//
// TODO(TRANSPORT.md §4.2.4): implement.
func (s *SessionStream) WriteEvent(msg []byte) []byte {
	_, _ = s, msg
	return nil
}

// ParseEvent parses a single SSE event line group and returns the
// underlying SEMP message bytes.
//
// TODO(TRANSPORT.md §4.2.4): implement.
func ParseEvent(line []byte) ([]byte, error) {
	_ = line
	return nil, nil
}
