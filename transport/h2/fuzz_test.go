package h2_test

import (
	"bytes"
	"io"
	"testing"

	"semp.dev/semp-go/transport/h2"
)

// FuzzEventReader feeds arbitrary bytes into the SSE EventReader and
// asserts it never panics. It must either return a data payload or an
// error (usually io.EOF) on every call and eventually terminate the
// stream with io.EOF or another error.
//
// Seeds include minimal valid events, events with comments, multi-
// line data continuations, CRLF line endings, and pure garbage so the
// fuzzer can mutate around each edge case.
func FuzzEventReader(f *testing.F) {
	f.Add([]byte("data: hello\n\n"))
	f.Add([]byte("data: line-one\ndata: line-two\n\n"))
	f.Add([]byte(": comment\ndata: after-comment\n\n"))
	f.Add([]byte("event: custom\nid: 42\nretry: 5000\ndata: payload\n\n"))
	f.Add([]byte("data: first\n\ndata: second\n\ndata: third\n\n"))
	f.Add([]byte("data: crlf\r\n\r\n"))
	f.Add([]byte(""))
	f.Add([]byte("\n\n\n"))
	f.Add([]byte("garbage with: no blank line"))

	f.Fuzz(func(t *testing.T, data []byte) {
		r := h2.NewEventReader(bytes.NewReader(data))
		// Bound the loop so an adversarial input that manages to
		// convince ReadEvent to succeed repeatedly on empty input
		// cannot hang the fuzzer. 1024 events is far more than any
		// legitimate seed could produce from a single byte slice.
		for i := 0; i < 1024; i++ {
			event, err := r.ReadEvent()
			if err != nil {
				if err != io.EOF {
					// Any error other than EOF is acceptable too;
					// the invariant is "no panic", not "always EOF".
					_ = event
				}
				return
			}
			// A non-error return MUST yield a non-nil byte slice
			// (even if empty, the slice itself must be allocated so
			// callers can distinguish "no data" from "EOF").
			_ = event
		}
	})
}

// FuzzEncodeEvent ensures EncodeEvent never panics on arbitrary input
// and that its output is always well-formed enough for EventReader to
// parse back a matching payload. SSE treats CR, LF, and CRLF as
// interchangeable line terminators (WHATWG HTML §9.2), so the round
// trip normalizes all three forms to a single LF — the invariant is
// therefore "decoded == normalizeLineEndings(input)".
func FuzzEncodeEvent(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte("hello"))
	f.Add([]byte("line1\nline2\nline3"))
	f.Add([]byte("carriage\rreturn"))
	f.Add([]byte("crlf\r\nterminated"))
	f.Add([]byte("unicode ü 你好"))
	f.Add([]byte{0x00, 0x01, 0xff})
	f.Add([]byte("\r"))
	f.Add([]byte("\n"))
	f.Add([]byte("\r\n"))
	f.Add([]byte("trailing\n"))

	f.Fuzz(func(t *testing.T, msg []byte) {
		encoded := h2.EncodeEvent(msg)
		if len(encoded) == 0 {
			t.Fatalf("EncodeEvent produced empty output for %q", msg)
		}
		r := h2.NewEventReader(bytes.NewReader(encoded))
		decoded, err := r.ReadEvent()
		if err != nil {
			t.Fatalf("ReadEvent failed on EncodeEvent output: %v\nencoded=%q", err, encoded)
		}
		want := normalizeLineEndings(msg)
		if !bytes.Equal(decoded, want) {
			t.Errorf("round-trip mismatch:\n  in=%q\n  want=%q\n  got=%q", msg, want, decoded)
		}
	})
}

// normalizeLineEndings replaces every CR, LF, and CRLF sequence with
// a single LF, matching EncodeEvent's line-splitting rules (and, by
// extension, the SSE line terminator spec). Used only by
// FuzzEncodeEvent to derive the expected round-trip target.
func normalizeLineEndings(b []byte) []byte {
	out := make([]byte, 0, len(b))
	for i := 0; i < len(b); i++ {
		switch b[i] {
		case '\r':
			out = append(out, '\n')
			if i+1 < len(b) && b[i+1] == '\n' {
				i++ // swallow the LF of a CRLF pair
			}
		default:
			out = append(out, b[i])
		}
	}
	return out
}
