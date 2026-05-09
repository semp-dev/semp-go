package canonical

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
)

// Marshal returns the canonical JSON serialization of v.
//
// Canonicalization rules (ENVELOPE.md §4.3):
//
//  1. UTF-8 encoded JSON.
//  2. Object keys sorted lexicographically by their byte values at every
//     level of nesting.
//  3. No insignificant whitespace.
//  4. Numbers serialized in their shortest unambiguous form (encoding/json's
//     default float formatting; SEMP envelopes carry no numbers that depend
//     on the stricter RFC 8785 rules, so this is sufficient for v0.1.0).
//  5. Strings escaped per RFC 8259 (encoding/json's default).
//
// Marshal does not perform field elision. Callers that need to zero out
// `seal.signature` / `seal.session_mac` or strip `postmark.hop_count` from
// the canonical form should use MarshalWithElision.
//
// Implementation note: the function marshals v with encoding/json, parses
// the result back into a generic value, and re-emits it with sorted keys.
// This is the JCS-style approach used by github.com/gowebpki/jcs and many
// other implementations. It is correct for any value that round-trips
// through encoding/json.
//
// TODO(VECTORS.md §3): if we ever ship a number whose float64 round-trip
// is lossy (e.g. very large integers > 2^53) we will need a strict number
// formatter. Today's SEMP envelopes do not contain any such numbers.
func Marshal(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("canonical: pre-marshal: %w", err)
	}
	var generic any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&generic); err != nil {
		return nil, fmt.Errorf("canonical: re-parse: %w", err)
	}
	var buf bytes.Buffer
	if err := writeValue(&buf, generic); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Elider is a callback that lets a caller mutate a value before it is
// canonicalized. Elider is invoked exactly once on a deep copy of the input,
// allowing safe in-place mutation of map[string]any / []any structures.
//
// The seal signer uses an Elider to set seal.signature and seal.session_mac
// to the empty string and to remove postmark.hop_count from the value before
// canonicalization, per ENVELOPE.md §4.3.
type Elider func(value any) error

// MarshalWithElision applies elide to a deep copy of v, then returns the
// canonical serialization of the modified copy. The original v is not
// touched.
func MarshalWithElision(v any, elide Elider) ([]byte, error) {
	if elide == nil {
		return Marshal(v)
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("canonical: pre-marshal: %w", err)
	}
	var generic any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&generic); err != nil {
		return nil, fmt.Errorf("canonical: re-parse: %w", err)
	}
	if err := elide(generic); err != nil {
		return nil, fmt.Errorf("canonical: elide: %w", err)
	}
	var buf bytes.Buffer
	if err := writeValue(&buf, generic); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Hash returns SHA-256(b). It is the digest used by every SEMP signature
// or MAC computed over canonical bytes (seal.signature input, seal.session_mac
// input, handshake confirmation hash, discovery response signature digest).
func Hash(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}

// writeValue serializes v in canonical form to buf. v must be one of the
// types produced by json.Decoder.UseNumber+Decode: nil, bool, json.Number,
// string, []any, or map[string]any.
func writeValue(buf *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case nil:
		buf.WriteString("null")
		return nil
	case bool:
		if x {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
		return nil
	case json.Number:
		buf.WriteString(string(x))
		return nil
	case string:
		return writeString(buf, x)
	case []any:
		buf.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeValue(buf, e); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
		return nil
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeString(buf, k); err != nil {
				return err
			}
			buf.WriteByte(':')
			if err := writeValue(buf, x[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
		return nil
	default:
		return fmt.Errorf("canonical: unsupported value type %T", v)
	}
}

// writeString writes a JSON string literal for s using encoding/json's
// own escaping. We re-use json.Marshal here so that the escape rules
// (Unicode escapes for control characters, backslash for special chars)
// match the rest of the Go ecosystem and the wire format produced by
// json.Marshal elsewhere in semp-go.
func writeString(buf *bytes.Buffer, s string) error {
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	buf.Write(b)
	return nil
}
