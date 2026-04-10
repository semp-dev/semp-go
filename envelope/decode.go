package envelope

import (
	"encoding/json"
	"fmt"
)

// Decode parses a UTF-8 JSON byte slice into an Envelope. The input MUST
// have the application/semp-envelope content type.
//
// Decode performs only structural validation:
//
//   - Type MUST be "SEMP_ENVELOPE".
//   - Version MUST be present and non-empty.
//   - Postmark, Seal, Brief, and Enclosure MUST be present.
//
// Decode does NOT verify the seal — callers must invoke
// seal.Verifier.VerifySignature (and VerifySessionMAC for receiving
// servers) on the result before trusting any field.
//
// Reference: ENVELOPE.md §2.1, MIME.md §3.3.
func Decode(data []byte) (*Envelope, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("envelope: empty input")
	}
	var e Envelope
	if err := json.Unmarshal(data, &e); err != nil {
		return nil, fmt.Errorf("envelope: parse: %w", err)
	}
	if e.Type != MessageType {
		return nil, fmt.Errorf("envelope: wrong type %q, want %q", e.Type, MessageType)
	}
	if e.Version == "" {
		return nil, fmt.Errorf("envelope: missing version")
	}
	if e.Brief == "" {
		return nil, fmt.Errorf("envelope: missing brief")
	}
	if e.Enclosure == "" {
		return nil, fmt.Errorf("envelope: missing enclosure")
	}
	if e.Postmark.SessionID == "" {
		return nil, fmt.Errorf("envelope: missing postmark.session_id")
	}
	return &e, nil
}

// DecodeFile is the equivalent of Decode for `.semp` file contents. It is a
// thin alias maintained for clarity at call sites that read from disk.
func DecodeFile(data []byte) (*Envelope, error) {
	return Decode(data)
}
