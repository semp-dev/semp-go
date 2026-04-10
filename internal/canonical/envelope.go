package canonical

// EnvelopeElider returns an Elider preconfigured for SEMP envelope
// canonicalization: it sets `seal.signature` and `seal.session_mac` to the
// empty string and deletes `postmark.hop_count` if present.
//
// This is the form fed into both seal signature computation and seal session
// MAC computation per ENVELOPE.md §4.3:
//
//   - seal.signature   set to ""        (so neither proof depends on the other)
//   - seal.session_mac set to ""
//   - postmark.hop_count omitted        (mutable in transit)
//
// The returned Elider is safe to reuse across goroutines because it carries
// no state.
func EnvelopeElider() Elider {
	return func(value any) error {
		root, ok := value.(map[string]any)
		if !ok {
			return nil
		}
		if seal, ok := root["seal"].(map[string]any); ok {
			seal["signature"] = ""
			seal["session_mac"] = ""
		}
		if postmark, ok := root["postmark"].(map[string]any); ok {
			delete(postmark, "hop_count")
		}
		return nil
	}
}

// HandshakeMessageElider returns an Elider preconfigured for handshake
// message canonicalization. It elides `server_signature` so that the data
// fed into signature computation does not contain the signature itself.
// Used by both message 2 (response) and message 4 (accepted/rejected) on
// the server side.
//
// Reference: HANDSHAKE.md §2.3, §2.7.
func HandshakeMessageElider() Elider {
	return func(value any) error {
		root, ok := value.(map[string]any)
		if !ok {
			return nil
		}
		delete(root, "server_signature")
		return nil
	}
}
