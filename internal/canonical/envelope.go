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
// The returned Elider is safe to reuse across goroutines.
//
// TODO(ENVELOPE.md §4.3): implement once the canonical Marshal pipeline can
// hand the elider a structured map[string]any view of the envelope.
func EnvelopeElider() Elider {
	return func(value any) error {
		_ = value
		return nil
	}
}

// HandshakeMessageElider returns an Elider preconfigured for handshake
// message canonicalization. Currently it omits `server_signature` from the
// canonical form when computing the data over which that signature is
// generated. The exact field set is governed by HANDSHAKE.md §2.3 and §2.7.
//
// TODO(HANDSHAKE.md §2.5.3): finalize the elision rules for confirmation
// hash inputs.
func HandshakeMessageElider() Elider {
	return func(value any) error {
		_ = value
		return nil
	}
}
