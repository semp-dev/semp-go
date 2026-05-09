package canonical

// EnclosureElider returns an Elider preconfigured for enclosure
// sender_signature computation per ENVELOPE.md section 6.5.2.
//
// It sets sender_signature.value to "" so the signature input does
// not depend on the signature itself, then normalizes the canonical
// shape to the form pinned by the sender-signature vector
// (VECTORS.md §17.2; ENVELOPE.md §6.5.3): every spec-required field
// MUST appear in the canonical bytes, even when empty:
//
//   - "attachments": [] (never null, never omitted)
//   - "extensions":  {} (never null, never omitted)
//   - "forwarded_from": null when absent (never omitted)
//   - "subject": "" when absent (never omitted)
//
// The normalization runs after json.Marshal but before canonical
// re-emit, so any field stripped by an `omitempty` tag on the source
// struct, or left nil during construction, is restored to the
// spec-required empty form before the signature input is computed.
// Without this step a sender that includes "extensions": {} in its
// JSON would not verify against a Go reader that round-tripped
// through a struct with omitempty, since the receiver's canonical
// bytes would be missing the field.
func EnclosureElider() Elider {
	return func(value any) error {
		root, ok := value.(map[string]any)
		if !ok {
			return nil
		}
		if sig, ok := root["sender_signature"].(map[string]any); ok {
			sig["value"] = ""
		}
		if v, ok := root["attachments"]; !ok || v == nil {
			root["attachments"] = []any{}
		}
		if v, ok := root["extensions"]; !ok || v == nil {
			root["extensions"] = map[string]any{}
		}
		if _, ok := root["forwarded_from"]; !ok {
			root["forwarded_from"] = nil
		}
		if _, ok := root["subject"]; !ok {
			root["subject"] = ""
		}
		return nil
	}
}

// ForwardedFromElider returns an Elider for the forwarder_attestation
// computation per ENVELOPE.md section 6.6. It sets
// forwarder_attestation.value to "" so the attestation input does not
// depend on the attestation itself; every other field of the
// forwarded_from block is covered.
func ForwardedFromElider() Elider {
	return func(value any) error {
		root, ok := value.(map[string]any)
		if !ok {
			return nil
		}
		if att, ok := root["forwarder_attestation"].(map[string]any); ok {
			att["value"] = ""
		}
		return nil
	}
}
