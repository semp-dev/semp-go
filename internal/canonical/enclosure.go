package canonical

// EnclosureElider returns an Elider preconfigured for enclosure
// sender_signature computation per ENVELOPE.md section 6.5.2.
//
// It sets sender_signature.value to "" so the signature input does
// not depend on the signature itself. All other fields of the
// enclosure (subject, content_type, body, attachments, forwarded_from,
// extensions) are covered by the signature, matching the spec's
// "every other field is covered" rule.
func EnclosureElider() Elider {
	return func(value any) error {
		root, ok := value.(map[string]any)
		if !ok {
			return nil
		}
		if sig, ok := root["sender_signature"].(map[string]any); ok {
			sig["value"] = ""
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
