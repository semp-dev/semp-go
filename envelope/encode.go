package envelope

// Encode returns the wire serialization of the envelope as a UTF-8 JSON
// byte slice with `application/semp-envelope` content type. The output is
// suitable for transmission over any SEMP transport and for storage as a
// `.semp` file.
//
// Encode does not produce the canonical form. Use CanonicalBytes for the
// byte stream consumed by signature and MAC computation; use Encode for
// transport.
//
// Reference: ENVELOPE.md §2.1, MIME.md §2.2.
//
// TODO(MIME.md §2.2): implement using encoding/json with deterministic
// pretty-printing disabled.
func Encode(e *Envelope) ([]byte, error) {
	_ = e
	return nil, nil
}

// EncodeFile returns the byte slice suitable for writing to a `.semp` file.
// The output is the same as Encode (one envelope per file, UTF-8 JSON, no
// BOM) per MIME.md §2.2.
func EncodeFile(e *Envelope) ([]byte, error) {
	return Encode(e)
}
