package envelope

// Decode parses a `application/semp-envelope` byte slice into an Envelope.
// The input MUST be valid UTF-8 JSON. Decode performs only structural
// validation: it checks that Type is "SEMP_ENVELOPE", that Version is
// present, and that the four required substructures (postmark, seal,
// brief, enclosure) exist. It does NOT verify the seal — callers must
// invoke seal.Verifier.VerifySignature for that.
//
// TODO(ENVELOPE.md §2.1, MIME.md §3.3): implement.
func Decode(data []byte) (*Envelope, error) {
	_ = data
	return nil, nil
}

// DecodeFile is the equivalent of Decode for `.semp` file contents. It is a
// thin alias maintained for clarity at call sites that read from disk.
func DecodeFile(data []byte) (*Envelope, error) {
	return Decode(data)
}
