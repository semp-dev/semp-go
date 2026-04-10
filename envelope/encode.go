package envelope

import (
	"encoding/json"
	"fmt"
)

// Encode returns the wire serialization of the envelope as a UTF-8 JSON
// byte slice. The output is suitable for transmission over any SEMP
// transport (Content-Type: application/semp-envelope) and for storage as
// a `.semp` file.
//
// Encode does not produce the canonical form. Use CanonicalBytes for the
// byte stream consumed by signature and MAC computation; use Encode for
// transport.
//
// Reference: ENVELOPE.md §2.1, MIME.md §2.2.
func Encode(e *Envelope) ([]byte, error) {
	if e == nil {
		return nil, fmt.Errorf("envelope: cannot encode nil envelope")
	}
	return json.Marshal(e)
}

// EncodeFile returns the byte slice suitable for writing to a `.semp` file.
// MIME.md §2.2 specifies one envelope per file, UTF-8 JSON, no BOM, no
// trailing newline. Encode already satisfies these requirements.
func EncodeFile(e *Envelope) ([]byte, error) {
	return Encode(e)
}
