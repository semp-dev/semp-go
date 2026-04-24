package handshake

import (
	"errors"
	"fmt"

	"semp.dev/semp-go/extensions"
)

// ChallengeInvalidError signals that an initiator received a
// non-conformant challenge and MUST abort the handshake with
// `reason_code: "challenge_invalid"` per HANDSHAKE.md section 2.2a.6.
// The handshake driver catches this error, sends the abort message,
// and then returns it to the caller.
type ChallengeInvalidError struct {
	// Reason is the human-readable detail that explains which rule the
	// issuer violated. Emitted verbatim in the abort message's
	// `reason` field.
	Reason string
}

// Error implements error. Matching the format `challenge_invalid:
// <detail>` keeps string-matching downstream paths consistent with
// the sentinel in client.go's OnChallenge rejections.
func (e *ChallengeInvalidError) Error() string {
	return "handshake: challenge_invalid: " + e.Reason
}

// IsChallengeInvalid reports whether err is (or wraps) a
// ChallengeInvalidError.
func IsChallengeInvalid(err error) bool {
	var cie *ChallengeInvalidError
	return errors.As(err, &cie)
}

// NewClientRejection produces an unsigned client-initiator abort
// message (HANDSHAKE.md section 2.2a.6). The wire form is
// party=client with no server_signature field; the initiator has not
// authenticated to the server at this point and MUST NOT do so as part
// of an abort.
//
// Use this when the client detects that a received challenge or
// response violates the protocol. Send the returned bytes on the
// handshake stream, then close the transport.
func NewClientRejection(reasonCode, reason string) ([]byte, error) {
	if reasonCode == "" {
		return nil, errors.New("handshake: empty reason_code in client rejection")
	}
	rej := Rejected{
		Type:       MessageType,
		Step:       StepRejected,
		Party:      PartyClient,
		Version:    "1.0.0",
		ReasonCode: reasonCode,
		Reason:     reason,
		Extensions: extensions.Map{},
	}
	out, err := CanonicalForHashing(&rej)
	if err != nil {
		return nil, fmt.Errorf("handshake: canonical client rejection: %w", err)
	}
	return out, nil
}
