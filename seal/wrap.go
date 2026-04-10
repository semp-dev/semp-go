package seal

import (
	"github.com/semp-dev/semp-go/crypto"
	"github.com/semp-dev/semp-go/keys"
)

// Wrapper wraps and unwraps the per-envelope symmetric keys (K_brief and
// K_enclosure) under recipient public keys. Wrap is called by the sending
// client; Unwrap is called by the recipient server (for K_brief) and the
// recipient client (for K_brief and K_enclosure).
type Wrapper interface {
	// Wrap encrypts the symmetric key under the recipient's public key and
	// returns the base64-encoded wrapped result.
	Wrap(recipientPublicKey, symmetricKey []byte) (string, error)

	// Unwrap decrypts the wrapped symmetric key using the recipient's
	// private key and returns the raw symmetric key bytes.
	Unwrap(recipientPrivateKey []byte, wrapped string) ([]byte, error)
}

// NewWrapper returns a Wrapper backed by the given algorithm suite. Wrapping
// uses the suite's KEM in encapsulate mode for hybrid suites and direct DH
// for the baseline suite.
//
// TODO(ENVELOPE.md §7.1 steps 5–8): implement once crypto suites are wired up.
func NewWrapper(suite crypto.Suite) Wrapper {
	_ = suite
	return nil
}

// WrapForRecipients wraps the symmetric key under each recipient's public
// key in turn and returns the resulting RecipientMap. Used by the sending
// client to populate Seal.BriefRecipients and Seal.EnclosureRecipients.
//
// Reference: ENVELOPE.md §7.1 steps 5–8.
//
// TODO(ENVELOPE.md §7.1): implement.
func WrapForRecipients(w Wrapper, symmetricKey []byte, recipients []RecipientKey) (RecipientMap, error) {
	_, _, _ = w, symmetricKey, recipients
	return nil, nil
}

// RecipientKey identifies a recipient public key by fingerprint and provides
// the raw key bytes needed for wrapping.
type RecipientKey struct {
	Fingerprint keys.Fingerprint
	PublicKey   []byte
}
