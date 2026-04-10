package handshake

import (
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/semp-dev/semp-go/crypto"
	"github.com/semp-dev/semp-go/internal/canonical"
)

// canonicalElidingField returns the canonical bytes of msg with the named
// top-level string field set to the empty string. This is the input fed to
// signature computation and verification for handshake messages that carry a
// `server_signature` field.
//
// The elision is performed on a deep-copy of the JSON-serialized form of msg,
// so the caller's struct value is not mutated.
func canonicalElidingField(msg any, field string) ([]byte, error) {
	return canonical.MarshalWithElision(msg, func(value any) error {
		m, ok := value.(map[string]any)
		if !ok {
			return fmt.Errorf("handshake: top-level value is not a JSON object (got %T)", value)
		}
		if _, has := m[field]; has {
			m[field] = ""
		}
		return nil
	})
}

// CanonicalForHashing returns the canonical bytes of msg, including any
// populated `server_signature` field. Used to compute the bytes that feed
// into the confirmation hash on the receiving side of a handshake.
func CanonicalForHashing(msg any) ([]byte, error) {
	return canonical.Marshal(msg)
}

// SignServerMessage computes the server's domain-key signature over the
// canonical form of msg with `server_signature` elided to "". The returned
// signature is the base64 string the caller stores back into msg's
// ServerSignature field.
//
// suite supplies the signing primitive (Ed25519 for both currently defined
// SEMP suites). domainPrivateKey is the server's long-term private key.
func SignServerMessage(suite crypto.Suite, domainPrivateKey []byte, msg any) (string, error) {
	if suite == nil {
		return "", errors.New("handshake: nil suite")
	}
	if len(domainPrivateKey) == 0 {
		return "", errors.New("handshake: missing domain private key")
	}
	canonicalBytes, err := canonicalElidingField(msg, "server_signature")
	if err != nil {
		return "", fmt.Errorf("handshake: canonical bytes: %w", err)
	}
	sig, err := suite.Signer().Sign(domainPrivateKey, canonicalBytes)
	if err != nil {
		return "", fmt.Errorf("handshake: sign: %w", err)
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}

// VerifyServerMessage verifies the server's domain-key signature over msg.
// The signature value is read from msg's `server_signature` field
// (signatureB64), then the field is elided to "" before re-canonicalization
// and verification.
func VerifyServerMessage(suite crypto.Suite, domainPublicKey []byte, msg any, signatureB64 string) error {
	if suite == nil {
		return errors.New("handshake: nil suite")
	}
	if len(domainPublicKey) == 0 {
		return errors.New("handshake: missing domain public key")
	}
	if signatureB64 == "" {
		return errors.New("handshake: empty server_signature")
	}
	sig, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return fmt.Errorf("handshake: server_signature base64: %w", err)
	}
	canonicalBytes, err := canonicalElidingField(msg, "server_signature")
	if err != nil {
		return fmt.Errorf("handshake: canonical bytes: %w", err)
	}
	if err := suite.Signer().Verify(domainPublicKey, canonicalBytes, sig); err != nil {
		return fmt.Errorf("handshake: server signature verify: %w", err)
	}
	return nil
}
