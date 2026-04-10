package discovery

import (
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/semp-dev/semp-go/crypto"
	"github.com/semp-dev/semp-go/internal/canonical"
	"github.com/semp-dev/semp-go/keys"
)

// canonicalResponseBytes returns the canonical JSON form of resp with
// the `signature.value` field elided. The other signature fields
// (algorithm, key_id) are preserved so an attacker can't swap them
// without invalidating the signature.
func canonicalResponseBytes(resp *Response) ([]byte, error) {
	if resp == nil {
		return nil, errors.New("discovery: nil response")
	}
	return canonical.MarshalWithElision(resp, func(v any) error {
		m, ok := v.(map[string]any)
		if !ok {
			return fmt.Errorf("discovery: expected top-level object, got %T", v)
		}
		sig, ok := m["signature"].(map[string]any)
		if !ok {
			return errors.New("discovery: response has no signature object")
		}
		sig["value"] = ""
		return nil
	})
}

// SignResponse computes an Ed25519 signature over the canonical form
// of resp with signature.value elided, then populates resp.Signature
// with the algorithm, the serving domain's key fingerprint, and the
// base64-encoded signature bytes.
//
// Reference: DISCOVERY.md §4.3, §8.1.
func SignResponse(signer crypto.Signer, privKey []byte, domainKeyID keys.Fingerprint, resp *Response) error {
	if signer == nil {
		return errors.New("discovery: nil signer")
	}
	if resp == nil {
		return errors.New("discovery: nil response")
	}
	if len(privKey) == 0 {
		return errors.New("discovery: empty signing private key")
	}
	resp.Signature.Algorithm = keys.SignatureAlgorithmEd25519
	resp.Signature.KeyID = domainKeyID
	msg, err := canonicalResponseBytes(resp)
	if err != nil {
		return fmt.Errorf("discovery: canonical response: %w", err)
	}
	sigBytes, err := signer.Sign(privKey, msg)
	if err != nil {
		return fmt.Errorf("discovery: sign response: %w", err)
	}
	resp.Signature.Value = base64.StdEncoding.EncodeToString(sigBytes)
	return nil
}

// VerifyResponse verifies resp.Signature against the given domain
// public key. Per DISCOVERY.md §8.1 the querying server MUST verify
// this signature before caching or acting on the results.
func VerifyResponse(signer crypto.Signer, resp *Response, domainPub []byte) error {
	if signer == nil {
		return errors.New("discovery: nil signer")
	}
	if resp == nil {
		return errors.New("discovery: nil response")
	}
	if resp.Signature.Value == "" {
		return errors.New("discovery: response is unsigned")
	}
	if len(domainPub) == 0 {
		return errors.New("discovery: empty domain public key")
	}
	sigBytes, err := base64.StdEncoding.DecodeString(resp.Signature.Value)
	if err != nil {
		return fmt.Errorf("discovery: signature base64: %w", err)
	}
	msg, err := canonicalResponseBytes(resp)
	if err != nil {
		return fmt.Errorf("discovery: canonical response: %w", err)
	}
	if err := signer.Verify(domainPub, msg, sigBytes); err != nil {
		return fmt.Errorf("discovery: verify response signature: %w", err)
	}
	return nil
}
