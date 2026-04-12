package keys

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"semp.dev/semp-go/crypto"
	"semp.dev/semp-go/internal/canonical"
)

// canonicalDeviceCertificateBytes returns the canonical JSON form of
// cert with the `signature.value` field elided (the rest of the
// `signature` object — algorithm and key_id — is covered so that an
// attacker can't downgrade the signing algorithm or forge a different
// issuer). The `signature.value` field is the output of the signing
// operation itself; it's the only piece that must be excluded from
// the canonical bytes.
func canonicalDeviceCertificateBytes(cert *DeviceCertificate) ([]byte, error) {
	if cert == nil {
		return nil, errors.New("keys: nil device certificate")
	}
	return canonical.MarshalWithElision(cert, func(v any) error {
		m, ok := v.(map[string]any)
		if !ok {
			return fmt.Errorf("keys: expected top-level object, got %T", v)
		}
		sig, ok := m["signature"].(map[string]any)
		if !ok {
			return errors.New("keys: device certificate has no signature object")
		}
		sig["value"] = ""
		return nil
	})
}

// SignDeviceCertificate computes an Ed25519 signature over the
// canonical form of cert with signature.value elided, then populates
// cert.Signature with the algorithm, the issuing device's key ID,
// and the base64 of the signature bytes. The caller supplies the
// issuing device's PRIVATE key; the matching public key MUST be the
// one whose fingerprint is already in cert.IssuingDeviceKeyID.
//
// Reference: KEY.md §10.3 (device certificates).
func SignDeviceCertificate(signer crypto.Signer, issuingPrivKey []byte, cert *DeviceCertificate) error {
	if signer == nil {
		return errors.New("keys: nil signer")
	}
	if cert == nil {
		return errors.New("keys: nil device certificate")
	}
	if len(issuingPrivKey) == 0 {
		return errors.New("keys: empty issuing private key")
	}
	// Pre-populate the algorithm + key_id so the canonicalized bytes
	// include them. The Value field is still elided inside
	// canonicalDeviceCertificateBytes.
	cert.Signature.Algorithm = SignatureAlgorithmEd25519
	cert.Signature.KeyID = cert.IssuingDeviceKeyID
	msg, err := canonicalDeviceCertificateBytes(cert)
	if err != nil {
		return fmt.Errorf("keys: canonical device certificate: %w", err)
	}
	sigBytes, err := signer.Sign(issuingPrivKey, msg)
	if err != nil {
		return fmt.Errorf("keys: sign device certificate: %w", err)
	}
	cert.Signature.Value = base64.StdEncoding.EncodeToString(sigBytes)
	return nil
}

// VerifyDeviceCertificate verifies cert.Signature against the given
// issuing device public key. Returns nil on success or an error if
// the signature is missing, malformed, or cryptographically invalid.
//
// This does NOT verify the signature chain (i.e. whether the issuing
// device is actually authorized for cert.UserID). Use VerifyChain for
// that — it performs both steps.
func VerifyDeviceCertificate(signer crypto.Signer, cert *DeviceCertificate, issuerPub []byte) error {
	if signer == nil {
		return errors.New("keys: nil signer")
	}
	if cert == nil {
		return errors.New("keys: nil device certificate")
	}
	if cert.Signature.Value == "" {
		return errors.New("keys: device certificate is unsigned")
	}
	if cert.Signature.KeyID != cert.IssuingDeviceKeyID {
		return fmt.Errorf("keys: device certificate signature.key_id %s does not match issuing_device_key_id %s",
			cert.Signature.KeyID, cert.IssuingDeviceKeyID)
	}
	sigBytes, err := base64.StdEncoding.DecodeString(cert.Signature.Value)
	if err != nil {
		return fmt.Errorf("keys: device certificate signature base64: %w", err)
	}
	msg, err := canonicalDeviceCertificateBytes(cert)
	if err != nil {
		return fmt.Errorf("keys: canonical device certificate: %w", err)
	}
	if err := signer.Verify(issuerPub, msg, sigBytes); err != nil {
		return fmt.Errorf("keys: verify device certificate signature: %w", err)
	}
	return nil
}

// VerifyChain checks that:
//
//  1. The certificate is not expired (if c.Expires is set).
//  2. The issuing device key is a registered identity key for
//     c.UserID in the supplied Store, and is not revoked.
//  3. The certificate's signature is valid under that issuing key.
//
// Reference: KEY.md §10.3.1, CLIENT.md §2.3.
func (c *DeviceCertificate) VerifyChain(ctx context.Context, suite crypto.Suite, store Store) error {
	if c == nil {
		return errors.New("keys: nil device certificate")
	}
	if suite == nil {
		return errors.New("keys: nil suite")
	}
	if store == nil {
		return errors.New("keys: nil store")
	}
	if !c.Expires.IsZero() && time.Now().After(c.Expires) {
		return fmt.Errorf("keys: device certificate for %s expired at %s",
			c.DeviceKeyID, c.Expires.Format(time.RFC3339))
	}

	// 1. Look up the issuing device's public key.
	records, err := store.LookupUserKeys(ctx, c.UserID, TypeIdentity)
	if err != nil {
		return fmt.Errorf("keys: lookup issuing device key: %w", err)
	}
	var issuerPub []byte
	for _, rec := range records {
		if rec == nil {
			continue
		}
		if rec.KeyID != c.IssuingDeviceKeyID {
			continue
		}
		if rec.Revocation != nil {
			return fmt.Errorf("keys: issuing device key %s is revoked: %s",
				rec.KeyID, rec.Revocation.Reason)
		}
		pub, err := base64.StdEncoding.DecodeString(rec.PublicKey)
		if err != nil {
			return fmt.Errorf("keys: decode issuing device key: %w", err)
		}
		issuerPub = pub
		break
	}
	if issuerPub == nil {
		return fmt.Errorf("keys: issuing device %s not authorized for %s",
			c.IssuingDeviceKeyID, c.UserID)
	}

	// 2. Verify the certificate signature.
	return VerifyDeviceCertificate(suite.Signer(), c, issuerPub)
}
