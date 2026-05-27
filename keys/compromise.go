package keys

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/semp-dev/semp-go/crypto"
	"github.com/semp-dev/semp-go/recovery"
)

// CompromiseRotation is the four-artifact bundle a revoking device
// produces for the KEY.md §10.5.5 atomic identity-key rotation
// cascade. Submitted as a single transaction to the home server,
// which MUST refuse to accept any artifact without the others.
//
// The cascade is invoked when revoking a device with reason
// `key_compromise`: the compromised device held the shared
// identity private key, so the adversary holds it too, and the
// account MUST rotate to a new identity key plus new encryption
// key in the same operation.
//
// The four artifacts:
//
//  1. DeviceRevocation: SEMP_DEVICE_REVOCATION for the compromised
//     device, reason key_compromise, signed by the prior identity
//     key.
//  2. Successor: SEMP_SUCCESSOR linking the prior identity key to
//     the new one, with recovery_signature and new_key_signature
//     populated. The home server fills in domain_signature on
//     receipt.
//  3. NewIdentityPublicKey + NewEncryptionPublicKey: the fresh
//     keys to publish via the account's key endpoint.
//  4. PriorIdentityRevocation: SEMP_KEY_REVOCATION for the prior
//     identity key, reason key_compromise, signed by the prior
//     identity key (which the revoking device still holds).
//
// Per §10.5.5 the home server MUST treat the bundle atomically: a
// partial cascade (device revoked but identity key not rotated)
// leaves the account vulnerable and is a specification violation.
type CompromiseRotation struct {
	DeviceRevocation        *DeviceRevocation
	Successor               *recovery.SuccessorRecord
	NewIdentityPublicKey    []byte
	NewIdentityKeyID        Fingerprint
	NewEncryptionPublicKey  []byte
	NewEncryptionKeyID      Fingerprint
	PriorIdentityRevocation *RevocationPublication
}

// CompromiseRotationInput collects the inputs BuildCompromiseRotation
// needs. The caller is responsible for generating the new keys
// (typically via suite.Signer().GenerateKeyPair() and
// suite.KEM().GenerateKeyPair()) and for deriving the recovery
// signing key from the user's recovery secret per RECOVERY.md §3.3.
type CompromiseRotationInput struct {
	// Suite is the negotiated algorithm suite.
	Suite crypto.Suite

	// UserID is the account's full SEMP address.
	UserID string

	// CompromisedDeviceID is the device being revoked.
	CompromisedDeviceID string

	// RevokingDeviceID is the device producing the cascade. It is
	// recorded as the `revoked_by_device_id` on the
	// DeviceRevocation.
	RevokingDeviceID string

	// PriorIdentityPriv signs the DeviceRevocation and the
	// PriorIdentityRevocation. The revoking device still holds
	// this key at cascade time.
	PriorIdentityPriv []byte
	PriorIdentityFP   Fingerprint

	// NewIdentityPriv signs the successor record's
	// new_key_signature.
	NewIdentityPriv []byte
	NewIdentityPub  []byte
	NewIdentityFP   Fingerprint

	// NewEncryptionPub is the freshly generated encryption public
	// key. Only the public half is needed in the cascade; the
	// private half is sync'd to remaining full-access devices via
	// the device-sync channel per §10.5.5 step 5.
	NewEncryptionPub []byte
	NewEncryptionFP  Fingerprint

	// RecoveryPriv is the private half of the recovery key pair
	// derived from the user's recovery secret per RECOVERY.md §3.3.
	// It signs the successor record's recovery_signature.
	RecoveryPriv  []byte
	RecoveryKeyID string

	// Now is the wall-clock used to stamp revoked_at and
	// recovered_at. The library defaults to time.Now().UTC() when
	// zero.
	Now time.Time
}

// BuildCompromiseRotation produces the four-artifact bundle a
// revoking device submits to the home server atomically.
//
// The successor record's domain_signature is left empty; the home
// server adds it on receipt per RECOVERY.md §7.3.
//
// Returns an error if any input is missing or any signing pass
// fails.
func BuildCompromiseRotation(in *CompromiseRotationInput) (*CompromiseRotation, error) {
	if in == nil {
		return nil, errors.New("keys: nil rotation input")
	}
	if in.Suite == nil {
		return nil, errors.New("keys: rotation input missing suite")
	}
	if in.UserID == "" {
		return nil, errors.New("keys: rotation input missing user_id")
	}
	if in.CompromisedDeviceID == "" {
		return nil, errors.New("keys: rotation input missing compromised_device_id")
	}
	if in.RevokingDeviceID == "" {
		return nil, errors.New("keys: rotation input missing revoking_device_id")
	}
	if len(in.PriorIdentityPriv) == 0 || in.PriorIdentityFP == "" {
		return nil, errors.New("keys: rotation input missing prior identity key")
	}
	if len(in.NewIdentityPriv) == 0 || len(in.NewIdentityPub) == 0 || in.NewIdentityFP == "" {
		return nil, errors.New("keys: rotation input missing new identity key")
	}
	if len(in.NewEncryptionPub) == 0 || in.NewEncryptionFP == "" {
		return nil, errors.New("keys: rotation input missing new encryption key")
	}
	if len(in.RecoveryPriv) == 0 || in.RecoveryKeyID == "" {
		return nil, errors.New("keys: rotation input missing recovery signing key")
	}
	if string(in.PriorIdentityFP) == string(in.NewIdentityFP) {
		return nil, errors.New("keys: prior and new identity fingerprints must differ")
	}

	now := in.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	signer := in.Suite.Signer()

	// 1. Device revocation, reason key_compromise.
	dev := &DeviceRevocation{
		UserID:            in.UserID,
		DeviceID:          in.CompromisedDeviceID,
		Reason:            DeviceRevocationKeyCompromise,
		RevokedAt:         now,
		RevokedByDeviceID: in.RevokingDeviceID,
	}
	if err := SignDeviceRevocation(signer, in.PriorIdentityPriv, in.PriorIdentityFP, dev); err != nil {
		return nil, fmt.Errorf("keys: sign device revocation: %w", err)
	}

	// 2. Successor record (recovery + new_key sigs).
	suc := &recovery.SuccessorRecord{
		UserID:       in.UserID,
		PriorKeyID:   string(in.PriorIdentityFP),
		NewKeyID:     string(in.NewIdentityFP),
		NewPublicKey: base64.StdEncoding.EncodeToString(in.NewIdentityPub),
		RecoveredAt:  now,
	}
	// Pre-populate all three signature slots so the canonical bytes
	// are stable across the recovery + new_key passes; the
	// domain_signature slot's KeyID is left empty for the home
	// server to fill in.
	recovery.PrepareSuccessorSignatures(suc, in.RecoveryKeyID, string(in.NewIdentityFP), "")
	if err := recovery.SignSuccessorRecovery(signer, in.RecoveryPriv, in.RecoveryKeyID, suc); err != nil {
		return nil, fmt.Errorf("keys: sign successor recovery: %w", err)
	}
	if err := recovery.SignSuccessorNewKey(signer, in.NewIdentityPriv, string(in.NewIdentityFP), suc); err != nil {
		return nil, fmt.Errorf("keys: sign successor new-key: %w", err)
	}

	// 3. The new public keys travel alongside the cascade;
	// publication via the key endpoint is the home server's job.

	// 4. Prior-identity revocation, signed by the prior identity
	// key with reason key_compromise and replacement_key_id pointing
	// at the new identity key.
	prior := &RevocationPublication{
		Type:    "SEMP_KEY_REVOCATION",
		Version: "1.0.0",
		RevokedKeys: []RevokedKeyEntry{
			{
				KeyID:            in.PriorIdentityFP,
				Address:          in.UserID,
				Reason:           ReasonKeyCompromise,
				RevokedAt:        now,
				ReplacementKeyID: in.NewIdentityFP,
			},
		},
	}
	if err := SignRevocationPublication(signer, in.PriorIdentityPriv, in.PriorIdentityFP, prior); err != nil {
		return nil, fmt.Errorf("keys: sign prior identity revocation: %w", err)
	}

	return &CompromiseRotation{
		DeviceRevocation:        dev,
		Successor:               suc,
		NewIdentityPublicKey:    in.NewIdentityPub,
		NewIdentityKeyID:        in.NewIdentityFP,
		NewEncryptionPublicKey:  in.NewEncryptionPub,
		NewEncryptionKeyID:      in.NewEncryptionFP,
		PriorIdentityRevocation: prior,
	}, nil
}

// VerifyCompromiseRotation checks every device-side signature in
// the cascade. The home server runs this on receipt before
// committing the bundle, then adds its own domain_signature to the
// successor record per RECOVERY.md §7.3.
//
// recoveryVerifyPub is the recovery_verify_pk that the prior
// identity key signed at bundle upload time per RECOVERY.md §7.5.
// The home server resolves it from the prior key record.
//
// priorIdentityPub is the published public half of the prior
// identity key; the home server resolves it from the account's
// (now-revoked-but-historical) key set.
func VerifyCompromiseRotation(_ context.Context, suite crypto.Suite, c *CompromiseRotation, priorIdentityPub, recoveryVerifyPub []byte) error {
	if c == nil {
		return errors.New("keys: nil rotation bundle")
	}
	if c.DeviceRevocation == nil {
		return errors.New("keys: rotation bundle missing device_revocation")
	}
	if c.Successor == nil {
		return errors.New("keys: rotation bundle missing successor record")
	}
	if c.PriorIdentityRevocation == nil {
		return errors.New("keys: rotation bundle missing prior_identity_revocation")
	}
	if c.DeviceRevocation.Reason != DeviceRevocationKeyCompromise {
		return fmt.Errorf("keys: rotation device revocation reason %q, want key_compromise", c.DeviceRevocation.Reason)
	}
	if err := VerifyDeviceRevocation(suite.Signer(), priorIdentityPub, c.DeviceRevocation); err != nil {
		return fmt.Errorf("keys: device revocation: %w", err)
	}
	// Successor record: recovery_signature verifies under
	// recoveryVerifyPub; new_key_signature verifies under the new
	// identity public key carried inline in NewPublicKey;
	// domain_signature is empty at this point.
	newPub, err := base64.StdEncoding.DecodeString(c.Successor.NewPublicKey)
	if err != nil {
		return fmt.Errorf("keys: decode successor new_public_key: %w", err)
	}
	if err := recovery.VerifySuccessorTwoSignatures(suite.Signer(), c.Successor, recoveryVerifyPub, newPub); err != nil {
		return fmt.Errorf("keys: successor record: %w", err)
	}
	if err := VerifyRevocationPublication(suite.Signer(), c.PriorIdentityRevocation, priorIdentityPub); err != nil {
		return fmt.Errorf("keys: prior identity revocation: %w", err)
	}
	// Cross-check: the revocation entry MUST name the prior identity
	// key with reason key_compromise and replacement = new identity
	// key carried inline.
	if len(c.PriorIdentityRevocation.RevokedKeys) != 1 {
		return fmt.Errorf("keys: prior identity revocation MUST contain exactly one entry, got %d",
			len(c.PriorIdentityRevocation.RevokedKeys))
	}
	entry := c.PriorIdentityRevocation.RevokedKeys[0]
	if entry.Reason != ReasonKeyCompromise {
		return fmt.Errorf("keys: prior identity revocation entry reason %q, want key_compromise", entry.Reason)
	}
	if string(entry.ReplacementKeyID) != string(c.NewIdentityKeyID) {
		return fmt.Errorf("keys: prior identity revocation replacement %q does not match cascade new_identity_key_id %q",
			entry.ReplacementKeyID, c.NewIdentityKeyID)
	}
	return nil
}
