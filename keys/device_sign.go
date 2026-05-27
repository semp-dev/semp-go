package keys

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/semp-dev/semp-go/clockskew"
	"github.com/semp-dev/semp-go/crypto"
	"github.com/semp-dev/semp-go/canonical"
)

// canonicalDeviceRegistrationBytes returns the canonical JSON form
// of reg with `signature.value` elided (the rest of the signature
// object is covered, matching the same pattern as
// SEMP_DEVICE_CERTIFICATE).
func canonicalDeviceRegistrationBytes(reg *DeviceRegistration) ([]byte, error) {
	if reg == nil {
		return nil, errors.New("keys: nil device registration")
	}
	return canonical.MarshalWithElision(reg, func(v any) error {
		m, ok := v.(map[string]any)
		if !ok {
			return fmt.Errorf("keys: expected top-level object, got %T", v)
		}
		sig, ok := m["signature"].(map[string]any)
		if !ok {
			return errors.New("keys: device registration missing signature object")
		}
		sig["value"] = ""
		return nil
	})
}

// authorizationCanonicalBytes returns the canonical bytes the
// authorizing device signs over per KEY.md §10.2.2:
// `device_id || device_public_key || enrolled_at || enroll_nonce`.
// Field separators are explicit so an attacker cannot shift
// boundaries to forge a different (id, pubkey, ts) tuple.
//
// The components are length-prefixed with a single `:` separator;
// none of the four input fields can contain `:` under SEMP rules
// (ULID alphabet excludes `:`, base64 excludes `:`, ISO 8601 UTC
// excludes `:` only inside the time portion which is always
// surrounded by structure, so we use `\x00` instead to be
// uncontroversially unambiguous).
func authorizationCanonicalBytes(deviceID, devicePublicKey string, enrolledAt time.Time, enrollNonce []byte) []byte {
	var buf bytes.Buffer
	buf.WriteString(deviceID)
	buf.WriteByte(0x00)
	buf.WriteString(devicePublicKey)
	buf.WriteByte(0x00)
	buf.WriteString(enrolledAt.UTC().Format(time.RFC3339Nano))
	buf.WriteByte(0x00)
	buf.Write(enrollNonce)
	return buf.Bytes()
}

// SignDeviceAuthorization computes the inner authorizing device
// signature for a SEMP_DEVICE registration record per KEY.md
// §10.2.2. authorizingPriv is the existing full-access device's
// device private key; authorizingDeviceID and authorizingKeyID
// identify it.
//
// The caller is expected to have populated reg.DeviceID,
// reg.DevicePublicKey, and reg.EnrolledAt before invoking. The
// authorization payload is signed over those three fields plus the
// caller-supplied enrollNonce, prefixed with
// SEMP-DEVICE-AUTHORIZE: per the domain-separation registry.
func SignDeviceAuthorization(signer crypto.Signer, authorizingPriv []byte, authorizingDeviceID string, authorizingKeyID Fingerprint, enrollNonce []byte, reg *DeviceRegistration, method DeviceAuthorizationMethod) error {
	if signer == nil {
		return errors.New("keys: nil signer")
	}
	if reg == nil {
		return errors.New("keys: nil device registration")
	}
	if len(authorizingPriv) == 0 {
		return errors.New("keys: empty authorizing private key")
	}
	if authorizingDeviceID == "" {
		return errors.New("keys: empty authorizing_device_id")
	}
	if authorizingKeyID == "" {
		return errors.New("keys: empty authorizing key fingerprint")
	}
	if len(enrollNonce) == 0 {
		return errors.New("keys: empty enroll nonce")
	}
	if reg.DeviceID == "" || reg.DevicePublicKey == "" {
		return errors.New("keys: device registration missing device_id or device_public_key")
	}
	if reg.EnrolledAt.IsZero() {
		return errors.New("keys: device registration missing enrolled_at")
	}
	authBytes := authorizationCanonicalBytes(reg.DeviceID, reg.DevicePublicKey, reg.EnrolledAt, enrollNonce)
	prefixed := crypto.PrefixedMessage(crypto.SigCtxDeviceAuthorize, authBytes)
	sig, err := signer.Sign(authorizingPriv, prefixed)
	if err != nil {
		return fmt.Errorf("keys: sign device authorization: %w", err)
	}
	reg.Authorization = DeviceAuthorization{
		Method:              method,
		AuthorizingDeviceID: authorizingDeviceID,
		AuthorizingSignature: PublicationSignature{
			Algorithm: SignatureAlgorithmEd25519,
			KeyID:     authorizingKeyID,
			Value:     base64.StdEncoding.EncodeToString(sig),
		},
	}
	return nil
}

// VerifyDeviceAuthorization checks the inner authorizing-device
// signature on a SEMP_DEVICE record. The caller supplies the
// authorizing device's PUBLIC key (looked up in the device
// directory by reg.Authorization.AuthorizingDeviceID) and the same
// enrollNonce that was used to produce the signature.
func VerifyDeviceAuthorization(signer crypto.Signer, authorizingPub []byte, enrollNonce []byte, reg *DeviceRegistration) error {
	if signer == nil {
		return errors.New("keys: nil signer")
	}
	if reg == nil {
		return errors.New("keys: nil device registration")
	}
	if len(authorizingPub) == 0 {
		return errors.New("keys: empty authorizing public key")
	}
	if reg.Authorization.AuthorizingSignature.Value == "" {
		return errors.New("keys: device registration missing authorizing_signature")
	}
	sig, err := base64.StdEncoding.DecodeString(reg.Authorization.AuthorizingSignature.Value)
	if err != nil {
		return fmt.Errorf("keys: authorizing_signature base64: %w", err)
	}
	authBytes := authorizationCanonicalBytes(reg.DeviceID, reg.DevicePublicKey, reg.EnrolledAt, enrollNonce)
	prefixed := crypto.PrefixedMessage(crypto.SigCtxDeviceAuthorize, authBytes)
	if err := signer.Verify(authorizingPub, prefixed, sig); err != nil {
		return fmt.Errorf("keys: verify device authorization: %w", err)
	}
	return nil
}

// SignDeviceRegistration computes the OUTER identity-key signature
// on a SEMP_DEVICE record per KEY.md §10.1. identityPriv is the
// account's identity private key; identityKeyID is its fingerprint.
// The caller MUST have already populated the inner
// reg.Authorization (typically via SignDeviceAuthorization).
//
// SignDeviceRegistration validates the structural rules in §10.1
// (role/certificate_id consistency, required fields) before signing.
func SignDeviceRegistration(signer crypto.Signer, identityPriv []byte, identityKeyID Fingerprint, reg *DeviceRegistration) error {
	if signer == nil {
		return errors.New("keys: nil signer")
	}
	if reg == nil {
		return errors.New("keys: nil device registration")
	}
	if len(identityPriv) == 0 {
		return errors.New("keys: empty identity private key")
	}
	if identityKeyID == "" {
		return errors.New("keys: empty identity key fingerprint")
	}
	if reg.Type == "" {
		reg.Type = DeviceRegistrationType
	}
	if reg.Step == "" {
		reg.Step = DeviceRegistrationStep
	}
	if reg.Version == "" {
		reg.Version = DeviceRecordVersion
	}
	if err := reg.Validate(); err != nil {
		return err
	}
	reg.Signature.Algorithm = SignatureAlgorithmEd25519
	reg.Signature.KeyID = identityKeyID
	reg.Signature.Value = ""
	canonicalBytes, err := canonicalDeviceRegistrationBytes(reg)
	if err != nil {
		return fmt.Errorf("keys: canonical device registration: %w", err)
	}
	prefixed := crypto.PrefixedMessage(crypto.SigCtxDeviceRegister, canonicalBytes)
	sig, err := signer.Sign(identityPriv, prefixed)
	if err != nil {
		return fmt.Errorf("keys: sign device registration: %w", err)
	}
	reg.Signature.Value = base64.StdEncoding.EncodeToString(sig)
	return nil
}

// VerifyDeviceRegistration checks the OUTER identity-key signature
// against identityPub. Does not check the inner authorization
// signature; pair with VerifyDeviceAuthorization for the full §10.1
// verification flow.
func VerifyDeviceRegistration(signer crypto.Signer, identityPub []byte, reg *DeviceRegistration) error {
	if signer == nil {
		return errors.New("keys: nil signer")
	}
	if reg == nil {
		return errors.New("keys: nil device registration")
	}
	if len(identityPub) == 0 {
		return errors.New("keys: empty identity public key")
	}
	if reg.Signature.Value == "" {
		return errors.New("keys: device registration is unsigned")
	}
	if err := reg.Validate(); err != nil {
		return err
	}
	sig, err := base64.StdEncoding.DecodeString(reg.Signature.Value)
	if err != nil {
		return fmt.Errorf("keys: device registration signature base64: %w", err)
	}
	canonicalBytes, err := canonicalDeviceRegistrationBytes(reg)
	if err != nil {
		return fmt.Errorf("keys: canonical device registration: %w", err)
	}
	prefixed := crypto.PrefixedMessage(crypto.SigCtxDeviceRegister, canonicalBytes)
	if err := signer.Verify(identityPub, prefixed, sig); err != nil {
		return fmt.Errorf("keys: verify device registration signature: %w", err)
	}
	return nil
}

// Validate reports whether reg is structurally well-formed per
// KEY.md §10.1.
func (reg *DeviceRegistration) Validate() error {
	if reg == nil {
		return errors.New("keys: nil device registration")
	}
	if reg.Type != DeviceRegistrationType {
		return fmt.Errorf("keys: device registration type %q, want %q", reg.Type, DeviceRegistrationType)
	}
	if reg.Step != DeviceRegistrationStep {
		return fmt.Errorf("keys: device registration step %q, want %q", reg.Step, DeviceRegistrationStep)
	}
	if reg.UserID == "" {
		return errors.New("keys: device registration missing user_id")
	}
	if reg.DeviceID == "" {
		return errors.New("keys: device registration missing device_id")
	}
	if reg.DevicePublicKey == "" {
		return errors.New("keys: device registration missing device_public_key")
	}
	if reg.DeviceIdentityPubkeyAlgorithm == "" {
		return errors.New("keys: device registration missing device_identity_pubkey_algorithm")
	}
	if reg.EnrolledAt.IsZero() {
		return errors.New("keys: device registration missing enrolled_at")
	}
	switch reg.Role {
	case DeviceRoleFullAccess:
		if reg.CertificateID != nil {
			return errors.New("keys: full_access device registration MUST have certificate_id = null")
		}
	case DeviceRoleDelegated:
		if reg.CertificateID == nil || *reg.CertificateID == "" {
			return errors.New("keys: delegated device registration MUST set certificate_id")
		}
	default:
		return fmt.Errorf("keys: device registration role %q is not a valid role", reg.Role)
	}
	switch reg.Authorization.Method {
	case DeviceAuthQRScan, DeviceAuthNumericCode:
		// ok
	case "":
		return errors.New("keys: device registration missing authorization.method")
	default:
		return fmt.Errorf("keys: device registration authorization.method %q is not supported",
			reg.Authorization.Method)
	}
	if reg.Authorization.AuthorizingDeviceID == "" {
		return errors.New("keys: device registration missing authorization.authorizing_device_id")
	}
	return nil
}

// canonicalDeviceRevocationBytes returns the canonical JSON form of
// rev with `signature.value` elided.
func canonicalDeviceRevocationBytes(rev *DeviceRevocation) ([]byte, error) {
	if rev == nil {
		return nil, errors.New("keys: nil device revocation")
	}
	return canonical.MarshalWithElision(rev, func(v any) error {
		m, ok := v.(map[string]any)
		if !ok {
			return fmt.Errorf("keys: expected top-level object, got %T", v)
		}
		sig, ok := m["signature"].(map[string]any)
		if !ok {
			return errors.New("keys: device revocation missing signature object")
		}
		sig["value"] = ""
		return nil
	})
}

// SignDeviceRevocation computes the identity-key signature on a
// SEMP_DEVICE_REVOCATION record per KEY.md §10.5. Validates the
// §10.5.1 structural rules (reason/replacement consistency) before
// signing.
func SignDeviceRevocation(signer crypto.Signer, identityPriv []byte, identityKeyID Fingerprint, rev *DeviceRevocation) error {
	if signer == nil {
		return errors.New("keys: nil signer")
	}
	if rev == nil {
		return errors.New("keys: nil device revocation")
	}
	if len(identityPriv) == 0 {
		return errors.New("keys: empty identity private key")
	}
	if identityKeyID == "" {
		return errors.New("keys: empty identity key fingerprint")
	}
	if rev.Type == "" {
		rev.Type = DeviceRevocationType
	}
	if rev.Version == "" {
		rev.Version = DeviceRecordVersion
	}
	if err := rev.Validate(); err != nil {
		return err
	}
	rev.Signature.Algorithm = SignatureAlgorithmEd25519
	rev.Signature.KeyID = identityKeyID
	rev.Signature.Value = ""
	canonicalBytes, err := canonicalDeviceRevocationBytes(rev)
	if err != nil {
		return fmt.Errorf("keys: canonical device revocation: %w", err)
	}
	prefixed := crypto.PrefixedMessage(crypto.SigCtxDeviceRevocation, canonicalBytes)
	sig, err := signer.Sign(identityPriv, prefixed)
	if err != nil {
		return fmt.Errorf("keys: sign device revocation: %w", err)
	}
	rev.Signature.Value = base64.StdEncoding.EncodeToString(sig)
	return nil
}

// VerifyDeviceRevocation checks the identity-key signature on rev
// against identityPub.
func VerifyDeviceRevocation(signer crypto.Signer, identityPub []byte, rev *DeviceRevocation) error {
	if signer == nil {
		return errors.New("keys: nil signer")
	}
	if rev == nil {
		return errors.New("keys: nil device revocation")
	}
	if len(identityPub) == 0 {
		return errors.New("keys: empty identity public key")
	}
	if rev.Signature.Value == "" {
		return errors.New("keys: device revocation is unsigned")
	}
	if err := rev.Validate(); err != nil {
		return err
	}
	sig, err := base64.StdEncoding.DecodeString(rev.Signature.Value)
	if err != nil {
		return fmt.Errorf("keys: device revocation signature base64: %w", err)
	}
	canonicalBytes, err := canonicalDeviceRevocationBytes(rev)
	if err != nil {
		return fmt.Errorf("keys: canonical device revocation: %w", err)
	}
	prefixed := crypto.PrefixedMessage(crypto.SigCtxDeviceRevocation, canonicalBytes)
	if err := signer.Verify(identityPub, prefixed, sig); err != nil {
		return fmt.Errorf("keys: verify device revocation signature: %w", err)
	}
	return nil
}

// Validate reports whether rev is structurally well-formed per
// KEY.md §10.5.
func (rev *DeviceRevocation) Validate() error {
	if rev == nil {
		return errors.New("keys: nil device revocation")
	}
	if rev.Type != DeviceRevocationType {
		return fmt.Errorf("keys: device revocation type %q, want %q", rev.Type, DeviceRevocationType)
	}
	if rev.UserID == "" {
		return errors.New("keys: device revocation missing user_id")
	}
	if rev.DeviceID == "" {
		return errors.New("keys: device revocation missing device_id")
	}
	if rev.RevokedAt.IsZero() {
		return errors.New("keys: device revocation missing revoked_at")
	}
	if rev.RevokedByDeviceID == "" {
		return errors.New("keys: device revocation missing revoked_by_device_id")
	}
	switch rev.Reason {
	case DeviceRevocationKeyCompromise, DeviceRevocationLost, DeviceRevocationRetired:
		if rev.ReplacementDeviceID != nil {
			return fmt.Errorf("keys: device revocation reason %q MUST have replacement_device_id = null", rev.Reason)
		}
	case DeviceRevocationSuperseded:
		if rev.ReplacementDeviceID == nil || *rev.ReplacementDeviceID == "" {
			return errors.New("keys: device revocation reason superseded MUST set replacement_device_id")
		}
	default:
		return fmt.Errorf("keys: device revocation reason %q is not a valid reason", rev.Reason)
	}
	return nil
}

// canonicalDeviceDirectoryBytes returns the canonical JSON form of
// dir with `signature.value` elided. The Devices array is sorted by
// device_id before canonicalization to match the §10.6.3 consumer
// rule that sort order is not semantic.
func canonicalDeviceDirectoryBytes(dir *DeviceDirectory) ([]byte, error) {
	if dir == nil {
		return nil, errors.New("keys: nil device directory")
	}
	// Work on a copy so we do not mutate the caller's slice ordering.
	cp := *dir
	cp.Devices = append([]DeviceDirectoryEntry(nil), dir.Devices...)
	sort.Slice(cp.Devices, func(i, j int) bool {
		return cp.Devices[i].DeviceID < cp.Devices[j].DeviceID
	})
	return canonical.MarshalWithElision(&cp, func(v any) error {
		m, ok := v.(map[string]any)
		if !ok {
			return fmt.Errorf("keys: expected top-level object, got %T", v)
		}
		sig, ok := m["signature"].(map[string]any)
		if !ok {
			return errors.New("keys: device directory missing signature object")
		}
		sig["value"] = ""
		return nil
	})
}

// SignDeviceDirectory computes the identity-key signature on a
// SEMP_DEVICE_DIRECTORY record per KEY.md §10.6. The caller MUST
// have set Revision such that it is monotonically greater than any
// previously published directory for the same UserID; the library
// has no global revision counter.
func SignDeviceDirectory(signer crypto.Signer, identityPriv []byte, identityKeyID Fingerprint, dir *DeviceDirectory) error {
	if signer == nil {
		return errors.New("keys: nil signer")
	}
	if dir == nil {
		return errors.New("keys: nil device directory")
	}
	if len(identityPriv) == 0 {
		return errors.New("keys: empty identity private key")
	}
	if identityKeyID == "" {
		return errors.New("keys: empty identity key fingerprint")
	}
	if dir.Type == "" {
		dir.Type = DeviceDirectoryType
	}
	if dir.Version == "" {
		dir.Version = DeviceRecordVersion
	}
	if err := dir.Validate(); err != nil {
		return err
	}
	dir.Signature.Algorithm = SignatureAlgorithmEd25519
	dir.Signature.KeyID = identityKeyID
	dir.Signature.Value = ""
	canonicalBytes, err := canonicalDeviceDirectoryBytes(dir)
	if err != nil {
		return fmt.Errorf("keys: canonical device directory: %w", err)
	}
	prefixed := crypto.PrefixedMessage(crypto.SigCtxDeviceDirectory, canonicalBytes)
	sig, err := signer.Sign(identityPriv, prefixed)
	if err != nil {
		return fmt.Errorf("keys: sign device directory: %w", err)
	}
	dir.Signature.Value = base64.StdEncoding.EncodeToString(sig)
	return nil
}

// VerifyDeviceDirectory checks the identity-key signature on dir
// against identityPub. It also checks the §10.6.3 consumer rules
// (every device_id unique, signature present). The rollback-detect
// rule (Revision >= cached) is the caller's responsibility because
// the cached value lives outside the record.
func VerifyDeviceDirectory(signer crypto.Signer, identityPub []byte, dir *DeviceDirectory) error {
	if signer == nil {
		return errors.New("keys: nil signer")
	}
	if dir == nil {
		return errors.New("keys: nil device directory")
	}
	if len(identityPub) == 0 {
		return errors.New("keys: empty identity public key")
	}
	if dir.Signature.Value == "" {
		return errors.New("keys: device directory is unsigned")
	}
	if err := dir.Validate(); err != nil {
		return err
	}
	sig, err := base64.StdEncoding.DecodeString(dir.Signature.Value)
	if err != nil {
		return fmt.Errorf("keys: device directory signature base64: %w", err)
	}
	canonicalBytes, err := canonicalDeviceDirectoryBytes(dir)
	if err != nil {
		return fmt.Errorf("keys: canonical device directory: %w", err)
	}
	prefixed := crypto.PrefixedMessage(crypto.SigCtxDeviceDirectory, canonicalBytes)
	if err := signer.Verify(identityPub, prefixed, sig); err != nil {
		return fmt.Errorf("keys: verify device directory signature: %w", err)
	}
	return nil
}

// Validate reports whether dir is structurally well-formed per
// KEY.md §10.6.
func (dir *DeviceDirectory) Validate() error {
	if dir == nil {
		return errors.New("keys: nil device directory")
	}
	if dir.Type != DeviceDirectoryType {
		return fmt.Errorf("keys: device directory type %q, want %q", dir.Type, DeviceDirectoryType)
	}
	if dir.UserID == "" {
		return errors.New("keys: device directory missing user_id")
	}
	if dir.Revision < 1 {
		return fmt.Errorf("keys: device directory revision %d MUST be >= 1", dir.Revision)
	}
	if dir.IssuedAt.IsZero() {
		return errors.New("keys: device directory missing issued_at")
	}
	seen := make(map[string]struct{}, len(dir.Devices))
	for i, d := range dir.Devices {
		if d.DeviceID == "" {
			return fmt.Errorf("keys: device directory devices[%d] missing device_id", i)
		}
		if d.DevicePublicKey == "" {
			return fmt.Errorf("keys: device directory devices[%d] missing device_public_key", i)
		}
		switch d.Role {
		case DeviceRoleFullAccess:
			if d.CertificateID != nil {
				return fmt.Errorf("keys: device directory devices[%d]: full_access entry MUST have certificate_id = null", i)
			}
		case DeviceRoleDelegated:
			if d.CertificateID == nil || *d.CertificateID == "" {
				return fmt.Errorf("keys: device directory devices[%d]: delegated entry MUST set certificate_id", i)
			}
		default:
			return fmt.Errorf("keys: device directory devices[%d]: role %q is not a valid role", i, d.Role)
		}
		if _, ok := seen[d.DeviceID]; ok {
			return fmt.Errorf("keys: device directory device_id %q appears more than once", d.DeviceID)
		}
		seen[d.DeviceID] = struct{}{}
	}
	return nil
}

// CheckEnrolledAtFresh reports whether enrolledAt is within the
// 15-minute submission-skew bound from KEY.md §10.2.3 relative to
// now. Used by home servers verifying a freshly received
// SEMP_DEVICE registration.
func CheckEnrolledAtFresh(enrolledAt, now time.Time) error {
	return clockskew.CheckFutureTimestamp(enrolledAt, now, clockskew.Default())
}
