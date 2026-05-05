package keys

import "time"

// Multi-device record types per KEY.md §10. The three record kinds
// share an account-identity-key signature on the outer envelope so a
// home server or correspondent can verify "this record was authored
// by the account's current identity key" without knowing the device
// graph in advance.
//
// SEMP_DEVICE (DeviceRegistration): announces a new device. Carries
//   the device's public key, role (full_access | delegated), and an
//   inner authorization signature from an existing full-access
//   device that authorized the enrollment.
//
// SEMP_DEVICE_REVOCATION: removes a device from the active set.
//   Self-revocation is permitted; full-access devices may revoke any
//   other device.
//
// SEMP_DEVICE_DIRECTORY: the home server's signed list of currently
//   active devices, with a monotonically increasing revision so
//   correspondents can detect rollback.

// DeviceRole names a device's authority level per KEY.md §10.
type DeviceRole string

// Device roles.
const (
	// DeviceRoleFullAccess: holds the user's identity private key,
	// can compose envelopes, authorize new devices, sign device-
	// scoped artifacts. certificate_id MUST be null.
	DeviceRoleFullAccess DeviceRole = "full_access"

	// DeviceRoleDelegated: holds its own device key only; operates
	// within the bounds of an associated SEMP_DEVICE_CERTIFICATE.
	// certificate_id MUST name the matching certificate's device_id.
	DeviceRoleDelegated DeviceRole = "delegated"
)

// DeviceAuthorizationMethod names how the user proved consent to
// adding a new device per KEY.md §10.2.1.
type DeviceAuthorizationMethod string

// Authorization methods.
const (
	DeviceAuthQRScan      DeviceAuthorizationMethod = "qr_scan"
	DeviceAuthNumericCode DeviceAuthorizationMethod = "numeric_code"
)

// DeviceAuthorization is the proof of user consent embedded in a
// SEMP_DEVICE registration record per KEY.md §10.2. The
// AuthorizingSignature is computed by the existing full-access
// device's device key over the canonical bytes
// `device_id || device_public_key || enrolled_at || enroll_nonce`,
// prefixed with `SEMP-DEVICE-AUTHORIZE:`.
type DeviceAuthorization struct {
	Method               DeviceAuthorizationMethod `json:"method"`
	AuthorizingDeviceID  string                    `json:"authorizing_device_id"`
	AuthorizingSignature PublicationSignature      `json:"authorizing_signature"`
}

// DeviceRegistration is a SEMP_DEVICE record per KEY.md §10.1.
type DeviceRegistration struct {
	Type                          string                `json:"type"`
	Step                          string                `json:"step"`
	Version                       string                `json:"version"`
	UserID                        string                `json:"user_id"`
	DeviceID                      string                `json:"device_id"`
	DeviceName                    string                `json:"device_name"`
	DeviceType                    string                `json:"device_type"`
	DevicePublicKey               string                `json:"device_public_key"`
	DeviceIdentityPubkeyAlgorithm string                `json:"device_identity_pubkey_algorithm"`
	EnrolledAt                    time.Time             `json:"enrolled_at"`
	Role                          DeviceRole            `json:"role"`
	CertificateID                 *string               `json:"certificate_id"` // null for full_access
	Authorization                 DeviceAuthorization   `json:"authorization"`
	Signature                     PublicationSignature  `json:"signature"`
}

// DeviceRevocationReason names why a device is being removed per
// KEY.md §10.5.2.
type DeviceRevocationReason string

// Revocation reasons.
const (
	// DeviceRevocationKeyCompromise triggers mandatory identity-key
	// rotation per KEY.md §10.5.5.
	DeviceRevocationKeyCompromise DeviceRevocationReason = "key_compromise"

	// DeviceRevocationLost: physically lost / unreachable, no
	// evidence of compromise. Identity key is NOT auto-rotated.
	DeviceRevocationLost DeviceRevocationReason = "lost"

	// DeviceRevocationRetired: voluntary decommissioning.
	DeviceRevocationRetired DeviceRevocationReason = "retired"

	// DeviceRevocationSuperseded: explicit replacement by a specific
	// new device. ReplacementDeviceID MUST be non-nil.
	DeviceRevocationSuperseded DeviceRevocationReason = "superseded"
)

// RequiresIdentityRotation reports whether r is the kind of
// revocation that triggers mandatory identity-key rotation per
// KEY.md §10.5.5.
func (r DeviceRevocationReason) RequiresIdentityRotation() bool {
	return r == DeviceRevocationKeyCompromise
}

// DeviceRevocation is a SEMP_DEVICE_REVOCATION record per KEY.md
// §10.5.1. Once published, the home server retains it indefinitely.
type DeviceRevocation struct {
	Type                  string                 `json:"type"`
	Version               string                 `json:"version"`
	UserID                string                 `json:"user_id"`
	DeviceID              string                 `json:"device_id"`
	Reason                DeviceRevocationReason `json:"reason"`
	RevokedAt             time.Time              `json:"revoked_at"`
	RevokedByDeviceID     string                 `json:"revoked_by_device_id"`
	ReplacementDeviceID   *string                `json:"replacement_device_id"` // non-nil only for superseded
	Signature             PublicationSignature   `json:"signature"`
}

// DeviceDirectoryEntry is one device's entry inside a
// SEMP_DEVICE_DIRECTORY per KEY.md §10.6.1.
type DeviceDirectoryEntry struct {
	DeviceID                      string     `json:"device_id"`
	DevicePublicKey               string     `json:"device_public_key"`
	DeviceIdentityPubkeyAlgorithm string     `json:"device_identity_pubkey_algorithm"`
	Role                          DeviceRole `json:"role"`
	CertificateID                 *string    `json:"certificate_id"`
	EnrolledAt                    time.Time  `json:"enrolled_at"`
	DeviceName                    string     `json:"device_name"`
	DeviceType                    string     `json:"device_type"`
}

// DeviceDirectory is a SEMP_DEVICE_DIRECTORY record per KEY.md
// §10.6.1: the home server's signed snapshot of active devices for
// an account. Revision MUST increase monotonically per directory
// emission; consumers reject a fetched directory whose Revision is
// less than a previously cached one for the same UserID
// (rollback-detection signal per §10.6.2).
type DeviceDirectory struct {
	Type      string                 `json:"type"`
	Version   string                 `json:"version"`
	UserID    string                 `json:"user_id"`
	Revision  int64                  `json:"revision"`
	IssuedAt  time.Time              `json:"issued_at"`
	Devices   []DeviceDirectoryEntry `json:"devices"`
	Signature PublicationSignature   `json:"signature"`
}

// Wire-level type discriminator constants used in the JSON `type`
// fields above.
const (
	DeviceRegistrationType = "SEMP_DEVICE"
	DeviceRevocationType   = "SEMP_DEVICE_REVOCATION"
	DeviceDirectoryType    = "SEMP_DEVICE_DIRECTORY"

	// DeviceRegistrationStep is the only valid `step` value for
	// SEMP_DEVICE today. Future revisions MAY define additional
	// steps (for example, a server-side acceptance step) under the
	// same type discriminator.
	DeviceRegistrationStep = "register"

	// DeviceRecordVersion is the `version` value emitted by this
	// library. Consumers MAY accept other minor versions per the
	// CONFORMANCE.md compatibility rules.
	DeviceRecordVersion = "1.0.0"
)
