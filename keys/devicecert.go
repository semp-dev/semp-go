package keys

import "time"

// DeviceCertificate is a SEMP_DEVICE_CERTIFICATE binding a delegated device's
// public key to a permission scope and signed by an authorizing primary
// device. The home server enforces the scope on every envelope submission
// from the delegated device (CLIENT.md §2.4).
//
// Reference: KEY.md §10.3.
type DeviceCertificate struct {
	// Type is the JSON type discriminator, always "SEMP_DEVICE_CERTIFICATE".
	Type string `json:"type"`

	// Version is the SEMP protocol version (semver).
	Version string `json:"version"`

	// UserID is the user account this certificate belongs to.
	UserID string `json:"user_id"`

	// DeviceID is the delegated device identifier (ULID recommended).
	DeviceID string `json:"device_id"`

	// DeviceKeyID is the fingerprint of the delegated device's public key.
	DeviceKeyID Fingerprint `json:"device_key_id"`

	// IssuingDeviceKeyID is the fingerprint of the primary device that
	// signed this certificate.
	IssuingDeviceKeyID Fingerprint `json:"issuing_device_key_id"`

	// Scope is the permission scope granted to the delegated device.
	Scope Scope `json:"scope"`

	// IssuedAt is the time the certificate was created.
	IssuedAt time.Time `json:"issued_at"`

	// Expires is the time after which the certificate is no longer valid.
	Expires time.Time `json:"expires,omitempty"`

	// Signature is the issuing device's signature over the canonical form
	// of the certificate (with this field set to empty during signing).
	Signature PublicationSignature `json:"signature"`
}

// Scope is the permission scope embedded in a device certificate
// (KEY.md §10.3.2).
type Scope struct {
	Send    SendScope    `json:"send"`
	Receive bool         `json:"receive"`
	Manage  ManageScope  `json:"manage"`
}

// SendScope governs which recipients a delegated device may send envelopes to.
type SendScope struct {
	// Mode is one of "all", "restricted", or "none".
	//   - all        : may send to any recipient (no scope check).
	//   - restricted : may send only to recipients listed in Allow.
	//   - none       : may not send envelopes at all.
	Mode string `json:"mode"`

	// Allow is the explicit allowlist of recipient addresses or domains
	// (mode == "restricted" only).
	Allow []string `json:"allow,omitempty"`
}

// ManageScope governs which administrative actions a delegated device may
// perform: registering additional devices, modifying block lists, managing
// keys.
type ManageScope struct {
	Devices    bool `json:"devices"`
	BlockLists bool `json:"block_lists"`
	Keys       bool `json:"keys"`
}

// VerifyChain checks that the certificate's signature is valid and that the
// issuing device key is itself authorized for the user account. Returns nil
// if the chain verifies.
//
// TODO(KEY.md §10.3.1): implement signature verification once crypto.Signer
// is wired in.
func (c *DeviceCertificate) VerifyChain(store Store) error {
	_ = store
	return nil
}
