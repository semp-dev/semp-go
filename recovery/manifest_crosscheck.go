package recovery

import (
	"errors"
	"fmt"
)

// DirectoryView is the minimal subset of the device directory that
// CrossCheckManifestContributors consumes. It exists so the recovery
// package does not have to import keys (which would create a cycle:
// keys.CompromiseRotation embeds recovery.SuccessorRecord, so keys
// already imports recovery).
//
// keys.DeviceDirectory satisfies DirectoryView via its
// AsDirectoryView helper, and operators with custom directory
// shapes can also provide their own implementation.
type DirectoryView interface {
	// UserID returns the account identifier the directory belongs
	// to. Used for an optional sanity check against any user-id
	// hint the caller already resolved. May return empty string.
	UserID() string

	// FindDevice returns the directory entry for deviceID. The
	// returned (algorithm, publicKey) are compared byte-exact
	// against the manifest's device_identity_pubkey block. The
	// found return is false when the directory has no entry for
	// deviceID.
	FindDevice(deviceID string) (algorithm string, publicKey string, found bool)
}

// CrossCheckManifestContributors implements RECOVERY.md §5.2's
// directory cross-check: for every contributor in m, the bound
// device MUST appear in directory with a matching device_public_key.
// Per the spec, a contributor that is not listed in the directory
// revision active at m.IssuedAt, or whose directory device_public_key
// does not match the manifest's device_identity_pubkey, indicates a
// stale or forged manifest and MUST be rejected.
//
// directory is the device-directory snapshot the caller resolved
// for the account at m.IssuedAt. Callers that maintain a
// per-revision history pick the revision active at m.IssuedAt;
// callers with only the current cached directory pass that
// snapshot, with the caveat that a recently-rotated directory may
// produce false negatives if the manifest pre-dates the rotation.
//
// Returns nil when every contributor matches a directory entry. On
// the first mismatch returns a *ManifestCrossCheckError carrying the
// offending contributor's share_index plus the specific mismatch
// kind. The error type makes it easy for callers to surface
// per-contributor diagnostics in the restore UI.
//
// CrossCheckManifestContributors does NOT verify the manifest
// signature; pair it with VerifyManifest for the full §5.2
// receive-side check.
func CrossCheckManifestContributors(m *RecoverySetManifest, directory DirectoryView) error {
	if m == nil {
		return errors.New("recovery: nil manifest")
	}
	if directory == nil {
		return errors.New("recovery: nil directory")
	}
	for i, c := range m.Contributors {
		algo, pub, found := directory.FindDevice(c.DeviceID)
		if !found {
			return &ManifestCrossCheckError{
				ContributorIndex: i,
				ShareIndex:       c.ShareIndex,
				DeviceID:         c.DeviceID,
				Reason:           CrossCheckMissingDevice,
			}
		}
		if pub != c.DeviceIdentityPubkey.PublicKey {
			return &ManifestCrossCheckError{
				ContributorIndex: i,
				ShareIndex:       c.ShareIndex,
				DeviceID:         c.DeviceID,
				Reason:           CrossCheckPubkeyMismatch,
			}
		}
		if c.DeviceIdentityPubkey.Algorithm != "" && algo != "" &&
			algo != c.DeviceIdentityPubkey.Algorithm {
			return &ManifestCrossCheckError{
				ContributorIndex: i,
				ShareIndex:       c.ShareIndex,
				DeviceID:         c.DeviceID,
				Reason:           CrossCheckAlgorithmMismatch,
			}
		}
	}
	return nil
}

// CrossCheckReason names the specific mismatch kind in a
// ManifestCrossCheckError. Each maps to one branch of the §5.2
// contributor-vs-directory comparison.
type CrossCheckReason string

// CrossCheckReason values.
const (
	// CrossCheckMissingDevice: the contributor's device_id is not
	// listed in the supplied directory revision.
	CrossCheckMissingDevice CrossCheckReason = "missing_device"

	// CrossCheckPubkeyMismatch: the contributor's
	// device_identity_pubkey.public_key does not match the
	// directory entry's device_public_key for the same device_id.
	CrossCheckPubkeyMismatch CrossCheckReason = "pubkey_mismatch"

	// CrossCheckAlgorithmMismatch: the contributor's pubkey
	// algorithm does not match the directory entry's algorithm.
	CrossCheckAlgorithmMismatch CrossCheckReason = "algorithm_mismatch"
)

// ManifestCrossCheckError describes the first contributor mismatch
// CrossCheckManifestContributors observed.
type ManifestCrossCheckError struct {
	ContributorIndex int
	ShareIndex       int
	DeviceID         string
	Reason           CrossCheckReason
}

// Error implements error.
func (e *ManifestCrossCheckError) Error() string {
	return fmt.Sprintf(
		"recovery: manifest contributor[%d] (share_index=%d, device_id=%q) %s against directory",
		e.ContributorIndex, e.ShareIndex, e.DeviceID, e.Reason,
	)
}
