package recovery_test

import (
	"errors"
	"testing"

	"github.com/semp-dev/semp-go/keys"
	"github.com/semp-dev/semp-go/recovery"
)

// fakeDirectory is a minimal recovery.DirectoryView used to keep the
// cross-check tests independent of keys.DeviceDirectory's signing
// machinery. The keys package's adapter is exercised separately.
type fakeDirectory struct {
	userID  string
	entries map[string]struct{ algo, pub string }
}

func (f *fakeDirectory) UserID() string { return f.userID }
func (f *fakeDirectory) FindDevice(deviceID string) (string, string, bool) {
	v, ok := f.entries[deviceID]
	return v.algo, v.pub, ok
}

func mkManifest(contributors []recovery.RecoveryContributor) *recovery.RecoverySetManifest {
	return &recovery.RecoverySetManifest{
		Type:         recovery.RecoverySetManifestType,
		Version:      recovery.RecordVersion,
		BundleID:     "01J0BUNDLE0000000000000001",
		Threshold:    2,
		TotalShares:  len(contributors),
		Contributors: contributors,
	}
}

func mkContributor(idx int, deviceID, algo, pub string) recovery.RecoveryContributor {
	return recovery.RecoveryContributor{
		ShareIndex: idx,
		DeviceID:   deviceID,
		DeviceIdentityPubkey: recovery.DeviceIdentityPubkey{
			Algorithm: algo,
			PublicKey: pub,
			KeyID:     deviceID + "-fp",
		},
	}
}

// TestCrossCheckHappyPath confirms a manifest whose every contributor
// matches the directory passes.
func TestCrossCheckHappyPath(t *testing.T) {
	m := mkManifest([]recovery.RecoveryContributor{
		mkContributor(1, "d-1", "ed25519", "pubA"),
		mkContributor(2, "d-2", "ed25519", "pubB"),
	})
	dir := &fakeDirectory{
		userID: "alice@example.com",
		entries: map[string]struct{ algo, pub string }{
			"d-1": {"ed25519", "pubA"},
			"d-2": {"ed25519", "pubB"},
		},
	}
	if err := recovery.CrossCheckManifestContributors(m, dir); err != nil {
		t.Errorf("CrossCheckManifestContributors: %v", err)
	}
}

// TestCrossCheckMissingDevice confirms a contributor whose device_id
// is not in the directory triggers CrossCheckMissingDevice.
func TestCrossCheckMissingDevice(t *testing.T) {
	m := mkManifest([]recovery.RecoveryContributor{
		mkContributor(1, "d-1", "ed25519", "pubA"),
		mkContributor(2, "d-ghost", "ed25519", "pubB"),
	})
	dir := &fakeDirectory{
		entries: map[string]struct{ algo, pub string }{
			"d-1": {"ed25519", "pubA"},
		},
	}
	err := recovery.CrossCheckManifestContributors(m, dir)
	var cce *recovery.ManifestCrossCheckError
	if !errors.As(err, &cce) {
		t.Fatalf("error is not *ManifestCrossCheckError: %v", err)
	}
	if cce.Reason != recovery.CrossCheckMissingDevice {
		t.Errorf("reason = %q, want %q", cce.Reason, recovery.CrossCheckMissingDevice)
	}
	if cce.DeviceID != "d-ghost" {
		t.Errorf("device_id = %q, want d-ghost", cce.DeviceID)
	}
	if cce.ShareIndex != 2 {
		t.Errorf("share_index = %d, want 2", cce.ShareIndex)
	}
}

// TestCrossCheckPubkeyMismatch confirms a contributor whose pubkey
// does not match the directory entry triggers
// CrossCheckPubkeyMismatch - the §5.2 stale-or-forged-manifest
// signal.
func TestCrossCheckPubkeyMismatch(t *testing.T) {
	m := mkManifest([]recovery.RecoveryContributor{
		mkContributor(1, "d-1", "ed25519", "stale-pubA"),
	})
	dir := &fakeDirectory{
		entries: map[string]struct{ algo, pub string }{
			"d-1": {"ed25519", "fresh-pubA"},
		},
	}
	err := recovery.CrossCheckManifestContributors(m, dir)
	var cce *recovery.ManifestCrossCheckError
	if !errors.As(err, &cce) {
		t.Fatalf("error is not *ManifestCrossCheckError: %v", err)
	}
	if cce.Reason != recovery.CrossCheckPubkeyMismatch {
		t.Errorf("reason = %q, want %q", cce.Reason, recovery.CrossCheckPubkeyMismatch)
	}
}

// TestCrossCheckAlgorithmMismatch confirms an algorithm mismatch is
// surfaced as its own reason kind.
func TestCrossCheckAlgorithmMismatch(t *testing.T) {
	m := mkManifest([]recovery.RecoveryContributor{
		mkContributor(1, "d-1", "ed25519", "pubA"),
	})
	dir := &fakeDirectory{
		entries: map[string]struct{ algo, pub string }{
			"d-1": {"some-future-algo", "pubA"},
		},
	}
	err := recovery.CrossCheckManifestContributors(m, dir)
	var cce *recovery.ManifestCrossCheckError
	if !errors.As(err, &cce) {
		t.Fatalf("error is not *ManifestCrossCheckError: %v", err)
	}
	if cce.Reason != recovery.CrossCheckAlgorithmMismatch {
		t.Errorf("reason = %q, want %q", cce.Reason, recovery.CrossCheckAlgorithmMismatch)
	}
}

// TestCrossCheckEmptyAlgorithmTolerated confirms an empty
// algorithm on either side is treated as "not declared" rather than
// a mismatch - the directory may pre-date the algorithm field
// (existing test fixtures do not always populate it), and the
// manifest's algorithm is still validated when both sides set it.
func TestCrossCheckEmptyAlgorithmTolerated(t *testing.T) {
	m := mkManifest([]recovery.RecoveryContributor{
		mkContributor(1, "d-1", "" /* unset */, "pubA"),
	})
	dir := &fakeDirectory{
		entries: map[string]struct{ algo, pub string }{
			"d-1": {"ed25519", "pubA"},
		},
	}
	if err := recovery.CrossCheckManifestContributors(m, dir); err != nil {
		t.Errorf("empty algorithm should not fail cross-check: %v", err)
	}
}

// TestCrossCheckRejectsNilArgs guards the obvious foot-guns.
func TestCrossCheckRejectsNilArgs(t *testing.T) {
	if err := recovery.CrossCheckManifestContributors(nil, &fakeDirectory{}); err == nil {
		t.Error("nil manifest accepted")
	}
	m := mkManifest([]recovery.RecoveryContributor{
		mkContributor(1, "d-1", "ed25519", "pubA"),
	})
	if err := recovery.CrossCheckManifestContributors(m, nil); err == nil {
		t.Error("nil directory accepted")
	}
}

// TestKeysDirectoryAdapterSatisfiesView confirms the
// keys.DeviceDirectory adapter actually plugs into the cross-check.
// This is the integration that makes the cross-check usable in a
// real restore flow.
func TestKeysDirectoryAdapterSatisfiesView(t *testing.T) {
	dir := &keys.DeviceDirectory{
		UserID: "alice@example.com",
		Devices: []keys.DeviceDirectoryEntry{
			{
				DeviceID:                      "d-1",
				DevicePublicKey:               "pubA",
				DeviceIdentityPubkeyAlgorithm: "ed25519",
			},
		},
	}
	m := mkManifest([]recovery.RecoveryContributor{
		mkContributor(1, "d-1", "ed25519", "pubA"),
	})
	if err := recovery.CrossCheckManifestContributors(m, dir.AsDirectoryView()); err != nil {
		t.Errorf("cross-check via keys adapter: %v", err)
	}
}
