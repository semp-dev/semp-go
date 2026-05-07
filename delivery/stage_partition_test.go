package delivery_test

import (
	"context"
	"testing"
	"time"

	"semp.dev/semp-go/brief"
	"semp.dev/semp-go/delivery"
	"semp.dev/semp-go/keys"
)

// fakeCerts is a tiny CertificateProvider for tests.
type fakeCerts map[string]*keys.DeviceCertificate

func (f fakeCerts) Certificate(deviceID string) (*keys.DeviceCertificate, error) {
	return f[deviceID], nil
}

func cert(stage int, mode keys.MatcherMode) *keys.DeviceCertificate {
	return &keys.DeviceCertificate{
		Type:            "SEMP_DEVICE_CERTIFICATE",
		DeviceID:        "x", // overridden by caller
		DevicePublicKey: "x",
		Account:         "alice@example.com",
		IssuedBy:        "primary",
		IssuedAt:        time.Now().UTC(),
		ExpiresAt:       time.Now().UTC().Add(180 * 24 * time.Hour),
		Scope: keys.Scope{
			Send:    keys.ScopeMatcher{Mode: keys.MatcherModeUnrestricted, RateLimits: []keys.RateLimitTier{}},
			Receive: keys.ScopeMatcher{Mode: mode, DeliveryStage: stage, RateLimits: []keys.RateLimitTier{}},
			Blocklist: keys.ScopeResource{Read: true, Write: true, RateLimits: []keys.RateLimitTier{}},
			Keys:      keys.ScopeResource{Read: true, Write: false, RateLimits: []keys.RateLimitTier{}},
			Devices:   keys.ScopeResource{Read: true, Write: false, RateLimits: []keys.RateLimitTier{}},
		},
	}
}

func mkDir(devs ...keys.DeviceDirectoryEntry) *keys.DeviceDirectory {
	return &keys.DeviceDirectory{
		Type:    keys.DeviceDirectoryType,
		Version: keys.DeviceRecordVersion,
		UserID:  "alice@example.com",
		Devices: devs,
	}
}

func devEntry(id, pub string, role keys.DeviceRole, certID *string) keys.DeviceDirectoryEntry {
	return keys.DeviceDirectoryEntry{
		DeviceID:                      id,
		DevicePublicKey:               pub,
		DeviceIdentityPubkeyAlgorithm: "ed25519",
		Role:                          role,
		CertificateID:                 certID,
		EnrolledAt:                    time.Now().UTC(),
		DeviceName:                    id,
		DeviceType:                    "test",
	}
}

func cid(s string) *string { return &s }

// TestPartitionStagesAllFullAccessNoStaging confirms the §3.2.1
// no-delegate fallback: full-access devices land at stage 1 and
// staging is a no-op.
func TestPartitionStagesAllFullAccessNoStaging(t *testing.T) {
	dir := mkDir(
		devEntry("d-phone", "pub-phone", keys.DeviceRoleFullAccess, nil),
		devEntry("d-laptop", "pub-laptop", keys.DeviceRoleFullAccess, nil),
	)
	stages, err := delivery.PartitionStages(delivery.PartitionInput{
		Directory:           dir,
		Certs:               fakeCerts{},
		EnclosureRecipients: map[string]struct{}{"pub-phone": {}, "pub-laptop": {}},
		SenderAddress:       brief.Address("bob@example.com"),
	})
	if err != nil {
		t.Fatalf("PartitionStages: %v", err)
	}
	if len(stages) != 1 || stages[0].Stage != 1 {
		t.Fatalf("stages = %+v, want one stage at 1", stages)
	}
	if len(stages[0].PendingDeviceIDs) != 2 {
		t.Errorf("pending devices = %v, want 2", stages[0].PendingDeviceIDs)
	}
}

// TestPartitionStagesDelegateBeforeFullAccess confirms the §10.3.3.1
// implicit full-access stage rule: full-access goes to
// max(delegate_stages_with_mode_not_none) + 1.
func TestPartitionStagesDelegateBeforeFullAccess(t *testing.T) {
	dir := mkDir(
		devEntry("d-spam", "pub-spam", keys.DeviceRoleDelegated, cid("cert-spam")),
		devEntry("d-phone", "pub-phone", keys.DeviceRoleFullAccess, nil),
	)
	certs := fakeCerts{
		"d-spam": cert(1, keys.MatcherModeUnrestricted),
	}
	stages, err := delivery.PartitionStages(delivery.PartitionInput{
		Directory:           dir,
		Certs:               certs,
		EnclosureRecipients: map[string]struct{}{"pub-spam": {}, "pub-phone": {}},
		SenderAddress:       brief.Address("bob@example.com"),
	})
	if err != nil {
		t.Fatalf("PartitionStages: %v", err)
	}
	if len(stages) != 2 {
		t.Fatalf("stages count = %d, want 2", len(stages))
	}
	if stages[0].Stage != 1 || stages[0].PendingDeviceIDs[0] != "d-spam" {
		t.Errorf("stage 1 = %+v, want d-spam", stages[0])
	}
	// Full-access at max(1) + 1 = 2.
	if stages[1].Stage != 2 || stages[1].PendingDeviceIDs[0] != "d-phone" {
		t.Errorf("stage 2 = %+v, want d-phone at stage 2", stages[1])
	}
}

// TestPartitionStagesExcludesByMatcher confirms a delegate whose
// receive matcher rejects the sender is excluded from the
// partition entirely (§3.2.1).
func TestPartitionStagesExcludesByMatcher(t *testing.T) {
	c := cert(1, keys.MatcherModeRestricted)
	c.Scope.Receive.Allow = []keys.ScopeEntry{
		{Type: keys.EntityTypeUser, Address: "carol@example.com"},
	}
	dir := mkDir(
		devEntry("d-spam", "pub-spam", keys.DeviceRoleDelegated, cid("cert-spam")),
		devEntry("d-phone", "pub-phone", keys.DeviceRoleFullAccess, nil),
	)
	stages, _ := delivery.PartitionStages(delivery.PartitionInput{
		Directory:           dir,
		Certs:               fakeCerts{"d-spam": c},
		EnclosureRecipients: map[string]struct{}{"pub-spam": {}, "pub-phone": {}},
		SenderAddress:       brief.Address("bob@example.com"), // not in allow
	})
	// d-spam excluded by matcher; full-access stays at stage 1+1=2
	// because the spec counts ALL delegates with mode != none in the
	// max-stage tally, even those that rejected this envelope.
	if len(stages) != 1 {
		t.Fatalf("stages count = %d, want 1 (only full-access remained)", len(stages))
	}
	if stages[0].Stage != 2 {
		t.Errorf("full-access stage = %d, want 2 (max delegate stage + 1)", stages[0].Stage)
	}
}

// TestPartitionStagesModeNoneDelegateExcludedFromMaxTally confirms
// a delegate with mode=none is excluded from the max-stage tally
// per §10.3.3.1.
func TestPartitionStagesModeNoneDelegateExcludedFromMaxTally(t *testing.T) {
	dir := mkDir(
		devEntry("d-disabled", "pub-d", keys.DeviceRoleDelegated, cid("cert-d")),
		devEntry("d-phone", "pub-phone", keys.DeviceRoleFullAccess, nil),
	)
	// The disabled delegate has mode=none, stage=5. It must NOT
	// contribute to the max tally; full-access falls back to stage 1.
	stages, _ := delivery.PartitionStages(delivery.PartitionInput{
		Directory:           dir,
		Certs:               fakeCerts{"d-disabled": cert(5, keys.MatcherModeNone)},
		EnclosureRecipients: map[string]struct{}{"pub-phone": {}},
		SenderAddress:       brief.Address("bob@example.com"),
	})
	if len(stages) != 1 || stages[0].Stage != 1 {
		t.Errorf("stages = %+v, want stage 1 only (mode=none delegate ignored)", stages)
	}
}

// TestPartitionStagesNoCertExcludesDevice confirms a delegate
// whose cert lookup returns nil (e.g., revoked) is excluded
// per §10.3.7.3.
func TestPartitionStagesNoCertExcludesDevice(t *testing.T) {
	dir := mkDir(
		devEntry("d-spam", "pub-spam", keys.DeviceRoleDelegated, cid("cert-spam")),
		devEntry("d-phone", "pub-phone", keys.DeviceRoleFullAccess, nil),
	)
	stages, _ := delivery.PartitionStages(delivery.PartitionInput{
		Directory:           dir,
		Certs:               fakeCerts{}, // empty; cert lookup returns nil
		EnclosureRecipients: map[string]struct{}{"pub-spam": {}, "pub-phone": {}},
		SenderAddress:       brief.Address("bob@example.com"),
	})
	if len(stages) != 1 || stages[0].PendingDeviceIDs[0] != "d-phone" {
		t.Errorf("stages = %+v, want only full-access (cert-less delegate skipped)", stages)
	}
}

// TestPartitionStagesEnclosureFilterApplied confirms a device whose
// pubkey is NOT in the enclosure_recipients set is excluded
// (typical case: the sender did not wrap K_brief for this device).
func TestPartitionStagesEnclosureFilterApplied(t *testing.T) {
	dir := mkDir(
		devEntry("d-phone", "pub-phone", keys.DeviceRoleFullAccess, nil),
		devEntry("d-laptop", "pub-laptop", keys.DeviceRoleFullAccess, nil),
	)
	stages, _ := delivery.PartitionStages(delivery.PartitionInput{
		Directory:           dir,
		Certs:               fakeCerts{},
		EnclosureRecipients: map[string]struct{}{"pub-phone": {}}, // only phone wrapped
		SenderAddress:       brief.Address("bob@example.com"),
	})
	if len(stages) != 1 || len(stages[0].PendingDeviceIDs) != 1 || stages[0].PendingDeviceIDs[0] != "d-phone" {
		t.Errorf("stages = %+v, want only d-phone", stages)
	}
}

// TestPartitionStagesGroupsMultipleDelegatesAtSameStage confirms
// two delegates declaring the same stage land in the same
// StagedHeldStage entry.
func TestPartitionStagesGroupsMultipleDelegatesAtSameStage(t *testing.T) {
	dir := mkDir(
		devEntry("d-spam", "pub-spam", keys.DeviceRoleDelegated, cid("cert-spam")),
		devEntry("d-policy", "pub-policy", keys.DeviceRoleDelegated, cid("cert-policy")),
		devEntry("d-phone", "pub-phone", keys.DeviceRoleFullAccess, nil),
	)
	certs := fakeCerts{
		"d-spam":   cert(1, keys.MatcherModeUnrestricted),
		"d-policy": cert(1, keys.MatcherModeUnrestricted),
	}
	stages, _ := delivery.PartitionStages(delivery.PartitionInput{
		Directory:           dir,
		Certs:               certs,
		EnclosureRecipients: map[string]struct{}{"pub-spam": {}, "pub-policy": {}, "pub-phone": {}},
		SenderAddress:       brief.Address("bob@example.com"),
	})
	if len(stages) != 2 {
		t.Fatalf("stages count = %d, want 2", len(stages))
	}
	if len(stages[0].PendingDeviceIDs) != 2 {
		t.Errorf("stage 1 pending = %v, want 2", stages[0].PendingDeviceIDs)
	}
}

// TestStagedRunnerReevaluateDropsDevice confirms §3.2.6: a held
// envelope's stage list updates when the cert changes.
func TestStagedRunnerReevaluateDropsDevice(t *testing.T) {
	h := newStagedHarness(t, 30*time.Second)
	stages := []delivery.StagedHeldStage{
		{Stage: 1, PendingDeviceIDs: []string{"d-spam", "d-policy"}},
		{Stage: 2, PendingDeviceIDs: []string{"d-phone"}},
	}
	if err := h.runner.Hold(context.Background(), "env-1", stages); err != nil {
		t.Fatalf("Hold: %v", err)
	}
	// Re-evaluate to drop d-policy from stage 1.
	newStages := []delivery.StagedHeldStage{
		{Stage: 1, PendingDeviceIDs: []string{"d-spam"}},
		{Stage: 2, PendingDeviceIDs: []string{"d-phone"}},
	}
	if err := h.runner.Reevaluate("env-1", newStages); err != nil {
		t.Fatalf("Reevaluate: %v", err)
	}
	snap := h.runner.Snapshot()
	if len(snap["env-1"].Stages[0].PendingDeviceIDs) != 1 {
		t.Errorf("stage 1 pending after reevaluate = %v, want [d-spam]",
			snap["env-1"].Stages[0].PendingDeviceIDs)
	}
}

// TestStagedRunnerReevaluateUnknownEnvelope confirms the not-held
// sentinel.
func TestStagedRunnerReevaluateUnknownEnvelope(t *testing.T) {
	h := newStagedHarness(t, 30*time.Second)
	if err := h.runner.Reevaluate("env-ghost", nil); err == nil {
		t.Error("Reevaluate accepted unknown envelope")
	}
}
