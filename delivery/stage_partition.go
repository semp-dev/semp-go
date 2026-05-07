package delivery

import (
	"errors"
	"fmt"
	"sort"

	"semp.dev/semp-go/brief"
	"semp.dev/semp-go/keys"
)

// CertificateProvider is the lookup hook PartitionStages calls for
// each delegated device's scoped certificate. The home server holds
// the canonical cert state; this interface decouples the partition
// computation from any particular certificate-store
// implementation. Returning (nil, nil) for a missing cert is treated
// as "no current cert"; the device is excluded from the partition
// (the spec's effect of certificate revocation per §10.3.7.3 step 3:
// "stop delivering inbound envelopes to device_id").
type CertificateProvider interface {
	Certificate(deviceID string) (*keys.DeviceCertificate, error)
}

// CertificateProviderFunc lets a plain function satisfy
// CertificateProvider.
type CertificateProviderFunc func(deviceID string) (*keys.DeviceCertificate, error)

// Certificate implements CertificateProvider.
func (f CertificateProviderFunc) Certificate(deviceID string) (*keys.DeviceCertificate, error) {
	return f(deviceID)
}

// PartitionInput bundles the inputs to PartitionStages.
type PartitionInput struct {
	// Directory is the user's current device directory. PartitionStages
	// iterates Directory.Devices to enumerate the account's devices.
	Directory *keys.DeviceDirectory

	// Certs supplies the scoped certificate for each delegated device.
	// PartitionStages calls Certs.Certificate(device_id) for every
	// device whose role is "delegated"; full-access devices have no
	// certificate.
	Certs CertificateProvider

	// EnclosureRecipients is the set of device public keys for which
	// the envelope's seal carries an enclosure-recipient wrap. Only
	// devices whose pubkey is in this set are eligible for delivery.
	// Pubkeys are compared verbatim against
	// DeviceDirectoryEntry.DevicePublicKey (the same base64 form the
	// directory uses).
	EnclosureRecipients map[string]struct{}

	// SenderAddress is the brief.from address the receive matcher
	// evaluates against per §10.3.4 "for receive, a peer is the
	// sender address of an inbound envelope after the home server
	// has decrypted the brief".
	SenderAddress brief.Address
}

// PartitionStages computes the §3.2.1 stage partition for an
// inbound envelope. Returns the slice of StagedHeldStage values
// callers feed to StagedRunner.Hold.
//
// Algorithm:
//
//  1. Walk the directory; for each device whose pubkey is in
//     EnclosureRecipients:
//     - Full-access devices are deferred (their stage is computed
//       implicitly per §10.3.3.1: max(delegated_stages) + 1).
//     - Delegated devices are evaluated against their scoped cert:
//       fetch the cert, run scope.receive against SenderAddress.
//       Devices whose receive matcher rejects the envelope (mode,
//       allow/deny, or rate limit at the matcher level) are
//       excluded from the partition entirely.
//  2. Compute the implicit full-access stage as
//     max(delegated_stages_with_mode_not_none) + 1, taken across
//     ALL delegates with receive.mode != "none" — not just those
//     that allowed THIS envelope. This matches §10.3.3.1's "the
//     maximum is taken over all delegated devices of the account
//     that have a receive matcher whose mode is not none". When no
//     such delegate exists, full-access devices are at stage 1 and
//     staging is a no-op.
//  3. Group eligible devices by stage and emit a sorted, monotonic
//     []StagedHeldStage. Stages with no devices are pruned.
//
// PartitionStages does NOT consult §10.3.3.3 rate-limit counters;
// rate-limit gating is the caller's concern (see
// keys.CheckRateLimit). The matcher mode and allow/deny are checked.
//
// Returns an empty slice if no eligible devices remain (the
// envelope is undeliverable to any device of the account; the
// caller surfaces this as silent or rejected per its own policy).
func PartitionStages(in PartitionInput) ([]StagedHeldStage, error) {
	if in.Directory == nil {
		return nil, errors.New("delivery: nil directory")
	}
	if in.Certs == nil {
		return nil, errors.New("delivery: nil certificate provider")
	}
	if in.EnclosureRecipients == nil {
		return nil, errors.New("delivery: nil enclosure_recipients set")
	}

	type entry struct {
		deviceID string
		stage    int
	}
	var (
		eligible        []entry
		fullAccessIDs   []string
		maxDelegateMode int // max stage over delegates with mode != none
	)
	for _, dev := range in.Directory.Devices {
		recipientWanted := false
		if _, ok := in.EnclosureRecipients[dev.DevicePublicKey]; ok {
			recipientWanted = true
		}

		switch dev.Role {
		case keys.DeviceRoleFullAccess:
			if recipientWanted {
				fullAccessIDs = append(fullAccessIDs, dev.DeviceID)
			}
		case keys.DeviceRoleDelegated:
			cert, err := in.Certs.Certificate(dev.DeviceID)
			if err != nil {
				return nil, fmt.Errorf("delivery: certificate lookup for %q: %w", dev.DeviceID, err)
			}
			if cert == nil {
				// No current cert: per §10.3.7.3 step 3, stop
				// delivering. Skip this device.
				continue
			}
			// max-stage tally first: every delegate whose mode is
			// not "none" contributes to the implicit full-access
			// stage, even if its allow/deny rejects THIS envelope.
			if cert.Scope.Receive.Mode != keys.MatcherModeNone {
				if cert.Scope.Receive.DeliveryStage > maxDelegateMode {
					maxDelegateMode = cert.Scope.Receive.DeliveryStage
				}
			}
			if !recipientWanted {
				continue
			}
			if cert.Scope.Receive.Mode == keys.MatcherModeNone {
				// Receive policy excludes the device entirely.
				continue
			}
			if !cert.Scope.Receive.AllowsSender(in.SenderAddress) {
				// Sender does not pass the matcher; exclude per
				// §3.2.1 "Devices whose scope.receive rejects the
				// envelope (by mode, matcher, or rate limit) are
				// excluded from the partition entirely."
				continue
			}
			stage := cert.Scope.Receive.DeliveryStage
			if stage < 1 {
				// Defensive: a delegated cert without a stage
				// (validate would catch this at issuance, but be
				// safe) gets stage 1 so it does not collide with
				// the full-access implicit stage.
				stage = 1
			}
			eligible = append(eligible, entry{deviceID: dev.DeviceID, stage: stage})
		}
	}

	// Implicit full-access stage per §10.3.3.1 / §3.2.1.
	fullAccessStage := 1
	if maxDelegateMode > 0 {
		fullAccessStage = maxDelegateMode + 1
	}
	for _, id := range fullAccessIDs {
		eligible = append(eligible, entry{deviceID: id, stage: fullAccessStage})
	}

	if len(eligible) == 0 {
		return nil, nil
	}

	// Group by stage and emit a sorted slice.
	byStage := make(map[int][]string)
	for _, e := range eligible {
		byStage[e.stage] = append(byStage[e.stage], e.deviceID)
	}
	stages := make([]int, 0, len(byStage))
	for s := range byStage {
		stages = append(stages, s)
	}
	sort.Ints(stages)
	out := make([]StagedHeldStage, 0, len(stages))
	for _, s := range stages {
		ids := byStage[s]
		sort.Strings(ids) // deterministic device order
		out = append(out, StagedHeldStage{
			Stage:            s,
			PendingDeviceIDs: ids,
		})
	}
	return out, nil
}
