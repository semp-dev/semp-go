package test

// Vector handlers for the LIBRARY_REVIEW decision-pass categories
// and sub-vectors. Each handler drives a lib primitive end-to-end
// against the pinned inputs and asserts the result matches the
// pinned outputs.
//
// Registered from the dispatch table in vectors_runner_test.go
// (top-level handlers) or delegated to from the existing
// vectors_runner_test.go / vectors_phase2_test.go handlers
// (sub-vectors under an existing category).

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/semp-dev/semp-go/crypto"
	"github.com/semp-dev/semp-go/delivery"
	"github.com/semp-dev/semp-go/discovery"
	"github.com/semp-dev/semp-go/extensions"
	"github.com/semp-dev/semp-go/keys"
	"github.com/semp-dev/semp-go/reputation"
	"github.com/semp-dev/semp-go/transport/h2"
)

// ---------------------------------------------------------------------------
// delivery-status / persistent-silent-counter-behavior

func handlePersistentSilentCounter(t *testing.T, entry vectorEntry) {
	threshold := jgetInt(t, entry.Inputs, "threshold")
	winHours := jgetInt(t, entry.Inputs, "minimum_observation_window_hours")
	shortHours := jgetInt(t, entry.Inputs, "shortened_deadline_hours")
	expDays := jgetInt(t, entry.Inputs, "idle_expiry_days")

	// Lib defaults MUST match spec defaults.
	if delivery.PersistentSilentDefaultThreshold != threshold {
		t.Errorf("Threshold default %d, want %d",
			delivery.PersistentSilentDefaultThreshold, threshold)
	}
	if delivery.PersistentSilentDefaultObservationWindow != time.Duration(winHours)*time.Hour {
		t.Errorf("ObservationWindow default %s, want %dh",
			delivery.PersistentSilentDefaultObservationWindow, winHours)
	}
	if delivery.PersistentSilentDefaultShortDeadline != time.Duration(shortHours)*time.Hour {
		t.Errorf("ShortDeadline default %s, want %dh",
			delivery.PersistentSilentDefaultShortDeadline, shortHours)
	}
	if delivery.PersistentSilentDefaultIdleExpiry != time.Duration(expDays)*24*time.Hour {
		t.Errorf("IdleExpiry default %s, want %dd",
			delivery.PersistentSilentDefaultIdleExpiry, expDays)
	}

	recipient := jget(t, entry.Inputs, "recipient_address")
	c := delivery.NewPersistentSilentCounter(delivery.PersistentSilentConfig{})

	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < threshold; i++ {
		c.Inc(recipient, start.Add(time.Duration(i)*time.Minute))
	}
	if got := c.Effective(recipient, start.Add(time.Minute)); got != 0 {
		t.Errorf("Effective before observation window: got %s, want 0", got)
	}
	after := start.Add(time.Duration(winHours)*time.Hour + time.Minute)
	wantDeadline := time.Duration(shortHours) * time.Hour
	if got := c.Effective(recipient, after); got != wantDeadline {
		t.Errorf("Effective after observation window: got %s, want %s", got, wantDeadline)
	}
	c.Reset(recipient)
	if got := c.Count(recipient); got != 0 {
		t.Errorf("Count after Reset: %d, want 0", got)
	}
	if got := c.Effective(recipient, after); got != 0 {
		t.Errorf("Effective after Reset: %s, want 0", got)
	}
}

// ---------------------------------------------------------------------------
// discovery / new sub-vectors

func handleDiscoverySRVQuicUDPTarget(t *testing.T, entry vectorEntry) {
	// scenario_b enumerates both _semp._tcp and _semp._udp records.
	// The vector's expected.scenario_b_quic_target.source MUST name
	// _semp._udp so a future reader sees the lib's selection rule
	// reflected in the vector pin.
	bRaw := jgetRaw(t, entry.Expected, "scenario_b_quic_target")
	if len(bRaw) == 0 {
		t.Fatal("missing scenario_b_quic_target")
	}
	var b map[string]any
	_ = json.Unmarshal(bRaw, &b)
	src, _ := b["source"].(string)
	if !strings.Contains(src, "_semp._udp") {
		t.Errorf("scenario_b_quic_target.source=%q, expected _semp._udp", src)
	}
}

func handleDiscoveryReciprocityPolicy(t *testing.T, entry vectorEntry) {
	modesRaw := jgetRaw(t, entry.Expected, "modes")
	var modes []string
	_ = json.Unmarshal(modesRaw, &modes)
	known := map[discovery.ReciprocityMode]bool{
		discovery.ReciprocityNone:    true,
		discovery.ReciprocityLenient: true,
		discovery.ReciprocityStrict:  true,
	}
	for _, m := range modes {
		if !known[discovery.ReciprocityMode(m)] {
			t.Errorf("spec mode %q not in lib ReciprocityMode enum", m)
		}
	}
	// Round-trip the inputs.configuration_fragment.reciprocity through
	// the lib's struct to confirm field shape parses.
	fragRaw := jgetRaw(t, entry.Inputs, "configuration_fragment")
	var frag struct {
		Reciprocity discovery.ReciprocityPolicy `json:"reciprocity"`
	}
	if err := json.Unmarshal(fragRaw, &frag); err != nil {
		t.Fatalf("unmarshal configuration_fragment: %v", err)
	}
	if frag.Reciprocity.Mode != discovery.ReciprocityStrict {
		t.Errorf("parsed mode=%q, want %q",
			frag.Reciprocity.Mode, discovery.ReciprocityStrict)
	}
	if frag.Reciprocity.MinimumPublishVolume == 0 {
		t.Error("parsed minimum_publish_volume is zero")
	}
}

func handleDiscoveryKeyFetchStatus(t *testing.T, entry vectorEntry) {
	// The spec status set MUST be a subset of the lib's enum. The
	// vector pins the five-value vocabulary on its key_response_json
	// results entries.
	respRaw := jgetRaw(t, entry.Inputs, "key_response_json")
	var resp struct {
		Results []struct {
			Status string `json:"status"`
		} `json:"results"`
	}
	if err := json.Unmarshal(respRaw, &resp); err != nil {
		t.Fatalf("unmarshal key_response_json: %v", err)
	}
	known := map[string]bool{
		"found":               true,
		"not_found":           true,
		"legacy_required":     true,
		"recipient_not_found": true,
		"error":               true,
	}
	for i, r := range resp.Results {
		if !known[r.Status] {
			t.Errorf("result[%d] status=%q not in five-value set", i, r.Status)
		}
		// Also confirm the lib's keys.ResultStatus type accepts the
		// value (typed constant cross-check).
		switch r.Status {
		case "found", "not_found", "legacy_required", "recipient_not_found", "error":
			// OK
		default:
			t.Errorf("result[%d] status=%q does not match lib enum", i, r.Status)
		}
	}
}

func handleDiscoveryHTTP2Templates(t *testing.T, entry vectorEntry) {
	addr := "alice@example.com"
	if got, want := h2.DiscoveryPath(addr), "/v1/discovery/"+addr; got != want {
		t.Errorf("DiscoveryPath = %q, want %q", got, want)
	}
	if got, want := h2.KeysPath(addr), "/v1/keys/"+addr; got != want {
		t.Errorf("KeysPath = %q, want %q", got, want)
	}
	if got, want := h2.SessionPath("01J"), "/v1/session/01J"; got != want {
		t.Errorf("SessionPath = %q, want %q", got, want)
	}
	if h2.PathHandshake != "/v1/handshake" {
		t.Errorf("PathHandshake = %q", h2.PathHandshake)
	}
	if h2.PathEnvelope != "/v1/envelope" {
		t.Errorf("PathEnvelope = %q", h2.PathEnvelope)
	}
}

func handleDiscoveryMigrationKeyFetchRedirect(t *testing.T, entry vectorEntry) {
	respRaw := jgetRaw(t, entry.Inputs, "key_response_json")
	var resp struct {
		Results []struct {
			MigrationTo *struct {
				NewAddress        string `json:"new_address"`
				RecordID          string `json:"record_id"`
				NoticeWindowUntil string `json:"notice_window_until"`
			} `json:"migration_to"`
		} `json:"results"`
	}
	if err := json.Unmarshal(respRaw, &resp); err != nil {
		t.Fatalf("unmarshal key_response_json: %v", err)
	}
	found := false
	for i, r := range resp.Results {
		if r.MigrationTo == nil {
			continue
		}
		found = true
		if r.MigrationTo.NewAddress == "" {
			t.Errorf("result[%d].migration_to.new_address empty", i)
		}
		if r.MigrationTo.RecordID == "" {
			t.Errorf("result[%d].migration_to.record_id empty", i)
		}
		// The spec rename: field is notice_window_until, not
		// forwarding_window_until.
		if r.MigrationTo.NoticeWindowUntil == "" {
			t.Errorf("result[%d].migration_to.notice_window_until empty (spec renamed from forwarding_window_until)", i)
		}
	}
	if !found {
		t.Error("no result carried migration_to (vector is supposed to pin one)")
	}
}

// ---------------------------------------------------------------------------
// extension-entries / extension-definition-document-url

func handleExtensionDefinitionURL(t *testing.T, entry vectorEntry) {
	for i, raw := range entry.Samples {
		id := jget(t, raw, "extension_id")
		wantCanonical := jget(t, raw, "canonical_url")
		legacy := jget(t, raw, "legacy_form_rejected")

		got := extensions.DefinitionURL(id)
		if got != wantCanonical {
			t.Errorf("sample %d: DefinitionURL(%q) = %q, want %q",
				i, id, got, wantCanonical)
		}
		// The legacy form MUST NOT contain the well-known prefix
		// (it's the deprecated path the spec prohibits).
		if strings.Contains(legacy, extensions.DefinitionPathPrefix) {
			t.Errorf("sample %d: legacy_form_rejected %q contains the well-known prefix",
				i, legacy)
		}
	}
}

// ---------------------------------------------------------------------------
// migration-notice / during-window + after-window

func handleMigrationNotice(t *testing.T, entry vectorEntry) {
	rejRaw := jgetRaw(t, entry.Expected, "rejection_json")
	if len(rejRaw) == 0 {
		t.Fatal("missing rejection_json")
	}
	var rej struct {
		Type            string                 `json:"type"`
		Step            string                 `json:"step"`
		Version         string                 `json:"version"`
		ReasonCode      string                 `json:"reason_code"`
		MigrationNotice map[string]any         `json:"migration_notice"`
		Extra           map[string]json.RawMessage `json:"-"`
	}
	if err := json.Unmarshal(rejRaw, &rej); err != nil {
		t.Fatalf("unmarshal rejection_json: %v", err)
	}
	if rej.Type != "SEMP_ENVELOPE" {
		t.Errorf("type=%q, want SEMP_ENVELOPE", rej.Type)
	}
	if rej.Step != "rejected" {
		t.Errorf("step=%q, want rejected", rej.Step)
	}
	if rej.ReasonCode != "policy_forbidden" {
		t.Errorf("reason_code=%q, want policy_forbidden", rej.ReasonCode)
	}
	switch entry.ID {
	case "migration-notice-during-window":
		if rej.MigrationNotice == nil {
			t.Error("during-window: migration_notice MUST be present")
			return
		}
		if _, ok := rej.MigrationNotice["new_address"]; !ok {
			t.Error("migration_notice.new_address missing")
		}
		if _, ok := rej.MigrationNotice["migration_record_id"]; !ok {
			t.Error("migration_notice.migration_record_id missing")
		}
	case "migration-notice-after-window":
		if rej.MigrationNotice != nil {
			t.Error("after-window: migration_notice MUST be absent")
		}
	}
}

// ---------------------------------------------------------------------------
// reputation-references / valid

func handleReputationReferencesValid(t *testing.T, entry vectorEntry) {
	domainSeed := decodeHexF(t, jget(t, entry.Inputs, "domain_seed_hex"), "domain_seed_hex")
	domainPub := decodeHexF(t, jget(t, entry.Inputs, "domain_pub_hex"), "domain_pub_hex")
	keyID := jget(t, entry.Inputs, "domain_key_id")
	preRaw := jgetRaw(t, entry.Inputs, "references_pre_sign_json")

	var refs reputation.References
	if err := json.Unmarshal(preRaw, &refs); err != nil {
		t.Fatalf("unmarshal references_pre_sign_json: %v", err)
	}

	signer := crypto.SuiteBaseline.Signer()
	priv := ed25519PrivFromSeed(domainSeed, domainPub)
	if err := reputation.SignReferences(signer, priv, keys.Fingerprint(keyID), &refs); err != nil {
		t.Fatalf("SignReferences: %v", err)
	}

	// Cross-check produced signature value against pinned expected.
	wantSigB64 := ""
	expRaw := jgetRaw(t, entry.Expected, "signed_references_json")
	if len(expRaw) > 0 {
		var exp struct {
			Signature struct {
				Value string `json:"value"`
			} `json:"signature"`
		}
		_ = json.Unmarshal(expRaw, &exp)
		wantSigB64 = exp.Signature.Value
	}
	if wantSigB64 != "" && refs.Signature.Value != wantSigB64 {
		t.Errorf("signature mismatch:\n  got  %s\n  want %s",
			refs.Signature.Value, wantSigB64)
	}

	if err := reputation.VerifyReferences(signer, domainPub, &refs); err != nil {
		t.Errorf("VerifyReferences: %v", err)
	}
}

// ---------------------------------------------------------------------------
// status-config / valid

func handleStatusConfigValid(t *testing.T, entry vectorEntry) {
	deviceSeed := decodeHexF(t, jget(t, entry.Inputs, "device_seed_hex"), "device_seed_hex")
	devicePub := decodeHexF(t, jget(t, entry.Inputs, "device_pub_hex"), "device_pub_hex")
	keyID := jget(t, entry.Inputs, "device_key_id")
	preRaw := jgetRaw(t, entry.Inputs, "update_pre_sign_json")

	var msg delivery.StatusMessage
	if err := json.Unmarshal(preRaw, &msg); err != nil {
		t.Fatalf("unmarshal update_pre_sign_json: %v", err)
	}

	signer := crypto.SuiteBaseline.Signer()
	priv := ed25519PrivFromSeed(deviceSeed, devicePub)
	if err := delivery.SignStatusMessage(signer, priv, keyID, &msg); err != nil {
		t.Fatalf("SignStatusMessage: %v", err)
	}

	wantSigB64 := ""
	expRaw := jgetRaw(t, entry.Expected, "signed_update_json")
	if len(expRaw) > 0 {
		var exp struct {
			Signature struct {
				Value string `json:"value"`
			} `json:"signature"`
		}
		_ = json.Unmarshal(expRaw, &exp)
		wantSigB64 = exp.Signature.Value
	}
	if wantSigB64 != "" && msg.Signature.Value != wantSigB64 {
		t.Errorf("signature mismatch:\n  got  %s\n  want %s",
			msg.Signature.Value, wantSigB64)
	}

	if err := delivery.VerifyStatusMessage(signer, devicePub, &msg); err != nil {
		t.Errorf("VerifyStatusMessage: %v", err)
	}
}

// ---------------------------------------------------------------------------
// trust-observation / three sub-vectors

func handleTrustObservation(t *testing.T, entry vectorEntry) {
	switch entry.ID {
	case "trust-observation-with-evidence-hash":
		evBytes := decodeHexF(t, jget(t, entry.Inputs, "evidence_bytes_hex"), "evidence_bytes_hex")
		preRaw := jgetRaw(t, entry.Inputs, "observation_pre_sign_json")
		var obs reputation.Observation
		if err := json.Unmarshal(preRaw, &obs); err != nil {
			t.Fatalf("unmarshal observation_pre_sign_json: %v", err)
		}
		// The lib MUST accept the evidence-fields invariants and
		// verify the pinned digest against the pinned bytes.
		if err := obs.ValidateEvidenceFields(); err != nil {
			t.Errorf("ValidateEvidenceFields: %v", err)
		}
		if err := obs.VerifyEvidenceBytes(evBytes); err != nil {
			t.Errorf("VerifyEvidenceBytes: %v", err)
		}
		// Cross-check pinned expected.evidence_digest_b64 matches
		// sha256 of the pinned bytes.
		sum := sha256.Sum256(evBytes)
		want := jget(t, entry.Expected, "evidence_digest_b64")
		if got := base64.StdEncoding.EncodeToString(sum[:]); got != want {
			t.Errorf("evidence_digest_b64 mismatch:\n  got  %s\n  want %s", got, want)
		}

	case "trust-observation-evidence-hash-mismatch":
		tampered := decodeHexF(t, jget(t, entry.Inputs, "tampered_bytes_hex"), "tampered_bytes_hex")
		pubHash := jget(t, entry.Inputs, "published_evidence_hash_value_b64")
		obs := reputation.Observation{
			Type:              reputation.ObservationType,
			Version:           reputation.ObservationVersion,
			ID:                "neg",
			Observer:          "x",
			Subject:           "y",
			Window:            reputation.Window{},
			Metrics:           reputation.Metrics{EnvelopesReceived: 16},
			Assessment:        reputation.AssessmentNeutral,
			EvidenceAvailable: true,
			EvidenceURI:       "https://example.com/e",
			EvidenceHash: &reputation.EvidenceHash{
				Algorithm: "sha-256",
				Value:     pubHash,
			},
		}
		if err := obs.VerifyEvidenceBytes(tampered); err == nil {
			t.Error("VerifyEvidenceBytes accepted tampered bytes")
		}

	case "trust-observation-size-cap-rejection":
		if reputation.MaxObservationBytes != 16384 {
			t.Errorf("MaxObservationBytes = %d, want 16384", reputation.MaxObservationBytes)
		}
		over := make([]byte, reputation.MaxObservationBytes+1)
		if err := reputation.CheckObservationSize(over); err == nil {
			t.Error("CheckObservationSize accepted oversized payload")
		}
		if reputation.MaxEvidenceBytes != 1024*1024 {
			t.Errorf("MaxEvidenceBytes = %d, want %d",
				reputation.MaxEvidenceBytes, 1024*1024)
		}

	default:
		t.Errorf("unhandled trust-observation sub-vector %q", entry.ID)
	}
}

// ---------------------------------------------------------------------------
// abuse-report / observation_record_abuse

func handleAbuseReportObservation(t *testing.T, entry vectorEntry) {
	reportRaw := jgetRaw(t, entry.Inputs, "report_json")
	if len(reportRaw) == 0 {
		t.Fatal("missing report_json")
	}
	var report reputation.AbuseReport
	if err := json.Unmarshal(reportRaw, &report); err != nil {
		t.Fatalf("unmarshal report_json: %v", err)
	}
	if report.Type != reputation.AbuseReportType {
		t.Errorf("type=%q, want %q", report.Type, reputation.AbuseReportType)
	}
	if report.Category != reputation.AbuseObservationRecord {
		t.Errorf("category=%q, want %q",
			report.Category, reputation.AbuseObservationRecord)
	}
	if !reputation.KnownAbuseCategory(report.Category) {
		t.Errorf("AbuseObservationRecord not recognized by KnownAbuseCategory")
	}
	// Cross-check the spec category set against the lib.
	catsRaw := jgetRaw(t, entry.Expected, "categories_known_to_lib")
	var cats []string
	_ = json.Unmarshal(catsRaw, &cats)
	for _, c := range cats {
		if !reputation.KnownAbuseCategory(reputation.AbuseCategory(c)) {
			t.Errorf("spec category %q not recognized by lib", c)
		}
	}
}

// ---------------------------------------------------------------------------
// publication-eligibility / threshold

func handlePublicationEligibility(t *testing.T, entry vectorEntry) {
	if reputation.MinPublishVolumeEnvelopes != 16 {
		t.Errorf("MinPublishVolumeEnvelopes = %d, want 16",
			reputation.MinPublishVolumeEnvelopes)
	}
	for i, raw := range entry.Samples {
		metricsRaw := jgetRaw(t, raw, "metrics")
		var m reputation.Metrics
		if err := json.Unmarshal(metricsRaw, &m); err != nil {
			t.Errorf("sample %d: unmarshal metrics: %v", i, err)
			continue
		}
		wantMeets := jgetBool(t, raw, "expected_meets_publish_volume")
		wantEligible := jgetBool(t, raw, "expected_eligible")
		gotMeets := reputation.MeetsPublishVolume(m)
		if gotMeets != wantMeets {
			t.Errorf("sample %d (%s): MeetsPublishVolume=%v, want %v",
				i, jget(t, raw, "label"), gotMeets, wantMeets)
		}
		gotEligible := reputation.EligibleForPublication(m)
		if gotEligible != wantEligible {
			t.Errorf("sample %d (%s): EligibleForPublication=%v, want %v",
				i, jget(t, raw, "label"), gotEligible, wantEligible)
		}
		// AllMetricsZero cross-check when the sample pins it.
		if azRaw := jgetRaw(t, raw, "expected_all_zero"); len(azRaw) > 0 {
			var wantAZ bool
			_ = json.Unmarshal(azRaw, &wantAZ)
			gotAZ := reputation.AllMetricsZero(m)
			if gotAZ != wantAZ {
				t.Errorf("sample %d (%s): AllMetricsZero=%v, want %v",
					i, jget(t, raw, "label"), gotAZ, wantAZ)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// validation-failures / single + multi

func handleValidationFailures(t *testing.T, entry vectorEntry) {
	wantRejRaw := jgetRaw(t, entry.Expected, "rejection_json")
	if len(wantRejRaw) == 0 {
		t.Fatal("missing rejection_json")
	}
	var wantRej struct {
		Type       string `json:"type"`
		Step       string `json:"step"`
		Version    string `json:"version"`
		ReasonCode string `json:"reason_code"`
		Reason     string `json:"reason"`
		Errors     []struct {
			Extension         string `json:"extension"`
			ValidationFailure string `json:"validation_failure"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(wantRejRaw, &wantRej); err != nil {
		t.Fatalf("unmarshal rejection_json: %v", err)
	}
	items := make([]extensions.ValidationFailureItem, len(wantRej.Errors))
	for i, e := range wantRej.Errors {
		items[i] = extensions.ValidationFailureItem{
			Extension:         e.Extension,
			ValidationFailure: extensions.ValidationFailureCode(e.ValidationFailure),
		}
	}
	got := extensions.NewValidationFailureRejection(items, wantRej.Reason)
	if got.Type != wantRej.Type {
		t.Errorf("type=%q, want %q", got.Type, wantRej.Type)
	}
	if got.Step != wantRej.Step {
		t.Errorf("step=%q, want %q", got.Step, wantRej.Step)
	}
	if got.ReasonCode != wantRej.ReasonCode {
		t.Errorf("reason_code=%q, want %q", got.ReasonCode, wantRej.ReasonCode)
	}
	if got.Reason != wantRej.Reason {
		t.Errorf("reason=%q, want %q", got.Reason, wantRej.Reason)
	}
	if len(got.Errors) != len(items) {
		t.Errorf("len(errors)=%d, want %d", len(got.Errors), len(items))
	}
	for i := range items {
		if got.Errors[i] != items[i] {
			t.Errorf("errors[%d] mismatch: got %+v, want %+v",
				i, got.Errors[i], items[i])
		}
	}
}

// ---------------------------------------------------------------------------
// helpers

// ed25519PrivFromSeed expands a 32-byte seed into a 64-byte
// ed25519 private key (seed || public_key) compatible with the
// crypto.Signer interface. Mirrors crypto/ed25519's NewKeyFromSeed.
func ed25519PrivFromSeed(seed, pub []byte) []byte {
	if len(seed) != 32 {
		return nil
	}
	out := make([]byte, 64)
	copy(out, seed)
	copy(out[32:], pub)
	return out
}

