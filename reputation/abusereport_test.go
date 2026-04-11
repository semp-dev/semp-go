package reputation_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/semp-dev/semp-go/crypto"
	"github.com/semp-dev/semp-go/extensions"
	"github.com/semp-dev/semp-go/reputation"
)

// identityFromHeader is a tiny SessionIdentityFunc used by the handler
// tests. It reads the authenticated user identity from a test-only
// header.
func identityFromHeader(r *http.Request) (string, bool) {
	id := r.Header.Get("X-Test-Identity")
	return id, id != ""
}

// buildMetadataReport returns a minimal AbuseReport with
// envelope_metadata evidence, ready to POST.
func buildMetadataReport(reporter, domain string, category reputation.AbuseCategory) reputation.AbuseReport {
	return reputation.AbuseReport{
		Type:           reputation.AbuseReportType,
		Version:        reputation.AbuseReportVersion,
		ID:             "01JTESTREPORT00000000001",
		Reporter:       reporter,
		ReportedDomain: domain,
		Category:       category,
		Timestamp:      time.Now().UTC(),
		Evidence: reputation.Evidence{
			Type:        reputation.EvidenceTypeEnvelopeMetadata,
			PostmarkIDs: []string{"01JPOSTMARK00000000000001"},
			Count:       1,
			Window:      "2026-04-11T11:00:00Z/2026-04-11T12:00:00Z",
		},
		Description: "test report",
		Extensions:  extensions.Map{},
	}
}

// newHandlerHarness constructs a handler backed by a fresh store
// plus an in-process httptest server.
func newHandlerHarness(t *testing.T, cfg reputation.AbuseReportHandlerConfig) (*reputation.ObservationStore, *httptest.Server) {
	t.Helper()
	store := reputation.NewObservationStore(nil)
	cfg.Store = store
	if cfg.SessionIdentity == nil {
		cfg.SessionIdentity = identityFromHeader
	}
	handler := reputation.NewAbuseReportHandler(cfg)
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return store, srv
}

// postReport POSTs the given report with the identity header set.
func postReport(t *testing.T, srv *httptest.Server, report reputation.AbuseReport, identity string) *http.Response {
	t.Helper()
	body, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}
	req, _ := http.NewRequest(http.MethodPost, srv.URL, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if identity != "" {
		req.Header.Set("X-Test-Identity", identity)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	return resp
}

// TestAbuseReportHandlerHappyPath confirms a valid metadata report
// is accepted and recorded in the store.
func TestAbuseReportHandlerHappyPath(t *testing.T) {
	store, srv := newHandlerHarness(t, reputation.AbuseReportHandlerConfig{})
	report := buildMetadataReport("alice@example.com", "spammy.example", reputation.AbuseSpam)

	resp := postReport(t, srv, report, "alice@example.com")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Errorf("status = %d, want 202", resp.StatusCode)
	}

	// Store should now reflect the report.
	m := store.Metrics("spammy.example")
	if m.AbuseReports != 1 {
		t.Errorf("AbuseReports = %d, want 1", m.AbuseReports)
	}
	if len(m.AbuseCategories) != 1 || m.AbuseCategories[0] != reputation.AbuseSpam {
		t.Errorf("AbuseCategories = %v, want [spam]", m.AbuseCategories)
	}
}

// TestAbuseReportHandlerUnauthenticated returns 401 when no identity
// is set on the request.
func TestAbuseReportHandlerUnauthenticated(t *testing.T) {
	_, srv := newHandlerHarness(t, reputation.AbuseReportHandlerConfig{})
	report := buildMetadataReport("alice@example.com", "spammy.example", reputation.AbuseSpam)
	resp := postReport(t, srv, report, "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

// TestAbuseReportHandlerReporterMismatch rejects a report where the
// reporter field does not match the authenticated identity. This is
// the §3.1 "users report to their own home server only" check —
// a client trying to file a report on someone else's behalf must be
// refused.
func TestAbuseReportHandlerReporterMismatch(t *testing.T) {
	_, srv := newHandlerHarness(t, reputation.AbuseReportHandlerConfig{})
	report := buildMetadataReport("bob@example.com", "spammy.example", reputation.AbuseSpam)
	resp := postReport(t, srv, report, "alice@example.com")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}

// TestAbuseReportHandlerWrongType rejects reports whose type field
// is wrong.
func TestAbuseReportHandlerWrongType(t *testing.T) {
	_, srv := newHandlerHarness(t, reputation.AbuseReportHandlerConfig{})
	report := buildMetadataReport("alice@example.com", "spammy.example", reputation.AbuseSpam)
	report.Type = "NOT_A_SEMP_MESSAGE"
	resp := postReport(t, srv, report, "alice@example.com")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

// TestAbuseReportHandlerWrongMethod returns 405 for GET.
func TestAbuseReportHandlerWrongMethod(t *testing.T) {
	_, srv := newHandlerHarness(t, reputation.AbuseReportHandlerConfig{})
	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", resp.StatusCode)
	}
}

// TestAbuseReportHandlerMissingDomain rejects reports missing the
// reported_domain field.
func TestAbuseReportHandlerMissingDomain(t *testing.T) {
	_, srv := newHandlerHarness(t, reputation.AbuseReportHandlerConfig{})
	report := buildMetadataReport("alice@example.com", "", reputation.AbuseSpam)
	resp := postReport(t, srv, report, "alice@example.com")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

// TestAbuseReportHandlerSealedEvidenceWithoutAuthorization rejects
// sealed-evidence reports that include decrypted content but no
// DisclosureAuthorization. This is the §3.7 MUST: "A server MUST NOT
// disclose decrypted envelope content in abuse evidence without the
// explicit, signed authorization of the affected user."
func TestAbuseReportHandlerSealedEvidenceWithoutAuthorization(t *testing.T) {
	_, srv := newHandlerHarness(t, reputation.AbuseReportHandlerConfig{
		Signer: crypto.SuiteBaseline.Signer(),
		UserKeys: func(_ any, _ string) ([]byte, error) {
			return nil, nil // unreachable for this test
		},
	})
	report := buildMetadataReport("alice@example.com", "spammy.example", reputation.AbuseHarassment)
	report.Evidence = reputation.Evidence{
		Type: reputation.EvidenceTypeSealedEvidence,
		Envelopes: []reputation.SealedEnvelopeEvidence{{
			Postmark:       map[string]any{"id": "pm-1"},
			Seal:           map[string]any{"algorithm": "ed25519"},
			DisclosedBrief: map[string]any{"from": "harasser@spammy.example"},
			// DisclosureAuthorization intentionally omitted.
		}},
	}
	resp := postReport(t, srv, report, "alice@example.com")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

// TestDisclosureAuthorizationRoundTrip confirms SignDisclosure +
// VerifyDisclosure under the same key succeeds.
func TestDisclosureAuthorizationRoundTrip(t *testing.T) {
	pub, priv, fp := newObserverKeypair(t)
	auth := &reputation.DisclosureAuthorization{
		User:         "alice@example.com",
		AuthorizedAt: time.Now().UTC(),
		Scope:        reputation.DisclosureScopeBriefOnly,
	}
	if err := reputation.SignDisclosureAuthorization(crypto.SuiteBaseline.Signer(), priv, fp, auth); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := reputation.VerifyDisclosureAuthorization(crypto.SuiteBaseline.Signer(), auth, pub); err != nil {
		t.Errorf("Verify: %v", err)
	}
}

// TestDisclosureAuthorizationScopes exercises the AllowsBrief /
// AllowsEnclosure helpers for each scope value.
func TestDisclosureAuthorizationScopes(t *testing.T) {
	tests := []struct {
		scope        string
		brief, encl  bool
	}{
		{reputation.DisclosureScopeBriefOnly, true, false},
		{reputation.DisclosureScopeEnclosureOnly, false, true},
		{reputation.DisclosureScopeBriefAndEnclosure, true, true},
		{"", false, false},
		{"future-mode", false, false},
	}
	for _, tc := range tests {
		t.Run(tc.scope, func(t *testing.T) {
			auth := &reputation.DisclosureAuthorization{Scope: tc.scope}
			if got := auth.AllowsBrief(); got != tc.brief {
				t.Errorf("AllowsBrief() = %v, want %v", got, tc.brief)
			}
			if got := auth.AllowsEnclosure(); got != tc.encl {
				t.Errorf("AllowsEnclosure() = %v, want %v", got, tc.encl)
			}
		})
	}
}

// TestAbuseReportHandlerSealedEvidenceWithValidAuthorization accepts
// a sealed-evidence report whose DisclosureAuthorization is signed
// by the affected user under a known key.
func TestAbuseReportHandlerSealedEvidenceWithValidAuthorization(t *testing.T) {
	userPub, userPriv, userFP := newObserverKeypair(t)
	store, srv := newHandlerHarness(t, reputation.AbuseReportHandlerConfig{
		Signer: crypto.SuiteBaseline.Signer(),
		UserKeys: func(_ any, user string) ([]byte, error) {
			if user == "alice@example.com" {
				return userPub, nil
			}
			return nil, nil
		},
	})

	auth := &reputation.DisclosureAuthorization{
		User:         "alice@example.com",
		AuthorizedAt: time.Now().UTC(),
		Scope:        reputation.DisclosureScopeBriefOnly,
	}
	if err := reputation.SignDisclosureAuthorization(crypto.SuiteBaseline.Signer(), userPriv, userFP, auth); err != nil {
		t.Fatalf("Sign disclosure: %v", err)
	}

	report := buildMetadataReport("alice@example.com", "spammy.example", reputation.AbuseHarassment)
	report.Evidence = reputation.Evidence{
		Type: reputation.EvidenceTypeSealedEvidence,
		Envelopes: []reputation.SealedEnvelopeEvidence{{
			Postmark:                map[string]any{"id": "pm-1"},
			Seal:                    map[string]any{"algorithm": "ed25519"},
			DisclosedBrief:          map[string]any{"from": "harasser@spammy.example"},
			DisclosureAuthorization: auth,
		}},
	}
	resp := postReport(t, srv, report, "alice@example.com")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Errorf("status = %d, want 202", resp.StatusCode)
	}
	m := store.Metrics("spammy.example")
	if m.AbuseReports != 1 {
		t.Errorf("AbuseReports = %d, want 1", m.AbuseReports)
	}
}

// TestAbuseReportHandlerEvidenceOutsideScope rejects a sealed report
// that discloses enclosure content when the authorization only
// allows brief disclosure.
func TestAbuseReportHandlerEvidenceOutsideScope(t *testing.T) {
	userPub, userPriv, userFP := newObserverKeypair(t)
	_, srv := newHandlerHarness(t, reputation.AbuseReportHandlerConfig{
		Signer: crypto.SuiteBaseline.Signer(),
		UserKeys: func(_ any, user string) ([]byte, error) {
			if user == "alice@example.com" {
				return userPub, nil
			}
			return nil, nil
		},
	})

	auth := &reputation.DisclosureAuthorization{
		User:         "alice@example.com",
		AuthorizedAt: time.Now().UTC(),
		Scope:        reputation.DisclosureScopeBriefOnly,
	}
	_ = reputation.SignDisclosureAuthorization(crypto.SuiteBaseline.Signer(), userPriv, userFP, auth)

	report := buildMetadataReport("alice@example.com", "spammy.example", reputation.AbuseHarassment)
	report.Evidence = reputation.Evidence{
		Type: reputation.EvidenceTypeSealedEvidence,
		Envelopes: []reputation.SealedEnvelopeEvidence{{
			Postmark:                map[string]any{"id": "pm-1"},
			Seal:                    map[string]any{"algorithm": "ed25519"},
			DisclosedEnclosure:      map[string]any{"body": "..."}, // outside scope
			DisclosureAuthorization: auth,
		}},
	}
	resp := postReport(t, srv, report, "alice@example.com")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

// TestKnownAbuseCategory confirms the category predicate.
func TestKnownAbuseCategory(t *testing.T) {
	valid := []reputation.AbuseCategory{
		reputation.AbuseSpam, reputation.AbuseHarassment, reputation.AbusePhishing,
		reputation.AbuseMalware, reputation.AbuseProtocolAbuse,
		reputation.AbuseImpersonation, reputation.AbuseOther,
	}
	for _, c := range valid {
		if !reputation.KnownAbuseCategory(c) {
			t.Errorf("KnownAbuseCategory(%q) = false, want true", c)
		}
	}
	if reputation.KnownAbuseCategory("future-category") {
		t.Error("unknown category should be rejected")
	}
}

// TestAbuseReportPipelineIntegration exercises the full chain: a
// handler that receives a report → writes to the store → the store
// updates its Score → the Score is hostile per the default curve.
// This is the "3oo+3pp end-to-end loop" that was the whole point of
// combining both milestones.
func TestAbuseReportPipelineIntegration(t *testing.T) {
	store, srv := newHandlerHarness(t, reputation.AbuseReportHandlerConfig{})
	// Pre-seed the store with envelope activity so the abuse rate
	// calculation has a nonzero denominator.
	for i := 0; i < 100; i++ {
		store.RecordEnvelope("spammy.example", true)
	}
	// Post 10 abuse reports from 10 different (fake) users. The
	// default classifier trips hostile at ≥ 5% abuse rate, so 10/100
	// should land the domain in hostile.
	for i := 0; i < 10; i++ {
		report := buildMetadataReport("user"+string(rune('0'+i))+"@example.com", "spammy.example", reputation.AbuseSpam)
		// Reuse the same ID suffix cheaply; collision is fine for
		// this test because the handler doesn't dedupe on ID.
		resp := postReport(t, srv, report, report.Reporter)
		resp.Body.Close()
		if resp.StatusCode != http.StatusAccepted {
			t.Fatalf("report[%d] status = %d, want 202", i, resp.StatusCode)
		}
	}
	score := store.Score("spammy.example")
	if score.Assessment != reputation.AssessmentHostile {
		t.Errorf("Assessment = %s, want hostile (abuse_rate=%v)", score.Assessment, score.AbuseRate)
	}
}

var _ = context.Background // keep import if we later add ctx-driven tests
