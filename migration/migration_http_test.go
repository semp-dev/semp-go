package migration_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"semp.dev/semp-go/crypto"
	"semp.dev/semp-go/migration"
)

// migrationHTTPHarness wires the four-key set + a fresh in-memory
// publication store + a lockout registry around a MigrationHandler.
type migrationHTTPHarness struct {
	kp       keypairs
	store    migration.PublicationStore
	regs     migration.LockoutRegistry
	server   *httptest.Server
}

func newMigrationHTTPHarness(t *testing.T) *migrationHTTPHarness {
	t.Helper()
	h := &migrationHTTPHarness{
		kp:    newKeypairs(t),
		store: migration.NewInMemoryPublicationStore(),
		regs:  migration.NewInMemoryLockoutRegistry(),
	}
	handler, err := migration.MigrationHandler(migration.MigrationHandlerConfig{
		Suite:            crypto.SuiteBaseline,
		BasePath:         "/migration",
		PublicationStore: h.store,
		OldDomainKeyID:   "old-domain-fp",
		OldDomainPriv:    h.kp.oldDomPriv,
		LookupOldIdentityPub: func(_ context.Context, kid string) ([]byte, error) {
			if kid == "old-fp" {
				return h.kp.oldIDPub, nil
			}
			return nil, migration.ErrUnknownIdentityKey
		},
		LookupNewDomainPub: func(_ context.Context, _ string) ([]byte, error) {
			return h.kp.newDomPub, nil
		},
		LookupOldIdentityCreated: func(_ context.Context, _ string) (time.Time, error) {
			return time.Now().UTC().Add(-30 * 24 * time.Hour), nil
		},
		Reservations: h.regs,
	})
	if err != nil {
		t.Fatalf("MigrationHandler: %v", err)
	}
	h.server = httptest.NewServer(handler)
	t.Cleanup(h.server.Close)
	return h
}

// buildSubmissionRecord drives BuildSubmission against the harness's
// keypairs and returns the 3-sig record ready to POST.
func (h *migrationHTTPHarness) buildSubmissionRecord(t *testing.T) *migration.MigrationRecord {
	t.Helper()
	r, err := migration.BuildSubmission(migration.SubmitInput{
		Suite:                crypto.SuiteBaseline,
		OldAddress:           "alice@old.example",
		NewAddress:           "alice@new.example",
		OldIdentityKeyID:     "old-fp",
		NewIdentityKeyID:     "new-fp",
		OldIdentityPriv:      h.kp.oldIDPriv,
		NewIdentityPriv:      h.kp.newIDPriv,
		NewIdentityPublicKey: base64.StdEncoding.EncodeToString(h.kp.newIDPub),
		NewDomainKeyID:       "new-domain-fp",
		NewDomainPriv:        h.kp.newDomPriv,
		OldDomainKeyID:       "old-domain-fp",
		Mode:                 migration.ModeCooperative,
		ForwardingWindow:     migration.RecommendedForwardingWindow,
		MigratedAt:           time.Now().UTC().Truncate(time.Second),
	})
	if err != nil {
		t.Fatalf("BuildSubmission: %v", err)
	}
	return r
}

// TestMigrationHTTPSubmitHappyPath drives the new provider →
// old provider cooperative submission flow over HTTP.
func TestMigrationHTTPSubmitHappyPath(t *testing.T) {
	h := newMigrationHTTPHarness(t)
	r := h.buildSubmissionRecord(t)
	body, _ := json.Marshal(r)
	resp, err := http.Post(h.server.URL+"/migration", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, want 201", resp.StatusCode)
	}
	var final migration.MigrationRecord
	if err := json.NewDecoder(resp.Body).Decode(&final); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if final.OldDomainSignature == nil || final.OldDomainSignature.Value == "" {
		t.Errorf("response missing old_domain_signature")
	}
	// Verify full 4-sig chain.
	if err := migration.VerifyMigrationRecord(crypto.SuiteBaseline.Signer(), &final,
		h.kp.oldIDPub, h.kp.newIDPub, h.kp.newDomPub, h.kp.oldDomPub); err != nil {
		t.Errorf("VerifyMigrationRecord on response: %v", err)
	}
}

// TestMigrationHTTPSubmitDuplicateLockedOut confirms a second
// submission for the same old address while the first is in its
// forwarding window returns 409 per §6.1 / §4.2.
func TestMigrationHTTPSubmitDuplicateLockedOut(t *testing.T) {
	h := newMigrationHTTPHarness(t)
	first := h.buildSubmissionRecord(t)
	body, _ := json.Marshal(first)
	resp, _ := http.Post(h.server.URL+"/migration", "application/json", bytes.NewReader(body))
	resp.Body.Close()

	second := h.buildSubmissionRecord(t)
	body2, _ := json.Marshal(second)
	resp2, _ := http.Post(h.server.URL+"/migration", "application/json", bytes.NewReader(body2))
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusConflict {
		t.Errorf("duplicate status = %d, want 409", resp2.StatusCode)
	}
	if locked, _, found, _ := h.regs.IsLockedOut(context.Background(), "alice", time.Now().UTC()); !found || locked == "" {
		t.Errorf("lockout missing after first submission: locked=%v found=%v", locked, found)
	}
}

// TestMigrationHTTPSubmitUnknownIdentityKey confirms an
// unrecognized old_identity_key_id returns 403.
func TestMigrationHTTPSubmitUnknownIdentityKey(t *testing.T) {
	h := newMigrationHTTPHarness(t)
	r := h.buildSubmissionRecord(t)
	r.OldIdentityKeyID = "ghost"
	body, _ := json.Marshal(r)
	resp, _ := http.Post(h.server.URL+"/migration", "application/json", bytes.NewReader(body))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}

// TestMigrationHTTPSubmitUnilateralRejected confirms unilateral
// records are refused at the old provider's endpoint per §4.2
// (the old provider is not a participant in unilateral migration).
func TestMigrationHTTPSubmitUnilateralRejected(t *testing.T) {
	h := newMigrationHTTPHarness(t)
	r, err := migration.BuildSubmission(migration.SubmitInput{
		Suite:                crypto.SuiteBaseline,
		OldAddress:           "alice@old.example",
		NewAddress:           "alice@new.example",
		OldIdentityKeyID:     "old-fp",
		NewIdentityKeyID:     "new-fp",
		OldIdentityPriv:      h.kp.oldIDPriv,
		NewIdentityPriv:      h.kp.newIDPriv,
		NewIdentityPublicKey: base64.StdEncoding.EncodeToString(h.kp.newIDPub),
		NewDomainKeyID:       "new-domain-fp",
		NewDomainPriv:        h.kp.newDomPriv,
		Mode:                 migration.ModeUnilateral,
		MigratedAt:           time.Now().UTC().Truncate(time.Second),
	})
	if err != nil {
		t.Fatalf("BuildSubmission unilateral: %v", err)
	}
	body, _ := json.Marshal(r)
	resp, _ := http.Post(h.server.URL+"/migration", "application/json", bytes.NewReader(body))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("unilateral status = %d, want 403", resp.StatusCode)
	}
}

// TestMigrationHTTPGetByOldAddress confirms the §3.4 publication
// endpoint returns the most recent record for an old address.
func TestMigrationHTTPGetByOldAddress(t *testing.T) {
	h := newMigrationHTTPHarness(t)
	r := h.buildSubmissionRecord(t)
	body, _ := json.Marshal(r)
	resp, _ := http.Post(h.server.URL+"/migration", "application/json", bytes.NewReader(body))
	resp.Body.Close()

	resp2, _ := http.Get(h.server.URL + "/migration/alice%40old.example")
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("GET status = %d, want 200", resp2.StatusCode)
	}
	var got migration.MigrationRecord
	if err := json.NewDecoder(resp2.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.OldAddress != "alice@old.example" {
		t.Errorf("OldAddress = %q", got.OldAddress)
	}
}

// TestMigrationHTTPGetByRecordID confirms /by-id/<record_id>
// returns the record.
func TestMigrationHTTPGetByRecordID(t *testing.T) {
	h := newMigrationHTTPHarness(t)
	r := h.buildSubmissionRecord(t)
	body, _ := json.Marshal(r)
	resp, _ := http.Post(h.server.URL+"/migration", "application/json", bytes.NewReader(body))
	resp.Body.Close()

	resp2, _ := http.Get(h.server.URL + "/migration/by-id/" + r.RecordID)
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("GET status = %d, want 200", resp2.StatusCode)
	}
}

// TestMigrationHTTPGetUnknown returns 404 for a missing address
// or record_id.
func TestMigrationHTTPGetUnknown(t *testing.T) {
	h := newMigrationHTTPHarness(t)
	resp, _ := http.Get(h.server.URL + "/migration/ghost%40nowhere.example")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

// TestPublicationStoreSentinelError confirms a typed error from a
// custom store still surfaces as 500.
func TestPublicationStoreSentinelError(t *testing.T) {
	failingStore := failingPubStore{err: errors.New("disk full")}
	handler, err := migration.MigrationHandler(migration.MigrationHandlerConfig{
		Suite:                    crypto.SuiteBaseline,
		BasePath:                 "/migration",
		PublicationStore:         failingStore,
		OldDomainKeyID:           "fp",
		OldDomainPriv:            []byte("p"),
		LookupOldIdentityPub:     func(context.Context, string) ([]byte, error) { return []byte("k"), nil },
		LookupNewDomainPub:       func(context.Context, string) ([]byte, error) { return []byte("k"), nil },
		LookupOldIdentityCreated: func(context.Context, string) (time.Time, error) { return time.Now(), nil },
		Reservations:             migration.NewInMemoryLockoutRegistry(),
	})
	if err != nil {
		t.Fatalf("MigrationHandler: %v", err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()
	resp, _ := http.Get(server.URL + "/migration/alice%40old.example")
	defer resp.Body.Close()
	// GetByOldAddress returns disk-full → 500.
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("store error: status = %d, want 500", resp.StatusCode)
	}
}

type failingPubStore struct{ err error }

func (f failingPubStore) PutRecord(context.Context, *migration.MigrationRecord) error {
	return f.err
}
func (f failingPubStore) GetByOldAddress(context.Context, string) (*migration.MigrationRecord, error) {
	return nil, f.err
}
func (f failingPubStore) GetByRecordID(context.Context, string) (*migration.MigrationRecord, error) {
	return nil, f.err
}
