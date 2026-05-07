package recovery_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"semp.dev/semp-go/recovery"
)

// httpHarness wires a BackupHandler with a fresh in-memory store
// for each test.
type httpHarness struct {
	store     recovery.BundleStore
	authOK    bool
	authCalls int
	server    *httptest.Server
}

func newHTTPHarness(t *testing.T, opts ...func(*httpHarness)) *httpHarness {
	t.Helper()
	h := &httpHarness{
		store:  recovery.NewInMemoryBundleStore(),
		authOK: true,
	}
	for _, opt := range opts {
		opt(h)
	}
	handler, err := recovery.BackupHandler(recovery.BackupHandlerConfig{
		Store:    h.store,
		BasePath: "/backup",
		Auth: func(_ *http.Request, _ string) (bool, error) {
			h.authCalls++
			return h.authOK, nil
		},
	})
	if err != nil {
		t.Fatalf("BackupHandler: %v", err)
	}
	h.server = httptest.NewServer(handler)
	t.Cleanup(h.server.Close)
	return h
}

func authFails() func(*httpHarness) {
	return func(h *httpHarness) { h.authOK = false }
}

func bundleForUser(userID, bundleID string, supersedes *string) *recovery.BackupBundle {
	return &recovery.BackupBundle{
		Type:             recovery.BundleType,
		Version:          recovery.RecordVersion,
		UserID:           userID,
		BundleID:         bundleID,
		CreatedAt:        time.Now().UTC().Truncate(time.Second),
		Supersedes:       supersedes,
		KDF: recovery.BundleKDF{
			Algorithm:   recovery.KDFAlgorithmArgon2id,
			Salt:        "AAAAAAAAAAAAAAAAAAAAAA==", // 16+ bytes base64
			MemoryKB:    recovery.MinKDFMemoryKB,
			Iterations:  recovery.MinKDFIterations,
			Parallelism: recovery.MinKDFParallelism,
		},
		PayloadAlgorithm: recovery.BundlePayloadAEAD,
		PayloadNonce:     "AAAAAAAAAAAAAAAAAAAAAAA=",
		EncryptedPayload: "Y2lwaGVydGV4dA==",
		RecoveryVerifyPK: recovery.RecoveryVerifyPK{
			Algorithm: "ed25519",
			PublicKey: "AAAA",
		},
	}
}

// TestBackupHTTPUploadHappyPath drives the §4.2 POST flow.
func TestBackupHTTPUploadHappyPath(t *testing.T) {
	h := newHTTPHarness(t)
	body, _ := json.Marshal(bundleForUser("alice@example.com", "bundle-1", nil))
	resp, err := http.Post(h.server.URL+"/backup/alice%40example.com",
		"application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("status = %d, want 201", resp.StatusCode)
	}
}

// TestBackupHTTPUploadRequiresAuth confirms POST without auth is 401.
func TestBackupHTTPUploadRequiresAuth(t *testing.T) {
	h := newHTTPHarness(t, authFails())
	body, _ := json.Marshal(bundleForUser("alice@example.com", "bundle-1", nil))
	resp, err := http.Post(h.server.URL+"/backup/alice%40example.com",
		"application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

// TestBackupHTTPUploadUserIDMismatch confirms a bundle whose
// user_id does not match the path target is rejected with 403.
func TestBackupHTTPUploadUserIDMismatch(t *testing.T) {
	h := newHTTPHarness(t)
	body, _ := json.Marshal(bundleForUser("bob@example.com", "bundle-1", nil))
	resp, err := http.Post(h.server.URL+"/backup/alice%40example.com",
		"application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}

// TestBackupHTTPDownloadHappyPath confirms GET without history
// returns the current bundle and does NOT require auth (§4.3).
func TestBackupHTTPDownloadHappyPath(t *testing.T) {
	h := newHTTPHarness(t)
	_ = h.store.PutCurrent(context.Background(), "alice@example.com",
		bundleForUser("alice@example.com", "bundle-1", nil), time.Now().UTC())
	resp, err := http.Get(h.server.URL + "/backup/alice%40example.com")
	if err != nil { t.Fatalf("HTTP: %v", err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var b recovery.BackupBundle
	if err := json.NewDecoder(resp.Body).Decode(&b); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if b.BundleID != "bundle-1" {
		t.Errorf("BundleID = %q, want bundle-1", b.BundleID)
	}
}

// TestBackupHTTPDownloadHistoryReturnsAll confirms ?history=true
// returns the array of retained bundles.
func TestBackupHTTPDownloadHistoryReturnsAll(t *testing.T) {
	h := newHTTPHarness(t)
	now := time.Now().UTC()
	id1 := "bundle-1"
	_ = h.store.PutCurrent(context.Background(), "alice@example.com",
		bundleForUser("alice@example.com", id1, nil), now)
	_ = h.store.PutCurrent(context.Background(), "alice@example.com",
		bundleForUser("alice@example.com", "bundle-2", &id1), now.Add(time.Hour))

	resp, err := http.Get(h.server.URL + "/backup/alice%40example.com?history=true")
	if err != nil { t.Fatalf("HTTP: %v", err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var got struct {
		Bundles []*recovery.BackupBundle `json:"bundles"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got.Bundles) != 2 {
		t.Errorf("history = %d, want 2", len(got.Bundles))
	}
}

// TestBackupHTTPDownloadNotFound confirms 404 on a never-uploaded
// user, preserving §4.3 existence-indistinguishability.
func TestBackupHTTPDownloadNotFound(t *testing.T) {
	h := newHTTPHarness(t)
	resp, err := http.Get(h.server.URL + "/backup/ghost%40example.com")
	if err != nil { t.Fatalf("HTTP: %v", err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

// TestBackupHTTPDeleteRequiresAuth confirms DELETE without auth
// is 401.
func TestBackupHTTPDeleteRequiresAuth(t *testing.T) {
	h := newHTTPHarness(t, authFails())
	req, _ := http.NewRequest(http.MethodDelete,
		h.server.URL+"/backup/alice%40example.com", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

// TestBackupHTTPDeleteWipesAll drives DELETE happy path.
func TestBackupHTTPDeleteWipesAll(t *testing.T) {
	h := newHTTPHarness(t)
	_ = h.store.PutCurrent(context.Background(), "alice@example.com",
		bundleForUser("alice@example.com", "bundle-1", nil), time.Now().UTC())
	req, _ := http.NewRequest(http.MethodDelete,
		h.server.URL+"/backup/alice%40example.com", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("status = %d, want 204", resp.StatusCode)
	}
	resp2, err := http.Get(h.server.URL + "/backup/alice%40example.com")
	if err != nil { t.Fatalf("HTTP: %v", err) }
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusNotFound {
		t.Errorf("post-delete GET status = %d, want 404", resp2.StatusCode)
	}
}

// TestBackupHTTPRateLimit confirms the §4.3 rate limiter returns
// 429 when the per-(user, IP) cap is exceeded.
func TestBackupHTTPRateLimit(t *testing.T) {
	store := recovery.NewInMemoryBundleStore()
	_ = store.PutCurrent(context.Background(), "alice@example.com",
		bundleForUser("alice@example.com", "bundle-1", nil), time.Now().UTC())
	limiter := recovery.NewInMemoryBackupRateLimiter(time.Hour, 2)
	handler, _ := recovery.BackupHandler(recovery.BackupHandlerConfig{
		Store:     store,
		BasePath:  "/backup",
		Auth:      func(*http.Request, string) (bool, error) { return true, nil },
		RateLimit: limiter,
	})
	server := httptest.NewServer(handler)
	defer server.Close()
	for i := 0; i < 2; i++ {
		resp, err := http.Get(server.URL + "/backup/alice%40example.com")
		if err != nil { t.Fatalf("HTTP: %v", err) }
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("request %d status = %d, want 200", i+1, resp.StatusCode)
		}
	}
	// Third hit exceeds the cap.
	resp, err := http.Get(server.URL + "/backup/alice%40example.com")
	if err != nil { t.Fatalf("HTTP: %v", err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("rate-limited status = %d, want 429", resp.StatusCode)
	}
	if resp.Header.Get("Retry-After") == "" {
		t.Error("429 response missing Retry-After header")
	}
}

// TestBackupHTTPMethodNotAllowed confirms PUT (or any other verb)
// returns 405 with an Allow header.
func TestBackupHTTPMethodNotAllowed(t *testing.T) {
	h := newHTTPHarness(t)
	req, _ := http.NewRequest(http.MethodPut,
		h.server.URL+"/backup/alice%40example.com", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", resp.StatusCode)
	}
	if got := resp.Header.Get("Allow"); got == "" {
		t.Error("405 missing Allow header")
	}
}

// TestBackupHTTPSupersedesMismatch confirms a stale supersedes
// pointer surfaces as 409 per the BundleStore typed error.
func TestBackupHTTPSupersedesMismatch(t *testing.T) {
	h := newHTTPHarness(t)
	bad := "ghost"
	body, _ := json.Marshal(bundleForUser("alice@example.com", "bundle-1", &bad))
	resp, err := http.Post(h.server.URL+"/backup/alice%40example.com",
		"application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("status = %d, want 409", resp.StatusCode)
	}
}
