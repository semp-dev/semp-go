package transparency_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"semp.dev/semp-go/crypto"
	"semp.dev/semp-go/transparency"
)

func newHandlerHarness(t *testing.T) (*httptest.Server, *transparency.Log, []byte) {
	t.Helper()
	signer := crypto.SuiteBaseline.Signer()
	pub, priv, err := signer.GenerateKeyPair()
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	tlog, err := transparency.NewLog(transparency.LogConfig{
		Suite:       crypto.SuiteBaseline,
		DomainKeyID: "log-fp",
		DomainPriv:  priv,
		NowFn:       func() time.Time { return time.Date(2026, 5, 7, 12, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatalf("NewLog: %v", err)
	}
	handler, err := transparency.LogHandler(transparency.LogHandlerConfig{
		Log:      tlog,
		BasePath: "/v1/log",
		AppendAuth: func(r *http.Request) (bool, error) {
			return r.Header.Get("X-Token") == "ok", nil
		},
	})
	if err != nil {
		t.Fatalf("LogHandler: %v", err)
	}
	return httptest.NewServer(handler), tlog, pub
}

func mustEntry(seq int) transparency.LogEntry {
	return transparency.LogEntry{
		Event:        transparency.EventPublish,
		UserID:       fmt.Sprintf("u%d@example.com", seq),
		KeyID:        fmt.Sprintf("fp-%d", seq),
		KeyType:      transparency.KeyTypeIdentity,
		Algorithm:    "ed25519",
		PublicKey:    "AAAA",
		Created:      time.Date(2026, 5, 7, 11, 0, seq, 0, time.UTC),
		LogTimestamp: time.Date(2026, 5, 7, 11, 0, seq, 0, time.UTC),
	}
}

// TestLogHTTPAppendUnauthenticated confirms POST without auth is 401.
func TestLogHTTPAppendUnauthenticated(t *testing.T) {
	srv, _, _ := newHandlerHarness(t)
	defer srv.Close()
	body, _ := json.Marshal(mustEntry(0))
	resp, err := http.Post(srv.URL+"/v1/log/entries", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

// TestLogHTTPAppendAuthenticated drives the happy path.
func TestLogHTTPAppendAuthenticated(t *testing.T) {
	srv, _, _ := newHandlerHarness(t)
	defer srv.Close()
	body, _ := json.Marshal(mustEntry(0))
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/log/entries", bytes.NewReader(body))
	req.Header.Set("X-Token", "ok")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, want 201", resp.StatusCode)
	}
	var got struct {
		LeafIndex int64 `json:"leaf_index"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.LeafIndex != 0 {
		t.Errorf("leaf_index = %d, want 0", got.LeafIndex)
	}
}

// TestLogHTTPSTH confirms GET /sth returns a verifiable STH.
func TestLogHTTPSTH(t *testing.T) {
	srv, tlog, pub := newHandlerHarness(t)
	defer srv.Close()
	for i := 0; i < 3; i++ {
		_, _ = tlog.Append(nil, mustEntry(i))
	}
	resp, err := http.Get(srv.URL + "/v1/log/sth")
	if err != nil { t.Fatalf("HTTP: %v", err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var sth transparency.SignedTreeHead
	if err := json.NewDecoder(resp.Body).Decode(&sth); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if err := transparency.VerifySTH(crypto.SuiteBaseline.Signer(), pub, &sth); err != nil {
		t.Errorf("VerifySTH: %v", err)
	}
	if sth.LogSize != 3 {
		t.Errorf("LogSize = %d, want 3", sth.LogSize)
	}
}

// TestLogHTTPInclusionProof drives the read-side end-to-end.
func TestLogHTTPInclusionProof(t *testing.T) {
	srv, tlog, _ := newHandlerHarness(t)
	defer srv.Close()
	for i := 0; i < 7; i++ {
		_, _ = tlog.Append(nil, mustEntry(i))
	}
	resp, err := http.Get(srv.URL + "/v1/log/proof/inclusion?leaf=3&size=7")
	if err != nil { t.Fatalf("HTTP: %v", err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var proof transparency.InclusionProof
	if err := json.NewDecoder(resp.Body).Decode(&proof); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// Independently fetch an STH and verify the proof.
	resp2, err := http.Get(srv.URL + "/v1/log/sth")
	if err != nil { t.Fatalf("HTTP: %v", err) }
	defer resp2.Body.Close()
	var sth transparency.SignedTreeHead
	_ = json.NewDecoder(resp2.Body).Decode(&sth)
	var root [32]byte
	d, _ := base64.StdEncoding.DecodeString(sth.RootHash)
	copy(root[:], d)
	if err := transparency.VerifyInclusionProof(proof, root); err != nil {
		t.Errorf("VerifyInclusionProof: %v", err)
	}
}

// TestLogHTTPConsistencyProof confirms /proof/consistency answers
// the audit-monitor query.
func TestLogHTTPConsistencyProof(t *testing.T) {
	srv, tlog, _ := newHandlerHarness(t)
	defer srv.Close()
	for i := 0; i < 3; i++ {
		_, _ = tlog.Append(nil, mustEntry(i))
	}
	earlySTH, _ := tlog.IssueSTH(nil)
	for i := 3; i < 8; i++ {
		_, _ = tlog.Append(nil, mustEntry(i))
	}
	laterSTH, _ := tlog.IssueSTH(nil)

	url := fmt.Sprintf("%s/v1/log/proof/consistency?from=%d&to=%d",
		srv.URL, earlySTH.LogSize, laterSTH.LogSize)
	resp, err := http.Get(url)
	if err != nil { t.Fatalf("HTTP: %v", err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var proof transparency.ConsistencyProof
	_ = json.NewDecoder(resp.Body).Decode(&proof)

	var firstRoot, secondRoot [32]byte
	d1, _ := base64.StdEncoding.DecodeString(earlySTH.RootHash)
	copy(firstRoot[:], d1)
	d2, _ := base64.StdEncoding.DecodeString(laterSTH.RootHash)
	copy(secondRoot[:], d2)
	if err := transparency.VerifyConsistencyProof(proof, firstRoot, secondRoot); err != nil {
		t.Errorf("VerifyConsistencyProof: %v", err)
	}
}

// TestLogHTTPEntry confirms GET /entries/<index>.
func TestLogHTTPEntry(t *testing.T) {
	srv, tlog, _ := newHandlerHarness(t)
	defer srv.Close()
	_, _ = tlog.Append(nil, mustEntry(0))
	resp, err := http.Get(srv.URL + "/v1/log/entries/0")
	if err != nil { t.Fatalf("HTTP: %v", err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var got transparency.LogEntry
	_ = json.NewDecoder(resp.Body).Decode(&got)
	if got.UserID != "u0@example.com" {
		t.Errorf("UserID = %q", got.UserID)
	}

	// Out-of-range returns 404.
	resp2, err := http.Get(srv.URL + "/v1/log/entries/99")
	if err != nil { t.Fatalf("HTTP: %v", err) }
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusNotFound {
		t.Errorf("OOB status = %d, want 404", resp2.StatusCode)
	}
}

// TestLogHTTPInclusionProofBadIndex confirms invalid args return 400.
func TestLogHTTPInclusionProofBadIndex(t *testing.T) {
	srv, tlog, _ := newHandlerHarness(t)
	defer srv.Close()
	_, _ = tlog.Append(nil, mustEntry(0))

	resp, err := http.Get(srv.URL + "/v1/log/proof/inclusion?leaf=5&size=1")
	if err != nil { t.Fatalf("HTTP: %v", err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}
