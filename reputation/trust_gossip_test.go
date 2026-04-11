package reputation_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/semp-dev/semp-go/crypto"
	"github.com/semp-dev/semp-go/extensions"
	"github.com/semp-dev/semp-go/keys"
	"github.com/semp-dev/semp-go/reputation"
)

// signedSample is a helper that returns a fresh sample Observation
// already signed under (pub, priv, fp).
func signedSample(t *testing.T, id string, priv []byte, fp keys.Fingerprint) reputation.Observation {
	t.Helper()
	now := time.Date(2026, 4, 11, 12, 0, 0, 0, time.UTC)
	obs := reputation.Observation{
		Type:     reputation.ObservationType,
		Version:  reputation.ObservationVersion,
		ID:       id,
		Observer: "observer.example",
		Subject:  "subject.example",
		Window: reputation.Window{
			Start: now.Add(-30 * 24 * time.Hour),
			End:   now,
		},
		Metrics: reputation.Metrics{
			EnvelopesReceived: 100,
			EnvelopesRejected: 2,
		},
		Assessment: reputation.AssessmentNeutral,
		Timestamp:  now,
		Expires:    now.Add(24 * time.Hour),
		Extensions: extensions.Map{},
	}
	if err := reputation.SignObservation(crypto.SuiteBaseline.Signer(), priv, fp, &obs); err != nil {
		t.Fatalf("SignObservation: %v", err)
	}
	return obs
}

// TestSignTrustObservationsRoundTrip confirms envelope-level sign +
// verify succeeds.
func TestSignTrustObservationsRoundTrip(t *testing.T) {
	pub, priv, fp := newObserverKeypair(t)
	resp := &reputation.TrustObservations{
		Subject: "subject.example",
		Observations: []reputation.Observation{
			signedSample(t, "obs-1", priv, fp),
		},
	}
	if err := reputation.SignTrustObservations(crypto.SuiteBaseline.Signer(), priv, fp, resp); err != nil {
		t.Fatalf("SignTrustObservations: %v", err)
	}
	if resp.Type != reputation.ObservationsType {
		t.Errorf("Type = %q, want %q", resp.Type, reputation.ObservationsType)
	}
	if err := reputation.VerifyTrustObservations(crypto.SuiteBaseline.Signer(), resp, pub); err != nil {
		t.Errorf("VerifyTrustObservations: %v", err)
	}
}

// TestVerifyTrustObservationsTampered confirms mutating an
// observation inside a signed envelope breaks the envelope signature.
func TestVerifyTrustObservationsTampered(t *testing.T) {
	pub, priv, fp := newObserverKeypair(t)
	resp := &reputation.TrustObservations{
		Subject: "subject.example",
		Observations: []reputation.Observation{
			signedSample(t, "obs-1", priv, fp),
		},
	}
	if err := reputation.SignTrustObservations(crypto.SuiteBaseline.Signer(), priv, fp, resp); err != nil {
		t.Fatalf("SignTrustObservations: %v", err)
	}
	resp.Observations[0].Subject = "attacker.example"
	if err := reputation.VerifyTrustObservations(crypto.SuiteBaseline.Signer(), resp, pub); err == nil {
		t.Error("tampered observation should have broken envelope signature")
	}
}

// TestPublicationHandlerServesSignedResponse runs the handler end-to-
// end through httptest and confirms the served bytes are a signed
// TrustObservations envelope verifiable by the client.
func TestPublicationHandlerServesSignedResponse(t *testing.T) {
	pub, priv, fp := newObserverKeypair(t)

	source := reputation.NewInMemoryObservationSource()
	source.Put("subject.example", []reputation.Observation{
		signedSample(t, "obs-1", priv, fp),
		signedSample(t, "obs-2", priv, fp),
	})

	handler := reputation.NewPublicationHandler(reputation.PublicationHandlerConfig{
		Source:        source,
		Signer:        crypto.SuiteBaseline.Signer(),
		PrivateKey:    priv,
		ObserverKeyID: fp,
	})
	srv := httptest.NewServer(handler)
	defer srv.Close()

	// End-to-end fetch via the client helper.
	resp, err := reputation.Fetch(context.Background(), reputation.FetcherConfig{
		Signer:            crypto.SuiteBaseline.Signer(),
		ObserverPublicKey: pub,
	}, srv.URL, "subject.example")
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if resp.Subject != "subject.example" {
		t.Errorf("Subject = %q, want subject.example", resp.Subject)
	}
	if len(resp.Observations) != 2 {
		t.Errorf("Observations length = %d, want 2", len(resp.Observations))
	}
}

// TestPublicationHandlerEmptySubject returns 400 when no subject is
// present in the path.
func TestPublicationHandlerEmptySubject(t *testing.T) {
	_, priv, fp := newObserverKeypair(t)
	source := reputation.NewInMemoryObservationSource()
	handler := reputation.NewPublicationHandler(reputation.PublicationHandlerConfig{
		Source:        source,
		Signer:        crypto.SuiteBaseline.Signer(),
		PrivateKey:    priv,
		ObserverKeyID: fp,
	})
	srv := httptest.NewServer(handler)
	defer srv.Close()

	r, _ := http.NewRequest(http.MethodGet, srv.URL+reputation.PublicationPath, nil)
	resp, err := srv.Client().Do(r)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

// TestPublicationHandlerWrongMethod returns 405 for POST.
func TestPublicationHandlerWrongMethod(t *testing.T) {
	_, priv, fp := newObserverKeypair(t)
	source := reputation.NewInMemoryObservationSource()
	handler := reputation.NewPublicationHandler(reputation.PublicationHandlerConfig{
		Source:        source,
		Signer:        crypto.SuiteBaseline.Signer(),
		PrivateKey:    priv,
		ObserverKeyID: fp,
	})
	srv := httptest.NewServer(handler)
	defer srv.Close()
	resp, err := http.Post(srv.URL+reputation.PublicationPath+"subject.example", "application/json", strings.NewReader(""))
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", resp.StatusCode)
	}
}

// TestFetchRejectsForgedEnvelope confirms that a response signed
// under the wrong key is rejected by the fetcher.
func TestFetchRejectsForgedEnvelope(t *testing.T) {
	_, attackerPriv, attackerFP := newObserverKeypair(t)
	realPub, _, _ := newObserverKeypair(t) // the legitimate observer's pubkey

	// Observation source signs with the attacker's key.
	source := reputation.NewInMemoryObservationSource()
	source.Put("subject.example", []reputation.Observation{
		signedSample(t, "obs-1", attackerPriv, attackerFP),
	})
	handler := reputation.NewPublicationHandler(reputation.PublicationHandlerConfig{
		Source:        source,
		Signer:        crypto.SuiteBaseline.Signer(),
		PrivateKey:    attackerPriv,
		ObserverKeyID: attackerFP,
	})
	srv := httptest.NewServer(handler)
	defer srv.Close()

	_, err := reputation.Fetch(context.Background(), reputation.FetcherConfig{
		Signer:            crypto.SuiteBaseline.Signer(),
		ObserverPublicKey: realPub,
	}, srv.URL, "subject.example")
	if err == nil {
		t.Fatal("Fetch should reject a response signed under the wrong key")
	}
}

// TestFetchDropsUnverifiableInnerObservation confirms that the
// fetcher keeps envelope-level verification intact but drops inner
// observations whose individual signature doesn't verify.
func TestFetchDropsUnverifiableInnerObservation(t *testing.T) {
	pub, priv, fp := newObserverKeypair(t)
	_, attackerPriv, attackerFP := newObserverKeypair(t)

	good := signedSample(t, "good-obs", priv, fp)
	bad := signedSample(t, "bad-obs", attackerPriv, attackerFP)

	source := reputation.NewInMemoryObservationSource()
	source.Put("subject.example", []reputation.Observation{good, bad})

	handler := reputation.NewPublicationHandler(reputation.PublicationHandlerConfig{
		Source:        source,
		Signer:        crypto.SuiteBaseline.Signer(),
		PrivateKey:    priv,
		ObserverKeyID: fp,
	})
	srv := httptest.NewServer(handler)
	defer srv.Close()

	resp, err := reputation.Fetch(context.Background(), reputation.FetcherConfig{
		Signer:            crypto.SuiteBaseline.Signer(),
		ObserverPublicKey: pub,
	}, srv.URL, "subject.example")
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	// The envelope verified but the bad inner observation should
	// have been dropped.
	if len(resp.Observations) != 1 {
		t.Errorf("Observations length = %d, want 1 (bad one dropped)", len(resp.Observations))
	}
	if len(resp.Observations) == 1 && resp.Observations[0].ID != "good-obs" {
		t.Errorf("kept observation ID = %q, want good-obs", resp.Observations[0].ID)
	}
}

// TestInMemoryObservationSourceLifecycle exercises Put + Lookup +
// clear (Put with empty slice).
func TestInMemoryObservationSourceLifecycle(t *testing.T) {
	_, priv, fp := newObserverKeypair(t)
	source := reputation.NewInMemoryObservationSource()
	if source.Len() != 0 {
		t.Errorf("initial Len = %d, want 0", source.Len())
	}
	source.Put("subject.example", []reputation.Observation{
		signedSample(t, "obs-1", priv, fp),
	})
	if source.Len() != 1 {
		t.Errorf("Len after Put = %d, want 1", source.Len())
	}
	got, err := source.Lookup(context.Background(), "Subject.Example")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if len(got) != 1 || got[0].ID != "obs-1" {
		t.Errorf("Lookup = %+v, want one obs-1", got)
	}
	// Put with empty slice clears the entry.
	source.Put("subject.example", nil)
	if source.Len() != 0 {
		t.Errorf("Len after clear = %d, want 0", source.Len())
	}
}

// TestPublicationHandlerJSONShape confirms the served JSON has the
// exact spec-level top-level keys.
func TestPublicationHandlerJSONShape(t *testing.T) {
	_, priv, fp := newObserverKeypair(t)
	source := reputation.NewInMemoryObservationSource()
	source.Put("subject.example", []reputation.Observation{
		signedSample(t, "obs-1", priv, fp),
	})
	handler := reputation.NewPublicationHandler(reputation.PublicationHandlerConfig{
		Source:        source,
		Signer:        crypto.SuiteBaseline.Signer(),
		PrivateKey:    priv,
		ObserverKeyID: fp,
	})
	srv := httptest.NewServer(handler)
	defer srv.Close()

	httpResp, err := http.Get(srv.URL + reputation.PublicationPath + "subject.example")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer httpResp.Body.Close()
	body, _ := io.ReadAll(httpResp.Body)

	var generic map[string]any
	if err := json.Unmarshal(body, &generic); err != nil {
		t.Fatalf("Unmarshal: %v\nbody: %s", err, body)
	}
	for _, key := range []string{"type", "version", "subject", "observations", "signature"} {
		if _, ok := generic[key]; !ok {
			t.Errorf("response missing top-level key %q", key)
		}
	}
	if generic["type"] != reputation.ObservationsType {
		t.Errorf("type = %v, want %q", generic["type"], reputation.ObservationsType)
	}
}
