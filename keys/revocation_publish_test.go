package keys_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/semp-dev/semp-go/crypto"
	"github.com/semp-dev/semp-go/keys"
	"github.com/semp-dev/semp-go/keys/memstore"
)

// newSigningKeypair generates an Ed25519 signing keypair for tests.
func newSigningKeypair(t *testing.T) (pub, priv []byte, fp keys.Fingerprint) {
	t.Helper()
	pub, priv, err := crypto.SuiteBaseline.Signer().GenerateKeyPair()
	if err != nil {
		t.Fatalf("signer keypair: %v", err)
	}
	return pub, priv, keys.Compute(pub)
}

// sampleRevocationPub builds a RevocationPublication with one entry.
func sampleRevocationPub() *keys.RevocationPublication {
	return &keys.RevocationPublication{
		Type:    keys.RevocationType,
		Version: keys.RevocationVersion,
		RevokedKeys: []keys.RevokedKeyEntry{{
			KeyID:            "abc123def456",
			Address:          "alice@example.com",
			Reason:           keys.ReasonKeyCompromise,
			RevokedAt:        time.Date(2026, 4, 12, 12, 0, 0, 0, time.UTC),
			ReplacementKeyID: "newkey789",
		}},
	}
}

// --- Signing ---

// TestSignRevocationPublicationRoundTrip confirms sign + verify
// under the same key succeeds.
func TestSignRevocationPublicationRoundTrip(t *testing.T) {
	pub, priv, fp := newSigningKeypair(t)
	rpub := sampleRevocationPub()
	if err := keys.SignRevocationPublication(crypto.SuiteBaseline.Signer(), priv, fp, rpub); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if rpub.Signature.Value == "" {
		t.Error("signature value is empty")
	}
	if rpub.Signature.Algorithm != keys.SignatureAlgorithmEd25519 {
		t.Errorf("algorithm = %s, want ed25519", rpub.Signature.Algorithm)
	}
	if err := keys.VerifyRevocationPublication(crypto.SuiteBaseline.Signer(), rpub, pub); err != nil {
		t.Errorf("Verify: %v", err)
	}
}

// TestSignRevocationPublicationTamperRejected confirms mutating
// a revoked_keys entry after signing breaks verification.
func TestSignRevocationPublicationTamperRejected(t *testing.T) {
	pub, priv, fp := newSigningKeypair(t)
	rpub := sampleRevocationPub()
	if err := keys.SignRevocationPublication(crypto.SuiteBaseline.Signer(), priv, fp, rpub); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	rpub.RevokedKeys[0].Reason = keys.ReasonSuperseded
	if err := keys.VerifyRevocationPublication(crypto.SuiteBaseline.Signer(), rpub, pub); err == nil {
		t.Error("tampered publication should fail verification")
	}
}

// TestVerifyRevocationPublicationWrongKey rejects under a different
// public key.
func TestVerifyRevocationPublicationWrongKey(t *testing.T) {
	_, priv, fp := newSigningKeypair(t)
	otherPub, _, _ := newSigningKeypair(t)
	rpub := sampleRevocationPub()
	_ = keys.SignRevocationPublication(crypto.SuiteBaseline.Signer(), priv, fp, rpub)
	if err := keys.VerifyRevocationPublication(crypto.SuiteBaseline.Signer(), rpub, otherPub); err == nil {
		t.Error("wrong key should fail verification")
	}
}

// TestVerifyRevocationPublicationUnsigned rejects an unsigned
// publication.
func TestVerifyRevocationPublicationUnsigned(t *testing.T) {
	pub, _, _ := newSigningKeypair(t)
	rpub := sampleRevocationPub()
	if err := keys.VerifyRevocationPublication(crypto.SuiteBaseline.Signer(), rpub, pub); err == nil {
		t.Error("unsigned should fail")
	}
}

// --- Publication handler ---

// fakeRevocationSource returns pre-configured revocation entries.
type fakeRevocationSource struct {
	entries map[string][]keys.RevokedKeyEntry
}

func (f *fakeRevocationSource) LookupRevocations(_ context.Context, q string) ([]keys.RevokedKeyEntry, error) {
	return f.entries[strings.ToLower(q)], nil
}

// TestRevocationPublicationHandlerServesSignedResponse drives the
// handler end-to-end through httptest.
func TestRevocationPublicationHandlerServesSignedResponse(t *testing.T) {
	pub, priv, fp := newSigningKeypair(t)
	source := &fakeRevocationSource{
		entries: map[string][]keys.RevokedKeyEntry{
			"alice@example.com": {{
				KeyID:     "abc123",
				Address:   "alice@example.com",
				Reason:    keys.ReasonKeyCompromise,
				RevokedAt: time.Now().UTC(),
			}},
		},
	}
	handler := keys.NewRevocationPublicationHandler(keys.RevocationHandlerConfig{
		Source:      source,
		Signer:      crypto.SuiteBaseline.Signer(),
		PrivateKey:  priv,
		DomainKeyID: fp,
	})
	srv := httptest.NewServer(handler)
	defer srv.Close()

	// Fetch via the client helper.
	rpub, err := keys.FetchRevocations(context.Background(), keys.FetchRevocationConfig{
		Signer:          crypto.SuiteBaseline.Signer(),
		DomainPublicKey: pub,
	}, srv.URL, "alice@example.com")
	if err != nil {
		t.Fatalf("FetchRevocations: %v", err)
	}
	if len(rpub.RevokedKeys) != 1 {
		t.Fatalf("RevokedKeys length = %d, want 1", len(rpub.RevokedKeys))
	}
	if rpub.RevokedKeys[0].KeyID != "abc123" {
		t.Errorf("KeyID = %q, want abc123", rpub.RevokedKeys[0].KeyID)
	}
}

// TestRevocationPublicationHandlerEmptyQuery returns 400.
func TestRevocationPublicationHandlerEmptyQuery(t *testing.T) {
	_, priv, fp := newSigningKeypair(t)
	handler := keys.NewRevocationPublicationHandler(keys.RevocationHandlerConfig{
		Source:      &fakeRevocationSource{},
		Signer:      crypto.SuiteBaseline.Signer(),
		PrivateKey:  priv,
		DomainKeyID: fp,
	})
	srv := httptest.NewServer(handler)
	defer srv.Close()
	resp, err := http.Get(srv.URL + keys.RevocationPublicationPath)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

// TestRevocationPublicationHandlerWrongMethod returns 405.
func TestRevocationPublicationHandlerWrongMethod(t *testing.T) {
	_, priv, fp := newSigningKeypair(t)
	handler := keys.NewRevocationPublicationHandler(keys.RevocationHandlerConfig{
		Source:      &fakeRevocationSource{},
		Signer:      crypto.SuiteBaseline.Signer(),
		PrivateKey:  priv,
		DomainKeyID: fp,
	})
	srv := httptest.NewServer(handler)
	defer srv.Close()
	resp, err := http.Post(srv.URL+keys.RevocationPublicationPath+"alice@example.com", "application/json", nil)
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", resp.StatusCode)
	}
}

// TestFetchRevocationsRejectsForgedEnvelope confirms the fetcher
// discards a response signed under the wrong key.
func TestFetchRevocationsRejectsForgedEnvelope(t *testing.T) {
	_, attackerPriv, attackerFP := newSigningKeypair(t)
	realPub, _, _ := newSigningKeypair(t)
	handler := keys.NewRevocationPublicationHandler(keys.RevocationHandlerConfig{
		Source: &fakeRevocationSource{
			entries: map[string][]keys.RevokedKeyEntry{
				"alice@example.com": {{KeyID: "abc", Reason: keys.ReasonSuperseded, RevokedAt: time.Now().UTC()}},
			},
		},
		Signer:      crypto.SuiteBaseline.Signer(),
		PrivateKey:  attackerPriv,
		DomainKeyID: attackerFP,
	})
	srv := httptest.NewServer(handler)
	defer srv.Close()
	_, err := keys.FetchRevocations(context.Background(), keys.FetchRevocationConfig{
		Signer:          crypto.SuiteBaseline.Signer(),
		DomainPublicKey: realPub,
	}, srv.URL, "alice@example.com")
	if err == nil {
		t.Fatal("forged envelope should be rejected")
	}
}

// TestRevocationPublicationJSONShape confirms the served JSON has
// the correct top-level fields.
func TestRevocationPublicationJSONShape(t *testing.T) {
	_, priv, fp := newSigningKeypair(t)
	handler := keys.NewRevocationPublicationHandler(keys.RevocationHandlerConfig{
		Source:      &fakeRevocationSource{entries: map[string][]keys.RevokedKeyEntry{"a@b.com": {}}},
		Signer:      crypto.SuiteBaseline.Signer(),
		PrivateKey:  priv,
		DomainKeyID: fp,
	})
	srv := httptest.NewServer(handler)
	defer srv.Close()
	resp, err := http.Get(srv.URL + keys.RevocationPublicationPath + "a@b.com")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var generic map[string]any
	if err := json.Unmarshal(body, &generic); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	for _, key := range []string{"type", "version", "revoked_keys", "signature"} {
		if _, ok := generic[key]; !ok {
			t.Errorf("response missing key %q", key)
		}
	}
	if generic["type"] != keys.RevocationType {
		t.Errorf("type = %v, want %q", generic["type"], keys.RevocationType)
	}
}

// --- RevocationCache ---

// TestRevocationCacheApplyAndIsRevoked exercises the cache lifecycle.
func TestRevocationCacheApplyAndIsRevoked(t *testing.T) {
	cache := keys.NewRevocationCache(time.Minute, nil)
	pub := sampleRevocationPub()
	cache.Apply(pub)
	entry, ok := cache.IsRevoked("abc123def456")
	if !ok {
		t.Fatal("expected cached revocation")
	}
	if entry.Reason != keys.ReasonKeyCompromise {
		t.Errorf("Reason = %s, want key_compromise", entry.Reason)
	}
	if cache.Len() != 1 {
		t.Errorf("Len = %d, want 1", cache.Len())
	}
}

// TestRevocationCacheExpiry confirms expired entries are lazily evicted.
func TestRevocationCacheExpiry(t *testing.T) {
	now := time.Now()
	clock := now
	cache := keys.NewRevocationCache(time.Minute, func() time.Time { return clock })
	cache.Apply(sampleRevocationPub())
	clock = now.Add(2 * time.Minute)
	if _, ok := cache.IsRevoked("abc123def456"); ok {
		t.Error("expired entry should not be returned")
	}
}

// TestRevocationCacheInvalidate clears the cache.
func TestRevocationCacheInvalidate(t *testing.T) {
	cache := keys.NewRevocationCache(time.Minute, nil)
	cache.Apply(sampleRevocationPub())
	cache.Invalidate()
	if cache.Len() != 0 {
		t.Errorf("Len after Invalidate = %d, want 0", cache.Len())
	}
}

// TestRevocationCacheInvalidateKey removes a single entry.
func TestRevocationCacheInvalidateKey(t *testing.T) {
	cache := keys.NewRevocationCache(time.Minute, nil)
	cache.Apply(sampleRevocationPub())
	cache.InvalidateKey("abc123def456")
	if _, ok := cache.IsRevoked("abc123def456"); ok {
		t.Error("invalidated key should not be returned")
	}
}

// TestRevocationCacheNilSafe confirms nil safety.
func TestRevocationCacheNilSafe(t *testing.T) {
	var cache *keys.RevocationCache
	cache.Apply(sampleRevocationPub())
	if _, ok := cache.IsRevoked("abc"); ok {
		t.Error("nil cache should return false")
	}
	cache.Invalidate()
	cache.InvalidateKey("abc")
	if cache.Len() != 0 {
		t.Error("nil Len should be 0")
	}
}

// TestRevocationCacheApplyToStore writes cached revocations into
// the keystore.
func TestRevocationCacheApplyToStore(t *testing.T) {
	store := memstore.New()
	// Pre-seed a user key so PutRevocation has something to attach to.
	encPub, _, _ := crypto.SuiteBaseline.KEM().GenerateKeyPair()
	store.PutUserKey("alice@example.com", keys.TypeEncryption, "x25519-chacha20-poly1305", encPub)

	cache := keys.NewRevocationCache(time.Minute, nil)
	fp := keys.Compute(encPub)
	pub := &keys.RevocationPublication{
		Type:    keys.RevocationType,
		Version: keys.RevocationVersion,
		RevokedKeys: []keys.RevokedKeyEntry{{
			KeyID:     fp,
			Address:   "alice@example.com",
			Reason:    keys.ReasonKeyCompromise,
			RevokedAt: time.Now().UTC(),
		}},
	}
	cache.Apply(pub)
	if err := cache.ApplyToStore(context.Background(), store); err != nil {
		t.Fatalf("ApplyToStore: %v", err)
	}
	// The store should now return the key with a revocation.
	recs, err := store.LookupUserKeys(context.Background(), "alice@example.com", keys.TypeEncryption)
	if err != nil {
		t.Fatalf("LookupUserKeys: %v", err)
	}
	found := false
	for _, r := range recs {
		if r.KeyID == fp && r.Revocation != nil {
			found = true
			if r.Revocation.Reason != keys.ReasonKeyCompromise {
				t.Errorf("Reason = %s, want key_compromise", r.Revocation.Reason)
			}
		}
	}
	if !found {
		t.Error("revocation not applied to store record")
	}
}

// --- StoreRevocationSource ---

// TestStoreRevocationSourceCollectsRevoked confirms the adapter
// returns only revoked keys.
func TestStoreRevocationSourceCollectsRevoked(t *testing.T) {
	store := memstore.New()
	encPub1, _, _ := crypto.SuiteBaseline.KEM().GenerateKeyPair()
	encPub2, _, _ := crypto.SuiteBaseline.KEM().GenerateKeyPair()
	store.PutUserKey("alice@example.com", keys.TypeEncryption, "x25519", encPub1)
	store.PutUserKey("alice@example.com", keys.TypeEncryption, "x25519", encPub2)
	fp1 := keys.Compute(encPub1)
	// Revoke only the first key.
	_ = store.PutRevocation(context.Background(), fp1, &keys.Revocation{
		Reason:    keys.ReasonSuperseded,
		RevokedAt: time.Now().UTC(),
	})

	source := &keys.StoreRevocationSource{Store: store}
	entries, err := source.LookupRevocations(context.Background(), "alice@example.com")
	if err != nil {
		t.Fatalf("LookupRevocations: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("entries = %d, want 1 (only the revoked key)", len(entries))
	}
	if entries[0].KeyID != fp1 {
		t.Errorf("entry KeyID = %s, want %s", entries[0].KeyID, fp1)
	}
}

// TestFetchRevocationsEndToEnd exercises the full chain: seed a
// revocation in a memstore, serve via the handler, fetch via the
// client, apply to a second store.
func TestFetchRevocationsEndToEnd(t *testing.T) {
	pub, priv, fp := newSigningKeypair(t)
	store := memstore.New()
	encPub, _, _ := crypto.SuiteBaseline.KEM().GenerateKeyPair()
	store.PutUserKey("alice@example.com", keys.TypeEncryption, "x25519", encPub)
	encFP := keys.Compute(encPub)
	_ = store.PutRevocation(context.Background(), encFP, &keys.Revocation{
		Reason:    keys.ReasonKeyCompromise,
		RevokedAt: time.Now().UTC(),
	})

	source := &keys.StoreRevocationSource{Store: store}
	handler := keys.NewRevocationPublicationHandler(keys.RevocationHandlerConfig{
		Source:      source,
		Signer:      crypto.SuiteBaseline.Signer(),
		PrivateKey:  priv,
		DomainKeyID: fp,
	})
	srv := httptest.NewServer(handler)
	defer srv.Close()

	rpub, err := keys.FetchRevocations(context.Background(), keys.FetchRevocationConfig{
		Signer:          crypto.SuiteBaseline.Signer(),
		DomainPublicKey: pub,
	}, srv.URL, "alice@example.com")
	if err != nil {
		t.Fatalf("FetchRevocations: %v", err)
	}

	// Apply to a second store.
	store2 := memstore.New()
	store2.PutUserKey("alice@example.com", keys.TypeEncryption, "x25519", encPub)
	cache := keys.NewRevocationCache(time.Minute, nil)
	cache.Apply(rpub)
	if err := cache.ApplyToStore(context.Background(), store2); err != nil {
		t.Fatalf("ApplyToStore: %v", err)
	}
	recs, _ := store2.LookupUserKeys(context.Background(), "alice@example.com", keys.TypeEncryption)
	revoked := false
	for _, r := range recs {
		if r.KeyID == encFP && r.Revocation != nil {
			revoked = true
		}
	}
	if !revoked {
		t.Error("revocation did not propagate to second store")
	}
}

var _ = errors.New // keep import
