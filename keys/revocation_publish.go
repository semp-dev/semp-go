// Package keys — revocation publication, signing, and pull-based
// distribution per KEY.md §8.
//
// The spec's revocation model is pull-based: "Servers have NO
// obligation to push revocation notices." Revocation records are
// made discoverable at the same well-known endpoint where the key
// was originally published, and receivers fetch them when they query
// keys. This file implements:
//
//   - SignRevocationPublication / VerifyRevocationPublication
//   - NewRevocationPublicationHandler (server-side HTTP handler)
//   - FetchRevocations (client-side HTTP fetcher)
//   - RevocationCache (in-memory cache of fetched revocations with TTL)
//
// The gossip model mirrors reputation/trust_gossip.go: publication
// at a well-known URI, per-domain signing, and a client that verifies
// the envelope before caching.
package keys

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"semp.dev/semp-go/crypto"
	"semp.dev/semp-go/internal/canonical"
)

// Wire-level constants for revocation publications.
const (
	// RevocationType is the wire-level `type` field for a
	// revocation publication (KEY.md §8.1).
	RevocationType = "SEMP_KEY_REVOCATION"

	// RevocationVersion is the SEMP protocol version this
	// implementation writes into revocation publications.
	RevocationVersion = "1.0.0"

	// RevocationPublicationPath is the well-known URI path prefix
	// where revocation publications are served. A domain serves
	// its revocations at:
	//
	//   https://<domain>/.well-known/semp/revocation/
	//
	// The handler expects the full address (user@domain) or domain
	// as the trailing path segment. The spec says revocation records
	// must be discoverable "at the same endpoint where the key was
	// originally published" (§8.3); this well-known path is the
	// designated publication point for batch revocations.
	RevocationPublicationPath = "/.well-known/semp/revocation/"
)

// -----------------------------------------------------------------------------
// Signing
// -----------------------------------------------------------------------------

// canonicalRevocationPublicationBytes returns the canonical JSON form
// of pub with signature.value elided — same elider pattern as
// observation signing and discovery response signing.
func canonicalRevocationPublicationBytes(pub *RevocationPublication) ([]byte, error) {
	if pub == nil {
		return nil, errors.New("keys: nil revocation publication")
	}
	return canonical.MarshalWithElision(pub, func(v any) error {
		m, ok := v.(map[string]any)
		if !ok {
			return fmt.Errorf("keys: expected top-level object, got %T", v)
		}
		sig, ok := m["signature"].(map[string]any)
		if !ok {
			return errors.New("keys: revocation publication has no signature object")
		}
		sig["value"] = ""
		return nil
	})
}

// SignRevocationPublication computes an Ed25519 signature over the
// canonical form of pub with signature.value elided, and populates
// pub.Signature. The signer is the domain's long-term identity key.
//
// Reference: KEY.md §8.1, §8.3.
func SignRevocationPublication(signer crypto.Signer, privKey []byte, signerKeyID Fingerprint, pub *RevocationPublication) error {
	if signer == nil {
		return errors.New("keys: nil signer")
	}
	if pub == nil {
		return errors.New("keys: nil revocation publication")
	}
	if len(privKey) == 0 {
		return errors.New("keys: empty signing private key")
	}
	if pub.Type == "" {
		pub.Type = RevocationType
	}
	if pub.Version == "" {
		pub.Version = RevocationVersion
	}
	pub.Signature.Algorithm = SignatureAlgorithmEd25519
	pub.Signature.KeyID = signerKeyID
	msg, err := canonicalRevocationPublicationBytes(pub)
	if err != nil {
		return fmt.Errorf("keys: canonical revocation publication: %w", err)
	}
	sigBytes, err := signer.Sign(privKey, msg)
	if err != nil {
		return fmt.Errorf("keys: sign revocation publication: %w", err)
	}
	pub.Signature.Value = base64.StdEncoding.EncodeToString(sigBytes)
	return nil
}

// VerifyRevocationPublication verifies the envelope-level signature
// on pub against the domain's published public key. Per KEY.md §8.3,
// receivers MUST verify the signature before caching or acting on
// any revocation entry.
func VerifyRevocationPublication(signer crypto.Signer, pub *RevocationPublication, domainPub []byte) error {
	if signer == nil {
		return errors.New("keys: nil signer")
	}
	if pub == nil {
		return errors.New("keys: nil revocation publication")
	}
	if pub.Signature.Value == "" {
		return errors.New("keys: revocation publication is unsigned")
	}
	if len(domainPub) == 0 {
		return errors.New("keys: empty domain public key")
	}
	sigBytes, err := base64.StdEncoding.DecodeString(pub.Signature.Value)
	if err != nil {
		return fmt.Errorf("keys: revocation signature base64: %w", err)
	}
	msg, err := canonicalRevocationPublicationBytes(pub)
	if err != nil {
		return fmt.Errorf("keys: canonical revocation publication: %w", err)
	}
	if err := signer.Verify(domainPub, msg, sigBytes); err != nil {
		return fmt.Errorf("keys: verify revocation publication: %w", err)
	}
	return nil
}

// -----------------------------------------------------------------------------
// Publication handler
// -----------------------------------------------------------------------------

// RevocationSource is the read side a publication handler uses to
// retrieve the current set of revocations for a query. The typical
// implementation walks the Store and collects all revoked key records
// for the requested address or domain.
type RevocationSource interface {
	// LookupRevocations returns the current revocation entries for
	// the given address or domain. An empty slice + nil error means
	// "no revocations on file." An error means the handler should
	// return HTTP 500.
	LookupRevocations(ctx context.Context, addressOrDomain string) ([]RevokedKeyEntry, error)
}

// StoreRevocationSource adapts a Store into a RevocationSource by
// looking up all user keys and collecting the revoked ones.
type StoreRevocationSource struct {
	Store Store
}

// LookupRevocations implements RevocationSource.
func (s *StoreRevocationSource) LookupRevocations(ctx context.Context, addressOrDomain string) ([]RevokedKeyEntry, error) {
	if s == nil || s.Store == nil {
		return nil, errors.New("keys: nil store")
	}
	recs, err := s.Store.LookupUserKeys(ctx, addressOrDomain)
	if err != nil {
		return nil, err
	}
	var entries []RevokedKeyEntry
	for _, r := range recs {
		if r.Revocation == nil {
			continue
		}
		entries = append(entries, RevokedKeyEntry{
			KeyID:            r.KeyID,
			Address:          r.Address,
			Reason:           r.Revocation.Reason,
			RevokedAt:        r.Revocation.RevokedAt,
			ReplacementKeyID: r.Revocation.ReplacementKeyID,
		})
	}
	return entries, nil
}

// RevocationHandlerConfig groups the inputs to
// NewRevocationPublicationHandler.
type RevocationHandlerConfig struct {
	// Source retrieves revocation entries. Required.
	Source RevocationSource

	// Signer is the crypto.Signer used to sign the publication
	// envelope. Required.
	Signer crypto.Signer

	// PrivateKey is the domain's signing private key. Required.
	PrivateKey []byte

	// DomainKeyID is the domain's key fingerprint.
	DomainKeyID Fingerprint
}

// NewRevocationPublicationHandler returns an http.Handler that serves
// revocation publications at RevocationPublicationPath per KEY.md
// §8.3. The handler extracts the address or domain from the trailing
// path segment, fetches revocations from the source, wraps them in a
// signed RevocationPublication, and serves as JSON.
//
// GET only; POST → 405; missing address → 400.
func NewRevocationPublicationHandler(cfg RevocationHandlerConfig) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !strings.HasPrefix(r.URL.Path, RevocationPublicationPath) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		query := strings.TrimPrefix(r.URL.Path, RevocationPublicationPath)
		if query == "" || strings.Contains(query, "/") {
			http.Error(w, "missing or malformed query", http.StatusBadRequest)
			return
		}
		if cfg.Source == nil || cfg.Signer == nil || len(cfg.PrivateKey) == 0 {
			http.Error(w, "handler misconfigured", http.StatusInternalServerError)
			return
		}
		entries, err := cfg.Source.LookupRevocations(r.Context(), query)
		if err != nil {
			http.Error(w, "lookup: "+err.Error(), http.StatusInternalServerError)
			return
		}
		pub := &RevocationPublication{
			Type:        RevocationType,
			Version:     RevocationVersion,
			RevokedKeys: entries,
		}
		if pub.RevokedKeys == nil {
			pub.RevokedKeys = []RevokedKeyEntry{}
		}
		if err := SignRevocationPublication(cfg.Signer, cfg.PrivateKey, cfg.DomainKeyID, pub); err != nil {
			http.Error(w, "sign: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		_ = json.NewEncoder(w).Encode(pub)
	})
}

// -----------------------------------------------------------------------------
// Fetcher
// -----------------------------------------------------------------------------

// FetchRevocationConfig groups the inputs to FetchRevocations.
type FetchRevocationConfig struct {
	// HTTPClient is the underlying HTTP client. Zero picks a client
	// with a 10-second timeout.
	HTTPClient *http.Client

	// Signer verifies the publication signature.
	Signer crypto.Signer

	// DomainPublicKey is the publishing domain's signing public key.
	// Required — unsigned or unverifiable publications MUST be
	// discarded per KEY.md §8.3.
	DomainPublicKey []byte

	// MaxBodyBytes caps the response body. Zero picks 256 KiB.
	MaxBodyBytes int64
}

// FetchRevocations retrieves the revocation publication for
// addressOrDomain from the given domain's well-known endpoint:
//
//	GET https://<domainBaseURL>/.well-known/semp/revocation/<addressOrDomain>
//
// The returned publication has been verified; if verification fails
// the function returns an error and callers MUST discard the data.
func FetchRevocations(ctx context.Context, cfg FetchRevocationConfig, domainBaseURL, addressOrDomain string) (*RevocationPublication, error) {
	if cfg.Signer == nil {
		return nil, errors.New("keys: FetchRevocations missing Signer")
	}
	if len(cfg.DomainPublicKey) == 0 {
		return nil, errors.New("keys: FetchRevocations missing DomainPublicKey")
	}
	if addressOrDomain == "" {
		return nil, errors.New("keys: FetchRevocations missing addressOrDomain")
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	maxBody := cfg.MaxBodyBytes
	if maxBody <= 0 {
		maxBody = 256 * 1024
	}
	url := strings.TrimRight(domainBaseURL, "/") + RevocationPublicationPath + addressOrDomain
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("keys: build fetch request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("keys: GET %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("keys: GET %s returned %d: %s", url, resp.StatusCode, string(body))
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return nil, fmt.Errorf("keys: read response: %w", err)
	}
	if int64(len(body)) > maxBody {
		return nil, fmt.Errorf("keys: response exceeds %d bytes", maxBody)
	}
	var pub RevocationPublication
	if err := json.Unmarshal(body, &pub); err != nil {
		return nil, fmt.Errorf("keys: parse response: %w", err)
	}
	if pub.Type != RevocationType {
		return nil, fmt.Errorf("keys: response type = %q, want %q", pub.Type, RevocationType)
	}
	if err := VerifyRevocationPublication(cfg.Signer, &pub, cfg.DomainPublicKey); err != nil {
		return nil, err
	}
	return &pub, nil
}

// -----------------------------------------------------------------------------
// RevocationCache
// -----------------------------------------------------------------------------

// RevocationCache caches fetched revocation entries per key
// fingerprint so envelope verification doesn't need to re-fetch from
// the publishing domain on every check. Entries are TTL-bounded;
// expired entries are lazily evicted on read.
//
// RevocationCache is safe for concurrent use.
type RevocationCache struct {
	mu      sync.Mutex
	entries map[Fingerprint]cachedRevocation
	ttl     time.Duration
	nowFunc func() time.Time
}

type cachedRevocation struct {
	entry     RevokedKeyEntry
	expiresAt time.Time
}

// NewRevocationCache returns an empty cache with the given TTL.
// Zero or negative TTL picks a conservative default of 5 minutes.
func NewRevocationCache(ttl time.Duration, now func() time.Time) *RevocationCache {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	if now == nil {
		now = time.Now
	}
	return &RevocationCache{
		entries: map[Fingerprint]cachedRevocation{},
		ttl:     ttl,
		nowFunc: now,
	}
}

// Apply ingests a verified RevocationPublication and caches every
// entry. Callers MUST verify the publication signature (via
// VerifyRevocationPublication) before calling Apply — Apply itself
// does not re-verify.
func (c *RevocationCache) Apply(pub *RevocationPublication) {
	if c == nil || pub == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.nowFunc()
	for _, e := range pub.RevokedKeys {
		c.entries[e.KeyID] = cachedRevocation{
			entry:     e,
			expiresAt: now.Add(c.ttl),
		}
	}
}

// IsRevoked reports whether keyID has a cached revocation. Returns
// the revocation entry and true if the key is known-revoked and the
// cache entry has not expired; returns a zero entry and false
// otherwise. Expired entries are lazily evicted.
func (c *RevocationCache) IsRevoked(keyID Fingerprint) (RevokedKeyEntry, bool) {
	if c == nil {
		return RevokedKeyEntry{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	cached, ok := c.entries[keyID]
	if !ok {
		return RevokedKeyEntry{}, false
	}
	if c.nowFunc().After(cached.expiresAt) {
		delete(c.entries, keyID)
		return RevokedKeyEntry{}, false
	}
	return cached.entry, true
}

// Invalidate removes all cached entries. Per KEY.md §8.3, senders
// with cached keys later found to be revoked MUST invalidate the
// cache and re-fetch.
func (c *RevocationCache) Invalidate() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = map[Fingerprint]cachedRevocation{}
}

// InvalidateKey removes the cached entry for a single key. Useful
// when a key response includes a revocation that the sender didn't
// expect — the sender invalidates just that key's cache and re-fetches.
func (c *RevocationCache) InvalidateKey(keyID Fingerprint) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, keyID)
}

// Len returns the number of cached entries (including expired ones
// that haven't been lazily evicted yet). For exact counts, callers
// should sweep the cache by calling IsRevoked for every fingerprint
// they care about.
func (c *RevocationCache) Len() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// ApplyToStore writes every cached revocation into the given Store
// via PutRevocation. This is the bridge from the pull-based
// distribution model to the local Store: after fetching and caching
// revocations from a peer, call ApplyToStore to propagate them into
// the local keystore so subsequent LookupUserKeys / LookupDomainKey
// calls reflect the revoked state.
func (c *RevocationCache) ApplyToStore(ctx context.Context, store Store) error {
	if c == nil || store == nil {
		return nil
	}
	c.mu.Lock()
	entries := make([]cachedRevocation, 0, len(c.entries))
	for _, e := range c.entries {
		entries = append(entries, e)
	}
	c.mu.Unlock()
	for _, e := range entries {
		rev := &Revocation{
			Reason:           e.entry.Reason,
			RevokedAt:        e.entry.RevokedAt,
			ReplacementKeyID: e.entry.ReplacementKeyID,
		}
		if err := store.PutRevocation(ctx, e.entry.KeyID, rev); err != nil {
			return fmt.Errorf("keys: apply revocation for %s: %w", e.entry.KeyID, err)
		}
	}
	return nil
}
