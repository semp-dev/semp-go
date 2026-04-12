package reputation

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
	"semp.dev/semp-go/keys"
)

// PublicationPath is the path prefix under which observation records
// are published per REPUTATION.md §5.1:
//
//	https://<observer>/.well-known/semp/reputation/<subject>
//
// Callers mount PublicationHandler at this prefix and the handler
// extracts the subject from the trailing path segment.
const PublicationPath = "/.well-known/semp/reputation/"

// TrustObservations is the response envelope served at the
// publication URL per REPUTATION.md §5.1. It bundles one or more
// Observation records together with a response-level signature from
// the observer so the fetching server can verify the publication as
// a whole in one step.
type TrustObservations struct {
	Type         string                    `json:"type"`
	Version      string                    `json:"version"`
	Subject      string                    `json:"subject"`
	Observations []Observation             `json:"observations"`
	Signature    keys.PublicationSignature `json:"signature"`
}

// canonicalTrustObservationsBytes returns the canonical JSON form of
// the response envelope with signature.value elided. Same pattern as
// the per-observation signer.
func canonicalTrustObservationsBytes(resp *TrustObservations) ([]byte, error) {
	if resp == nil {
		return nil, errors.New("reputation: nil trust observations response")
	}
	return canonical.MarshalWithElision(resp, func(v any) error {
		m, ok := v.(map[string]any)
		if !ok {
			return fmt.Errorf("reputation: expected top-level object, got %T", v)
		}
		sig, ok := m["signature"].(map[string]any)
		if !ok {
			return errors.New("reputation: trust observations response has no signature object")
		}
		sig["value"] = ""
		return nil
	})
}

// SignTrustObservations computes an Ed25519 signature over the
// canonical form of resp with signature.value elided, and populates
// resp.Signature. The per-observation signatures inside
// resp.Observations are NOT re-signed — they retain whatever
// signatures they had when the caller assembled the response.
//
// The envelope-level signature lets a fetcher verify the whole
// response in one step while still being able to verify each
// individual observation if it wants granular evidence.
func SignTrustObservations(signer crypto.Signer, privKey []byte, observerKeyID keys.Fingerprint, resp *TrustObservations) error {
	if signer == nil {
		return errors.New("reputation: nil signer")
	}
	if resp == nil {
		return errors.New("reputation: nil response")
	}
	if len(privKey) == 0 {
		return errors.New("reputation: empty signing private key")
	}
	if resp.Type == "" {
		resp.Type = ObservationsType
	}
	if resp.Version == "" {
		resp.Version = ObservationVersion
	}
	resp.Signature.Algorithm = keys.SignatureAlgorithmEd25519
	resp.Signature.KeyID = observerKeyID
	msg, err := canonicalTrustObservationsBytes(resp)
	if err != nil {
		return fmt.Errorf("reputation: canonical response: %w", err)
	}
	sigBytes, err := signer.Sign(privKey, msg)
	if err != nil {
		return fmt.Errorf("reputation: sign response: %w", err)
	}
	resp.Signature.Value = base64.StdEncoding.EncodeToString(sigBytes)
	return nil
}

// VerifyTrustObservations verifies the envelope-level signature
// against observerPub. It does NOT verify the per-observation
// signatures inside resp.Observations — callers should walk those
// and call VerifyObservation on each, because different observations
// in the same envelope MAY be signed under different key_ids (e.g.
// after a key rotation).
func VerifyTrustObservations(signer crypto.Signer, resp *TrustObservations, observerPub []byte) error {
	if signer == nil {
		return errors.New("reputation: nil signer")
	}
	if resp == nil {
		return errors.New("reputation: nil response")
	}
	if resp.Signature.Value == "" {
		return errors.New("reputation: response is unsigned")
	}
	if len(observerPub) == 0 {
		return errors.New("reputation: empty observer public key")
	}
	sigBytes, err := base64.StdEncoding.DecodeString(resp.Signature.Value)
	if err != nil {
		return fmt.Errorf("reputation: response signature base64: %w", err)
	}
	msg, err := canonicalTrustObservationsBytes(resp)
	if err != nil {
		return fmt.Errorf("reputation: canonical response: %w", err)
	}
	if err := signer.Verify(observerPub, msg, sigBytes); err != nil {
		return fmt.Errorf("reputation: verify response signature: %w", err)
	}
	return nil
}

// -----------------------------------------------------------------------------
// Publication handler
// -----------------------------------------------------------------------------

// ObservationSource is the read side of an observation store. A
// PublicationHandler calls Lookup(subject) to retrieve the set of
// observations it should publish for subject, then serves them back
// to the requester as a signed TrustObservations envelope.
//
// The handler takes a read-side interface rather than a concrete
// *ObservationStore so operators can plug in a persistent backend
// that stores pre-signed observation records at rest.
type ObservationSource interface {
	// Lookup returns the currently-published observations for
	// subject. An empty slice plus nil error means "no data" and
	// produces a signed-but-empty publication — legitimate per
	// REPUTATION.md §5.1. Returning an error causes the handler to
	// respond with HTTP 500.
	Lookup(ctx context.Context, subject string) ([]Observation, error)
}

// InMemoryObservationSource is a tiny ObservationSource backed by a
// map of pre-signed observations keyed by subject domain. Operators
// that build observations from an ObservationStore on a fixed cadence
// can park the resulting signed records here so the PublicationHandler
// can serve them without regenerating on every request.
type InMemoryObservationSource struct {
	mu sync.Mutex
	// byDomain keys on lowercase subject domain.
	byDomain map[string][]Observation
}

// NewInMemoryObservationSource returns an empty source.
func NewInMemoryObservationSource() *InMemoryObservationSource {
	return &InMemoryObservationSource{byDomain: map[string][]Observation{}}
}

// Put replaces the observation list for subject. The caller owns
// signing — Put does NOT verify signatures and does NOT reject
// unsigned observations. Use this after SignObservation has been
// called on each record.
func (s *InMemoryObservationSource) Put(subject string, observations []Observation) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(observations) == 0 {
		delete(s.byDomain, normalize(subject))
		return
	}
	// Defensive copy so mutations to the caller's slice don't leak.
	cp := make([]Observation, len(observations))
	copy(cp, observations)
	s.byDomain[normalize(subject)] = cp
}

// Lookup implements ObservationSource.
func (s *InMemoryObservationSource) Lookup(_ context.Context, subject string) ([]Observation, error) {
	if s == nil {
		return nil, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	obs := s.byDomain[normalize(subject)]
	if len(obs) == 0 {
		return nil, nil
	}
	cp := make([]Observation, len(obs))
	copy(cp, obs)
	return cp, nil
}

// Len returns the number of subjects with at least one observation.
func (s *InMemoryObservationSource) Len() int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.byDomain)
}

// PublicationHandlerConfig groups the inputs to NewPublicationHandler.
type PublicationHandlerConfig struct {
	// Source is the read side of the observation store. Required.
	Source ObservationSource

	// Signer is the crypto.Suite signer used to sign the envelope.
	// Required.
	Signer crypto.Signer

	// PrivateKey is the observer domain's private signing key.
	// Required — the handler cannot publish without being able to
	// sign the envelope.
	PrivateKey []byte

	// ObserverKeyID is the observer domain's key fingerprint. Must
	// match the corresponding public key published at the observer's
	// discovery record so fetchers can verify.
	ObserverKeyID keys.Fingerprint
}

// NewPublicationHandler returns an http.Handler that serves the
// well-known trust gossip publication endpoint per REPUTATION.md §5.1.
// The handler extracts the subject from the trailing path segment,
// fetches observations via cfg.Source, wraps them in a signed
// TrustObservations response, and writes it as JSON.
//
// Mount at PublicationPath ("/.well-known/semp/reputation/") using a
// pattern that captures the subject:
//
//	mux.Handle(reputation.PublicationPath, reputation.NewPublicationHandler(cfg))
//
// The handler accepts GET only. Any other method returns 405.
// Paths that don't start with PublicationPath return 404. Missing
// subject (path equals PublicationPath exactly) returns 400.
func NewPublicationHandler(cfg PublicationHandlerConfig) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !strings.HasPrefix(r.URL.Path, PublicationPath) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		subject := strings.TrimPrefix(r.URL.Path, PublicationPath)
		if subject == "" || strings.Contains(subject, "/") {
			http.Error(w, "missing or malformed subject", http.StatusBadRequest)
			return
		}
		if cfg.Source == nil || cfg.Signer == nil || len(cfg.PrivateKey) == 0 {
			http.Error(w, "publication handler misconfigured", http.StatusInternalServerError)
			return
		}

		observations, err := cfg.Source.Lookup(r.Context(), subject)
		if err != nil {
			http.Error(w, "lookup: "+err.Error(), http.StatusInternalServerError)
			return
		}
		resp := &TrustObservations{
			Type:         ObservationsType,
			Version:      ObservationVersion,
			Subject:      subject,
			Observations: observations,
		}
		if err := SignTrustObservations(cfg.Signer, cfg.PrivateKey, cfg.ObserverKeyID, resp); err != nil {
			http.Error(w, "sign: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		_ = json.NewEncoder(w).Encode(resp)
	})
}

// -----------------------------------------------------------------------------
// Fetcher (client side)
// -----------------------------------------------------------------------------

// FetcherConfig groups the inputs to Fetch.
type FetcherConfig struct {
	// HTTPClient is the underlying *http.Client. Zero picks a
	// client with a 10-second timeout, which is appropriate for
	// gossip fetches — they are not latency-critical.
	HTTPClient *http.Client

	// Signer is the crypto.Suite signer used to verify response and
	// per-observation signatures.
	Signer crypto.Signer

	// ObserverPublicKey is the public signing key of the observer
	// whose publication we are fetching. Required — an unsigned
	// response MUST be discarded per REPUTATION.md §5.2.
	ObserverPublicKey []byte

	// MaxBodyBytes caps the size of the response body. Zero picks
	// 1 MiB, which is ample for any realistic TrustObservations
	// response.
	MaxBodyBytes int64
}

// Fetch retrieves the trust observations for subject from the given
// observer domain. observerBaseURL is the fully-qualified base URL
// of the observer's well-known endpoint (e.g.
// "https://observer.example.com"); the fetcher appends
// PublicationPath + subject. The returned response has been
// verified at the envelope level AND at the per-observation level;
// any observation whose signature does not verify is DROPPED with a
// non-fatal log call via cfg.Signer.
func Fetch(ctx context.Context, cfg FetcherConfig, observerBaseURL, subject string) (*TrustObservations, error) {
	if cfg.Signer == nil {
		return nil, errors.New("reputation: Fetch missing Signer")
	}
	if len(cfg.ObserverPublicKey) == 0 {
		return nil, errors.New("reputation: Fetch missing ObserverPublicKey")
	}
	if subject == "" {
		return nil, errors.New("reputation: Fetch missing subject")
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	maxBody := cfg.MaxBodyBytes
	if maxBody <= 0 {
		maxBody = 1 << 20
	}
	url := strings.TrimRight(observerBaseURL, "/") + PublicationPath + subject
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("reputation: build fetch request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	httpResp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("reputation: GET %s: %w", url, err)
	}
	defer httpResp.Body.Close()
	if httpResp.StatusCode < 200 || httpResp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(httpResp.Body, 4096))
		return nil, fmt.Errorf("reputation: GET %s returned %d: %s", url, httpResp.StatusCode, string(body))
	}
	body, err := io.ReadAll(io.LimitReader(httpResp.Body, maxBody+1))
	if err != nil {
		return nil, fmt.Errorf("reputation: read response: %w", err)
	}
	if int64(len(body)) > maxBody {
		return nil, fmt.Errorf("reputation: response exceeds %d bytes", maxBody)
	}
	var resp TrustObservations
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("reputation: parse response: %w", err)
	}
	if resp.Type != ObservationsType {
		return nil, fmt.Errorf("reputation: response type = %q, want %q", resp.Type, ObservationsType)
	}

	// Envelope-level verification first.
	if err := VerifyTrustObservations(cfg.Signer, &resp, cfg.ObserverPublicKey); err != nil {
		return nil, err
	}

	// Per-observation verification. A response may legitimately
	// contain observations signed under different key_ids (key
	// rotation), but in the common case all observations share the
	// ObserverPublicKey. Drop any observation whose signature does
	// not verify under cfg.ObserverPublicKey rather than failing
	// the whole response — the envelope signature already bound the
	// observation set together, so a verified envelope with an
	// unverifiable inner observation indicates either a rotation
	// gap or a forged inner record.
	kept := resp.Observations[:0]
	for i := range resp.Observations {
		obs := &resp.Observations[i]
		if err := VerifyObservation(cfg.Signer, obs, cfg.ObserverPublicKey); err != nil {
			continue
		}
		kept = append(kept, *obs)
	}
	resp.Observations = kept
	return &resp, nil
}
