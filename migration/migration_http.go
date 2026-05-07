package migration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"semp.dev/semp-go/crypto"
)

// MigrationHandlerConfig bundles the inputs the old provider's
// `migration` endpoint handler needs.
type MigrationHandlerConfig struct {
	Suite crypto.Suite

	BasePath string // e.g., "/migration". Without trailing slash.

	// PublicationStore persists the four-sig record after
	// successful AcceptSubmission. Operators wire a durable
	// backend; the in-memory NewInMemoryPublicationStore covers
	// tests and demos.
	PublicationStore PublicationStore

	// OldDomainKeyID + OldDomainPriv sign the old-provider
	// countersignature.
	OldDomainKeyID string
	OldDomainPriv  []byte

	// LookupOldIdentityPub returns the bytes of the old identity
	// public key for the supplied old_identity_key_id. Operators
	// look up the user's identity key state by this fingerprint;
	// returning (nil, ErrUnknownIdentityKey) signals an unknown
	// key.
	LookupOldIdentityPub func(ctx context.Context, oldIdentityKeyID string) ([]byte, error)

	// LookupNewDomainPub returns the new provider's current
	// domain signing key for the supplied new_address's domain.
	// Operators fetch this from the new provider's discovery
	// configuration.
	LookupNewDomainPub func(ctx context.Context, newDomain string) ([]byte, error)

	// LookupOldIdentityCreated returns the creation timestamp of
	// the old identity key for the §3.4 migrated_at lower-bound
	// check.
	LookupOldIdentityCreated func(ctx context.Context, oldIdentityKeyID string) (time.Time, error)

	// ForwardingPolicy is the operator's per-window-bound check;
	// nil accepts any spec-conformant window.
	ForwardingPolicy func(window time.Duration) error

	// Reservations is the §6.1 lockout registry. Required.
	Reservations LockoutRegistry

	// NowFn supplies the wall-clock; defaults to time.Now().UTC.
	NowFn func() time.Time
}

// PublicationStore retains published 4-sig migration records for
// the §3.4 publication endpoint. Operators wire a durable backend;
// NewInMemoryPublicationStore is the reference implementation.
type PublicationStore interface {
	// PutRecord persists a published 4-sig record.
	PutRecord(ctx context.Context, r *MigrationRecord) error

	// GetByOldAddress returns the most recent published record
	// for the given old address, or (nil, nil) when none exists.
	// Per §6.2 the record remains published as historical evidence
	// even after the local-part is reassigned.
	GetByOldAddress(ctx context.Context, oldAddress string) (*MigrationRecord, error)

	// GetByRecordID returns the record with the given id, or
	// (nil, nil) when not found.
	GetByRecordID(ctx context.Context, recordID string) (*MigrationRecord, error)
}

// ErrUnknownIdentityKey is returned by a
// LookupOldIdentityPub callback when the supplied key id is not in
// the operator's key history.
var ErrUnknownIdentityKey = errors.New("migration: unknown identity key")

// MigrationHandler returns an http.Handler implementing the §4.1
// `migration` endpoint on the old provider side. The handler
// routes:
//
//   - POST  <BasePath>            : accept a new-provider submission
//     (cooperative flow §4.1 step 7-8). Verifies the three submitted
//     signatures, applies the forwarding policy, registers the §6.1
//     lockout, countersigns, persists, and returns the 4-sig record.
//   - GET   <BasePath>/<old_address>  : fetch the published record
//     for the given old address per §3.4.
//   - GET   <BasePath>/by-id/<record_id> : fetch by record_id.
//
// Errors return a JSON `{"error":"<reason>"}` body with the
// appropriate HTTP status: 400 for malformed input, 403 for
// signature / mode rejection, 409 for lockout / supersedes
// conflicts, 500 for store / lookup failures.
func MigrationHandler(cfg MigrationHandlerConfig) (http.Handler, error) {
	if cfg.Suite == nil {
		return nil, errors.New("migration: handler requires Suite")
	}
	if cfg.BasePath == "" {
		return nil, errors.New("migration: handler requires BasePath")
	}
	if cfg.PublicationStore == nil {
		return nil, errors.New("migration: handler requires PublicationStore")
	}
	if cfg.OldDomainKeyID == "" || len(cfg.OldDomainPriv) == 0 {
		return nil, errors.New("migration: handler requires OldDomainKeyID and OldDomainPriv")
	}
	if cfg.LookupOldIdentityPub == nil || cfg.LookupNewDomainPub == nil ||
		cfg.LookupOldIdentityCreated == nil {
		return nil, errors.New("migration: handler requires every lookup callback")
	}
	if cfg.Reservations == nil {
		return nil, errors.New("migration: handler requires Reservations")
	}
	now := cfg.NowFn
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	cfg.BasePath = strings.TrimRight(cfg.BasePath, "/")
	return &migrationHandler{cfg: cfg, nowFn: now}, nil
}

type migrationHandler struct {
	cfg   MigrationHandlerConfig
	nowFn func() time.Time
}

func (h *migrationHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		h.handleSubmit(w, r)
	case http.MethodGet:
		h.handleGet(w, r)
	default:
		w.Header().Set("Allow", "GET, POST")
		writeMigrationError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (h *migrationHandler) handleSubmit(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != h.cfg.BasePath {
		writeMigrationError(w, http.StatusNotFound, "POST takes no path suffix")
		return
	}
	var rec MigrationRecord
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rec); err != nil {
		writeMigrationError(w, http.StatusBadRequest, fmt.Sprintf("decode record: %v", err))
		return
	}
	ctx := r.Context()
	oldIdentityPub, err := h.cfg.LookupOldIdentityPub(ctx, rec.OldIdentityKeyID)
	if err != nil {
		if errors.Is(err, ErrUnknownIdentityKey) {
			writeMigrationError(w, http.StatusForbidden, "unknown old identity key")
			return
		}
		writeMigrationError(w, http.StatusInternalServerError, fmt.Sprintf("identity lookup: %v", err))
		return
	}
	newDomain := domainOf(rec.NewAddress)
	if newDomain == "" {
		writeMigrationError(w, http.StatusBadRequest, "new_address has no domain")
		return
	}
	newDomainPub, err := h.cfg.LookupNewDomainPub(ctx, newDomain)
	if err != nil {
		writeMigrationError(w, http.StatusInternalServerError, fmt.Sprintf("new domain key lookup: %v", err))
		return
	}
	oldCreated, err := h.cfg.LookupOldIdentityCreated(ctx, rec.OldIdentityKeyID)
	if err != nil {
		writeMigrationError(w, http.StatusInternalServerError, fmt.Sprintf("old identity created lookup: %v", err))
		return
	}

	final, err := AcceptSubmission(ctx, AcceptInput{
		Suite:              h.cfg.Suite,
		Record:             &rec,
		OldIdentityPub:     oldIdentityPub,
		NewDomainPub:       newDomainPub,
		OldDomainKeyID:     h.cfg.OldDomainKeyID,
		OldDomainPriv:      h.cfg.OldDomainPriv,
		Now:                h.nowFn(),
		OldIdentityCreated: oldCreated,
		ForwardingPolicy:   h.cfg.ForwardingPolicy,
		Reservations:       h.cfg.Reservations,
	})
	if err != nil {
		switch {
		case errors.Is(err, ErrLocalPartLockedOut),
			errors.Is(err, ErrForwardingWindowRefused):
			writeMigrationError(w, http.StatusConflict, err.Error())
		default:
			writeMigrationError(w, http.StatusForbidden, err.Error())
		}
		return
	}
	if err := h.cfg.PublicationStore.PutRecord(ctx, final); err != nil {
		writeMigrationError(w, http.StatusInternalServerError, fmt.Sprintf("publish: %v", err))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(final)
}

func (h *migrationHandler) handleGet(w http.ResponseWriter, r *http.Request) {
	suffix := strings.TrimPrefix(r.URL.Path, h.cfg.BasePath)
	suffix = strings.TrimPrefix(suffix, "/")
	suffix = path.Clean(suffix)
	if suffix == "" || suffix == "." {
		writeMigrationError(w, http.StatusNotFound, "GET requires a path suffix (old_address or by-id/<record_id>)")
		return
	}
	ctx := r.Context()
	if strings.HasPrefix(suffix, "by-id/") {
		id := strings.TrimPrefix(suffix, "by-id/")
		if id == "" || strings.Contains(id, "/") {
			writeMigrationError(w, http.StatusBadRequest, "malformed record_id")
			return
		}
		decoded, err := url.PathUnescape(id)
		if err != nil {
			writeMigrationError(w, http.StatusBadRequest, "record_id urlencoding")
			return
		}
		rec, err := h.cfg.PublicationStore.GetByRecordID(ctx, decoded)
		if err != nil {
			writeMigrationError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if rec == nil {
			writeMigrationError(w, http.StatusNotFound, "no record with that id")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(rec)
		return
	}
	addr, err := url.PathUnescape(suffix)
	if err != nil {
		writeMigrationError(w, http.StatusBadRequest, "old_address urlencoding")
		return
	}
	rec, err := h.cfg.PublicationStore.GetByOldAddress(ctx, addr)
	if err != nil {
		writeMigrationError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if rec == nil {
		writeMigrationError(w, http.StatusNotFound, "no record for that old address")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(rec)
}

func writeMigrationError(w http.ResponseWriter, status int, reason string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": reason})
}

// domainOf returns the domain portion of an address; "" when the
// address has no '@'.
func domainOf(addr string) string {
	i := strings.LastIndex(addr, "@")
	if i < 0 {
		return ""
	}
	return addr[i+1:]
}
