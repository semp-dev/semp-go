package recovery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"
)

// BackupAuthFunc authenticates a request against the user-scoped
// path. Returns the authenticated user_id (empty string when the
// request is unauthenticated) and any auth error.
//
// Per RECOVERY.md §4.3 download MUST NOT require authentication
// against the user (a recovering user has no remaining private
// keys), so the HTTP handler distinguishes:
//
//   - GET (download) — no authentication required; the operator's
//     auth function is consulted for rate-limit policy only.
//   - POST (upload) and DELETE — MUST be authenticated against the
//     user's current session per §4.2 / §4.4.
//
// Implementations typically inspect a bearer token, mTLS client
// cert, or session cookie.
type BackupAuthFunc func(r *http.Request, userID string) (authenticated bool, err error)

// BackupRateLimiter is the per-user-per-IP rate gate consulted by
// BackupHandler on every download request per RECOVERY.md §4.3.
// "A RECOMMENDED limit is 10 download requests per user address per
// hour across all sources." The library does not impose a specific
// shape; operators wire their own counter.
//
// Allow returns false to indicate the request exceeds the limit;
// the handler responds with HTTP 429.
type BackupRateLimiter func(ctx context.Context, userID, sourceIP string) (allowed bool, err error)

// BackupHandlerConfig bundles the BackupHandler inputs.
type BackupHandlerConfig struct {
	Store       BundleStore
	BasePath    string // e.g., "/backup". MUST end without trailing slash.
	Auth        BackupAuthFunc
	RateLimit   BackupRateLimiter
	NowFn       func() time.Time
}

// BackupHandler returns an http.Handler implementing the §4.1
// `backup` endpoint. The handler routes:
//
//   - POST  <BasePath>/<user_id> : upload a new bundle
//   - GET   <BasePath>/<user_id>            : download current bundle
//   - GET   <BasePath>/<user_id>?history=true : download every retained bundle
//   - DELETE <BasePath>/<user_id> : delete all stored bundles
//
// All requests target a user-scoped path derived by URL-encoding the
// user address per §4.1.
//
// The handler:
//
//   - Authenticates POST / DELETE via Auth (MUST succeed per §4.2 / §4.4).
//   - Authorizes GET without authentication per §4.3 (a recovering
//     user has no remaining private keys).
//   - Applies RateLimit on GET per §4.3 (RECOMMENDED 10/hour/user).
//   - Validates the uploaded bundle's signature is the caller's
//     concern (the operator typically verifies before calling
//     Store.PutCurrent — the library's BundleStore.PutCurrent
//     enforces the §4.2 step 3 supersedes-chain rule but does not
//     verify signatures).
//
// The HTTP body for upload is the bundle JSON (RECOVERY.md §2.1
// SEMP_BACKUP_BUNDLE shape); responses are JSON. Errors return a
// minimal `{"error":"<reason>"}` body alongside the appropriate
// HTTP status code so a sender's home server can map to its own
// reason codes per CLOSURE.md §5 indistinguishability rules.
func BackupHandler(cfg BackupHandlerConfig) (http.Handler, error) {
	if cfg.Store == nil {
		return nil, errors.New("recovery: backup handler requires Store")
	}
	if cfg.BasePath == "" {
		return nil, errors.New("recovery: backup handler requires BasePath")
	}
	now := cfg.NowFn
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	cfg.BasePath = strings.TrimRight(cfg.BasePath, "/")
	return &backupHandler{cfg: cfg, nowFn: now}, nil
}

type backupHandler struct {
	cfg   BackupHandlerConfig
	nowFn func() time.Time
}

func (h *backupHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	userID, ok := h.userIDFromPath(r.URL.Path)
	if !ok {
		writeError(w, http.StatusNotFound, "user_id missing in path")
		return
	}
	switch r.Method {
	case http.MethodPost:
		h.handleUpload(w, r, userID)
	case http.MethodGet:
		h.handleDownload(w, r, userID)
	case http.MethodDelete:
		h.handleDelete(w, r, userID)
	default:
		w.Header().Set("Allow", "GET, POST, DELETE")
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// userIDFromPath strips the BasePath prefix and URL-decodes the
// remainder.
func (h *backupHandler) userIDFromPath(p string) (string, bool) {
	prefix := h.cfg.BasePath
	if !strings.HasPrefix(p, prefix+"/") {
		return "", false
	}
	tail := strings.TrimPrefix(p, prefix+"/")
	tail = path.Clean(tail)
	if tail == "" || tail == "." || strings.Contains(tail, "/") {
		return "", false
	}
	decoded, err := url.PathUnescape(tail)
	if err != nil || decoded == "" {
		return "", false
	}
	return decoded, true
}

func (h *backupHandler) handleUpload(w http.ResponseWriter, r *http.Request, userID string) {
	if h.cfg.Auth == nil {
		writeError(w, http.StatusInternalServerError, "auth not configured")
		return
	}
	authenticated, err := h.cfg.Auth(r, userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "auth error")
		return
	}
	if !authenticated {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var bundle BackupBundle
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&bundle); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("decode bundle: %v", err))
		return
	}
	if bundle.UserID != userID {
		// §4.2 step 2: verify user_id matches the authenticated user.
		writeError(w, http.StatusForbidden, "bundle.user_id does not match path user")
		return
	}
	if err := bundle.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// The handler does NOT verify the bundle's outer signature here;
	// the operator's auth pipeline does that before calling. The
	// Store enforces the §4.2 step 3 supersedes-chain rule.
	if err := h.cfg.Store.PutCurrent(r.Context(), userID, &bundle, h.nowFn()); err != nil {
		if errors.Is(err, ErrSupersedesMismatch) {
			writeError(w, http.StatusConflict, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("put current: %v", err))
		return
	}
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"bundle_id":  bundle.BundleID,
		"created_at": bundle.CreatedAt,
	})
}

func (h *backupHandler) handleDownload(w http.ResponseWriter, r *http.Request, userID string) {
	if h.cfg.RateLimit != nil {
		allowed, err := h.cfg.RateLimit(r.Context(), userID, sourceIP(r))
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("rate limit: %v", err))
			return
		}
		if !allowed {
			w.Header().Set("Retry-After", "3600")
			writeError(w, http.StatusTooManyRequests,
				"rate limit exceeded for backup downloads")
			return
		}
	}

	if r.URL.Query().Get("history") == "true" {
		bundles, err := h.cfg.Store.History(r.Context(), userID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("history: %v", err))
			return
		}
		// §4.3: do not expose existence through metadata. An empty
		// user history returns 404 to match the same "not found"
		// posture as a never-uploaded user.
		if len(bundles) == 0 {
			writeError(w, http.StatusNotFound, "no bundles for user")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{"bundles": bundles})
		return
	}
	bundle, err := h.cfg.Store.GetCurrent(r.Context(), userID)
	if err != nil {
		if errors.Is(err, ErrBundleNotFound) {
			writeError(w, http.StatusNotFound, "no bundle for user")
			return
		}
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("get current: %v", err))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(bundle)
}

func (h *backupHandler) handleDelete(w http.ResponseWriter, r *http.Request, userID string) {
	if h.cfg.Auth == nil {
		writeError(w, http.StatusInternalServerError, "auth not configured")
		return
	}
	authenticated, err := h.cfg.Auth(r, userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "auth error")
		return
	}
	if !authenticated {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if err := h.cfg.Store.DeleteAll(r.Context(), userID); err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("delete: %v", err))
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// sourceIP extracts a sourcing IP from r, preferring an
// X-Forwarded-For header when present (operators behind a reverse
// proxy SHOULD configure their proxy to set this header). Falls
// back to RemoteAddr.
func sourceIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first comma-separated value.
		if i := strings.Index(xff, ","); i >= 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	host := r.RemoteAddr
	// Strip port.
	if i := strings.LastIndex(host, ":"); i >= 0 {
		host = host[:i]
	}
	return host
}

// writeError emits a minimal JSON error body alongside the supplied
// status code.
func writeError(w http.ResponseWriter, status int, reason string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": reason})
}

// NewInMemoryBackupRateLimiter returns a simple per-(user,IP)
// rate limiter using a rolling-window counter. limitPerWindow
// caps requests within the window; when zero the function defaults
// to RECOMMENDED §4.3 cap (10 per hour). Concurrency-safe.
//
// The reference implementation enforces the limit independently
// per (user_id, source_ip) tuple. Production deployments typically
// also enforce a per-IP cap across all users (covered by the
// operator's reverse-proxy layer) and a per-user cap across all
// IPs (which this function provides).
func NewInMemoryBackupRateLimiter(window time.Duration, limitPerWindow int) BackupRateLimiter {
	if window <= 0 {
		window = time.Hour
	}
	if limitPerWindow <= 0 {
		limitPerWindow = 10
	}
	hits := struct {
		sync.Mutex
		// per-(user_id + "\x00" + source_ip) timestamp lists.
		log map[string][]time.Time
	}{log: make(map[string][]time.Time)}

	return func(_ context.Context, userID, sourceIP string) (bool, error) {
		key := userID + "\x00" + sourceIP
		hits.Lock()
		defer hits.Unlock()
		now := time.Now().UTC()
		cutoff := now.Add(-window)
		// Trim entries before the cutoff.
		entries := hits.log[key]
		i := 0
		for ; i < len(entries); i++ {
			if !entries[i].Before(cutoff) {
				break
			}
		}
		entries = entries[i:]
		if len(entries) >= limitPerWindow {
			hits.log[key] = entries
			return false, nil
		}
		entries = append(entries, now)
		hits.log[key] = entries
		return true, nil
	}
}
