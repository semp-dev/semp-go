package transparency

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
)

// LogHandlerConfig bundles inputs to LogHandler.
type LogHandlerConfig struct {
	Log      *Log
	BasePath string // e.g., "/v1/log"

	// AppendAuth is invoked on POST /entries to authenticate the
	// caller. Operators wire admission-policy logic here (only the
	// owning domain MAY append). When nil, POST is rejected with
	// 401 (no anonymous appends).
	AppendAuth func(r *http.Request) (authenticated bool, err error)
}

// LogHandler returns an http.Handler implementing the transparency
// log's monitor + append surface:
//
//   - POST <BasePath>/entries                : append a LogEntry.
//   - GET  <BasePath>/entries/<index>        : fetch a LogEntry by index.
//   - GET  <BasePath>/sth                     : fetch a fresh STH.
//   - GET  <BasePath>/proof/inclusion?leaf=<i>&size=<n>
//                                            : RFC 6962 inclusion proof.
//   - GET  <BasePath>/proof/consistency?from=<a>&to=<b>
//                                            : RFC 6962 consistency proof.
//
// Read paths are unauthenticated; POST requires AppendAuth.
//
// Errors return JSON `{"error":"<reason>"}` bodies with 400 / 401 /
// 404 / 405 / 500 status codes as appropriate.
func LogHandler(cfg LogHandlerConfig) (http.Handler, error) {
	if cfg.Log == nil {
		return nil, errors.New("transparency: log handler requires Log")
	}
	if cfg.BasePath == "" {
		return nil, errors.New("transparency: log handler requires BasePath")
	}
	cfg.BasePath = strings.TrimRight(cfg.BasePath, "/")
	return &logHandler{cfg: cfg}, nil
}

type logHandler struct {
	cfg LogHandlerConfig
}

func (h *logHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	suffix := strings.TrimPrefix(r.URL.Path, h.cfg.BasePath)
	suffix = strings.TrimPrefix(suffix, "/")
	switch {
	case suffix == "sth" && r.Method == http.MethodGet:
		h.handleSTH(w, r)
	case suffix == "entries" && r.Method == http.MethodPost:
		h.handleAppend(w, r)
	case strings.HasPrefix(suffix, "entries/") && r.Method == http.MethodGet:
		h.handleEntry(w, r, strings.TrimPrefix(suffix, "entries/"))
	case suffix == "proof/inclusion" && r.Method == http.MethodGet:
		h.handleInclusion(w, r)
	case suffix == "proof/consistency" && r.Method == http.MethodGet:
		h.handleConsistency(w, r)
	default:
		writeLogError(w, http.StatusNotFound, "no handler for path "+r.URL.Path)
	}
}

func (h *logHandler) handleSTH(w http.ResponseWriter, r *http.Request) {
	sth, err := h.cfg.Log.IssueSTH(r.Context())
	if err != nil {
		writeLogError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(sth)
}

func (h *logHandler) handleAppend(w http.ResponseWriter, r *http.Request) {
	if h.cfg.AppendAuth == nil {
		writeLogError(w, http.StatusUnauthorized, "append requires authentication")
		return
	}
	authenticated, err := h.cfg.AppendAuth(r)
	if err != nil {
		writeLogError(w, http.StatusInternalServerError, "auth error")
		return
	}
	if !authenticated {
		writeLogError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	var entry LogEntry
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&entry); err != nil {
		writeLogError(w, http.StatusBadRequest, "decode entry: "+err.Error())
		return
	}
	idx, err := h.cfg.Log.Append(r.Context(), entry)
	if err != nil {
		writeLogError(w, http.StatusBadRequest, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"leaf_index": idx,
	})
}

func (h *logHandler) handleEntry(w http.ResponseWriter, r *http.Request, indexStr string) {
	idx, err := strconv.ParseInt(indexStr, 10, 64)
	if err != nil {
		writeLogError(w, http.StatusBadRequest, "leaf index parse: "+err.Error())
		return
	}
	entry, err := h.cfg.Log.Entry(r.Context(), idx)
	if err != nil {
		if errors.Is(err, ErrEntryNotFound) {
			writeLogError(w, http.StatusNotFound, "entry not found")
			return
		}
		writeLogError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(entry)
}

func (h *logHandler) handleInclusion(w http.ResponseWriter, r *http.Request) {
	leafIndex, err := parseInt64(r.URL.Query().Get("leaf"))
	if err != nil {
		writeLogError(w, http.StatusBadRequest, "leaf query: "+err.Error())
		return
	}
	treeSize, err := parseInt64(r.URL.Query().Get("size"))
	if err != nil {
		writeLogError(w, http.StatusBadRequest, "size query: "+err.Error())
		return
	}
	proof, err := h.cfg.Log.InclusionProof(r.Context(), leafIndex, treeSize)
	if err != nil {
		switch {
		case errors.Is(err, ErrInvalidIndex), errors.Is(err, ErrInvalidTreeSize):
			writeLogError(w, http.StatusBadRequest, err.Error())
		default:
			writeLogError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(proof)
}

func (h *logHandler) handleConsistency(w http.ResponseWriter, r *http.Request) {
	from, err := parseInt64(r.URL.Query().Get("from"))
	if err != nil {
		writeLogError(w, http.StatusBadRequest, "from query: "+err.Error())
		return
	}
	to, err := parseInt64(r.URL.Query().Get("to"))
	if err != nil {
		writeLogError(w, http.StatusBadRequest, "to query: "+err.Error())
		return
	}
	proof, err := h.cfg.Log.ConsistencyProof(r.Context(), from, to)
	if err != nil {
		if errors.Is(err, ErrInvalidTreeSize) {
			writeLogError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeLogError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(proof)
}

func parseInt64(s string) (int64, error) {
	if s == "" {
		return 0, errors.New("missing")
	}
	return strconv.ParseInt(s, 10, 64)
}

func writeLogError(w http.ResponseWriter, status int, reason string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": reason})
}
