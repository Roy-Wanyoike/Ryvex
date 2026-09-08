package api

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/Roy-Wanyoike/Ryvex/internal/bus"
	"github.com/Roy-Wanyoike/Ryvex/internal/reconcile"
	"github.com/Roy-Wanyoike/Ryvex/internal/state"
)

// Version is reported on /healthz and the API index.
const Version = "v1.0.0"

// Server wires the store, bus and reconciler into an HTTP handler.
type Server struct {
	store      state.Backend
	bus        *bus.Bus
	reconciler *reconcile.Reconciler
	log        *slog.Logger
	mux        *http.ServeMux
}

// ServerOptions configures NewServer.
type ServerOptions struct {
	Auth   AuthOptions
	Logger *slog.Logger
	// CORSOrigins lists browser origins allowed to call the API
	// (e.g. "http://localhost:3100"). Empty disables CORS.
	CORSOrigins []string
}

// NewServer builds the full handler stack:
// RequestID -> Recover -> Log -> Auth -> routes.
func NewServer(store state.Backend, b *bus.Bus, rec *reconcile.Reconciler, o ServerOptions) http.Handler {
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	s := &Server{store: store, bus: b, reconciler: rec, log: o.Logger, mux: http.NewServeMux()}

	s.mux.HandleFunc("/healthz", s.handleHealthz)
	s.mux.HandleFunc("/v1/", s.routeV1)
	s.mux.HandleFunc("/v1", s.handleIndex)
	s.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			writeError(w, r, http.StatusNotFound, CodeNotFound, "unknown route; the REST face lives under /v1/")
			return
		}
		s.handleIndex(w, r)
	})

	// /healthz stays open; everything under /v1 requires a key.
	o.Auth.SkipPrefixes = append(o.Auth.SkipPrefixes, "/healthz")
	stack := Chain(
		RequestIDMiddleware,
		RecoverMiddleware(o.Logger),
		LogMiddleware(o.Logger),
		CORSMiddleware(o.CORSOrigins),
		AuthMiddleware(o.Auth, o.Logger),
	)
	return stack(s.mux)
}

// Chain composes middleware left-to-right (first runs outermost).
func Chain(mws ...func(http.Handler) http.Handler) func(http.Handler) http.Handler {
	return func(final http.Handler) http.Handler {
		for i := len(mws) - 1; i >= 0; i-- {
			final = mws[i](final)
		}
		return final
	}
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":    "ok",
		"service":   "ryvexd",
		"version":   Version,
		"resources": s.store.Count(),
		"time":      nowUTC(),
	})
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"name":    "Ryvex Control Plane API",
		"version": Version,
		"endpoints": []string{
			"GET    /healthz",
			"GET    /v1",
			"POST   /v1/resources",
			"GET    /v1/resources?org=&project=&env=&kind=&limit=&cursor=",
			"GET    /v1/resources/{id}",
			"DELETE /v1/resources/{id}",
			"GET    /v1/{org}/events?limit=",
			"GET    /v1/{org}/audit?kind=&limit=",
			"POST   /v1/{org}/reconcile/{id}",
			"GET    /v1/{org}/{project}/{env}/{kind}",
			"GET    /v1/{org}/{project}/{env}/{kind}/{name}",
			"PUT    /v1/{org}/{project}/{env}/{kind}/{name}",
			"DELETE /v1/{org}/{project}/{env}/{kind}/{name}",
		},
		"docs": "docs/api-contracts.md",
	})
}

// routeV1 dispatches the /v1 face manually. The stdlib ServeMux cannot
// host these patterns together (segment-count ambiguity between
// /v1/resources/{id} and /v1/{org}/events), so we route on depth and
// bind path values explicitly with Go 1.22 SetPathValue.
func (s *Server) routeV1(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/v1")
	path = strings.Trim(path, "/")
	if path == "" {
		s.handleIndex(w, r)
		return
	}
	seg := strings.Split(path, "/")

	switch {
	case seg[0] == "resources" && len(seg) == 1:
		switch r.Method {
		case http.MethodPost:
			s.handleCreate(w, r)
		case http.MethodGet:
			s.handleList(w, r)
		default:
			methodNotAllowed(w, r, http.MethodPost, http.MethodGet)
		}
	case seg[0] == "resources" && len(seg) == 2:
		r.SetPathValue("id", seg[1])
		switch r.Method {
		case http.MethodGet:
			s.handleGetByID(w, r)
		case http.MethodDelete:
			s.handleDeleteByID(w, r)
		default:
			methodNotAllowed(w, r, http.MethodGet, http.MethodDelete)
		}
	case len(seg) == 2 && seg[1] == "events":
		s.handleEvents(w, r, seg[0])
	case len(seg) == 2 && seg[1] == "audit":
		s.handleAudit(w, r, seg[0])
	case len(seg) == 3 && seg[1] == "reconcile":
		if r.Method != http.MethodPost {
			methodNotAllowed(w, r, http.MethodPost)
			return
		}
		r.SetPathValue("org", seg[0])
		r.SetPathValue("id", seg[2])
		s.handleReconcile(w, r)
	case len(seg) == 4:
		s.handleScopeList(w, r, seg)
	case len(seg) == 5:
		r.SetPathValue("org", seg[0])
		r.SetPathValue("project", seg[1])
		r.SetPathValue("env", seg[2])
		r.SetPathValue("kind", seg[3])
		r.SetPathValue("name", seg[4])
		switch r.Method {
		case http.MethodGet:
			s.handleScopeGet(w, r)
		case http.MethodPut:
			s.handleScopePut(w, r)
		case http.MethodDelete:
			s.handleScopeDelete(w, r)
		default:
			methodNotAllowed(w, r, http.MethodGet, http.MethodPut, http.MethodDelete)
		}
	default:
		writeError(w, r, http.StatusNotFound, CodeNotFound, "unknown /v1 route")
	}
}

func methodNotAllowed(w http.ResponseWriter, r *http.Request, allow ...string) {
	w.Header().Set("Allow", strings.Join(allow, ", "))
	writeError(w, r, http.StatusMethodNotAllowed, CodeMethodNotAllowed, "method "+r.Method+" not allowed on this route")
}

func nowUTC() string { return timeNow().UTC().Format("2006-01-02T15:04:05Z") }

// decodeBody parses a JSON object body with a 1 MiB cap.
func decodeBody(r *http.Request, v any) error {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return state.ErrBadRequest
	}
	if len(body) == 0 {
		return &state.ValidationError{Field: "body", Message: "request body required"}
	}
	if err := json.Unmarshal(body, v); err != nil {
		return &state.ValidationError{Field: "body", Message: "invalid JSON: " + err.Error()}
	}
	return nil
}

func queryInt(r *http.Request, key string, def int) int {
	v := r.URL.Query().Get(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return def
	}
	return n
}
