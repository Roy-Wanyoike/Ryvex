package api

// Tests for issue #84: CORS matrix coverage, 405 enforcement on the
// 4-segment scope-list route, request-id hardening (bounded length,
// safe charset), and errors.Is-based state error mapping.

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Roy-Wanyoike/Ryvex/internal/bus"
	"github.com/Roy-Wanyoike/Ryvex/internal/reconcile"
	"github.com/Roy-Wanyoike/Ryvex/internal/state"
)

const corsAllowedOrigin = "http://localhost:3100"

// newCORSServer boots the standard legacy-auth test server with one
// allowed CORS origin (the web console's dev origin).
func newCORSServer(t *testing.T) http.Handler {
	t.Helper()
	store := state.NewStore()
	eventBus := bus.New()
	rec := reconcile.New(store, eventBus, reconcile.Options{Interval: time.Hour, Logger: discardLogger()})
	ctx, cancel := context.WithCancel(context.Background())
	rec.Start(ctx)
	t.Cleanup(func() {
		cancel()
		rec.Stop(2 * time.Second)
	})
	return NewServer(store, eventBus, rec, ServerOptions{
		Auth:        AuthOptions{APIKeys: map[string]string{testToken: "ci"}},
		Logger:      discardLogger(),
		CORSOrigins: []string{corsAllowedOrigin},
	})
}

// corsDo issues a request carrying exactly the headers the test asks
// for — unlike do() it adds no Authorization or Content-Type header,
// so preflight short-circuiting can be observed pre-auth.
func corsDo(t *testing.T, h http.Handler, method, path, origin string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

// corsHeadersAbsent asserts no Access-Control-* header leaked onto the
// response.
func corsHeadersAbsent(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	for _, name := range []string{
		"Access-Control-Allow-Origin",
		"Access-Control-Allow-Methods",
		"Access-Control-Allow-Headers",
		"Access-Control-Max-Age",
	} {
		if got := w.Header().Get(name); got != "" {
			t.Errorf("%s must not be set for this origin, got %q", name, got)
		}
	}
}

// ---- CORS matrix (issue #84) ----

func TestCORSMatrix(t *testing.T) {
	h := newCORSServer(t)
	cases := []struct {
		name       string
		method     string
		path       string
		origin     string
		withToken  bool
		wantStatus int
		wantACAO   string // "" = header must be absent
	}{
		{"allowed origin GET gets cors headers", http.MethodGet, "/v1", corsAllowedOrigin, true, http.StatusOK, corsAllowedOrigin},
		{"disallowed origin GET gets no headers", http.MethodGet, "/v1", "http://evil.example", true, http.StatusOK, ""},
		{"no origin gets no headers", http.MethodGet, "/v1", "", true, http.StatusOK, ""},
		{"origin match is exact: suffix", http.MethodGet, "/v1", corsAllowedOrigin + ".evil.example", true, http.StatusOK, ""},
		{"origin match is exact: scheme", http.MethodGet, "/v1", "https://localhost:3100", true, http.StatusOK, ""},
		{"origin match is exact: case", http.MethodGet, "/v1", "HTTP://LOCALHOST:3100", true, http.StatusOK, ""},
		{"preflight allowed origin short-circuits pre-auth", http.MethodOptions, "/v1/resources", corsAllowedOrigin, false, http.StatusNoContent, corsAllowedOrigin},
		{"preflight disallowed origin leaks no headers", http.MethodOptions, "/v1/resources", "http://evil.example", false, http.StatusNoContent, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			headers := map[string]string{}
			if c.withToken {
				headers["Authorization"] = "Bearer " + testToken
			}
			w := corsDo(t, h, c.method, c.path, c.origin, headers)
			if w.Code != c.wantStatus {
				t.Fatalf("status = %d, want %d (body: %.200s)", w.Code, c.wantStatus, w.Body.String())
			}
			if got := w.Header().Get("Access-Control-Allow-Origin"); got != c.wantACAO {
				t.Fatalf("Access-Control-Allow-Origin = %q, want %q", got, c.wantACAO)
			}
			if c.wantACAO == "" {
				corsHeadersAbsent(t, w)
				return
			}
			// Full header set on allowed-origin responses.
			if got := w.Header().Get("Vary"); got != "Origin" {
				t.Errorf("Vary = %q, want Origin", got)
			}
			if got := w.Header().Get("Access-Control-Allow-Methods"); got != "GET, POST, PUT, DELETE, OPTIONS" {
				t.Errorf("Access-Control-Allow-Methods = %q", got)
			}
			if got := w.Header().Get("Access-Control-Allow-Headers"); got != "Authorization, Content-Type" {
				t.Errorf("Access-Control-Allow-Headers = %q", got)
			}
			if got := w.Header().Get("Access-Control-Max-Age"); got != "600" {
				t.Errorf("Access-Control-Max-Age = %q", got)
			}
		})
	}
}

// Preflight needs no token even on protected routes: the OPTIONS
// short-circuit fires before the auth middleware.
func TestPreflightPreAuth(t *testing.T) {
	h := newCORSServer(t)
	w := corsDo(t, h, http.MethodOptions, "/v1/resources", corsAllowedOrigin, nil)
	if w.Code != http.StatusNoContent {
		t.Fatalf("preflight = %d, want 204 (body: %s)", w.Code, w.Body.String())
	}
	if w.Body.Len() != 0 {
		t.Fatalf("preflight body must be empty, got %q", w.Body.String())
	}
	if w.Header().Get("Access-Control-Allow-Origin") != corsAllowedOrigin {
		t.Fatalf("preflight must carry the allowed origin")
	}
}

// ---- 405 on the 4-segment scope-list route (issue #84) ----

func TestScopeListRouteMethodMatrix(t *testing.T) {
	h := newTestServer(t)
	seedScopeResources(t, h, 2) // sanity seed: GET must still list

	// GET stays a 200 list.
	w := do(t, h, http.MethodGet, "/v1/acme/core/prod/applications", "")
	if w.Code != http.StatusOK {
		t.Fatalf("GET scope list: want 200, got %d: %s", w.Code, w.Body.String())
	}
	if items := decode(t, w)["items"].([]any); len(items) != 2 {
		t.Fatalf("GET scope list: want 2 items, got %d", len(items))
	}

	for _, method := range []string{
		http.MethodPost,
		http.MethodPut,
		http.MethodDelete,
		http.MethodPatch,
		http.MethodOptions,
	} {
		t.Run(method, func(t *testing.T) {
			// do() sets a valid bearer token and no Origin header, so the
			// request reaches routeV1 and the method switch decides.
			w := do(t, h, method, "/v1/acme/core/prod/applications", appBody)
			if w.Code != http.StatusMethodNotAllowed {
				t.Fatalf("%s on 4-segment scope route: want 405, got %d: %s", method, w.Code, w.Body.String())
			}
			if allow := w.Header().Get("Allow"); allow != http.MethodGet {
				t.Fatalf("%s: Allow = %q, want GET", method, allow)
			}
			m := decode(t, w)
			if m["error"].(map[string]any)["code"] != CodeMethodNotAllowed {
				t.Fatalf("%s: envelope code = %s", method, w.Body.String())
			}
			if m["error"].(map[string]any)["request_id"] == "" {
				t.Fatalf("%s: 405 envelope must carry a request_id", method)
			}
		})
	}

	// The method change must not have widened the 5-segment item route:
	// POST there was already a 405.
	w = do(t, h, http.MethodPost, "/v1/acme/core/prod/applications/checkout", appBody)
	if w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") != "GET, PUT, DELETE" {
		t.Fatalf("5-segment POST: want 405 with Allow GET, PUT, DELETE, got %d / %q", w.Code, w.Header().Get("Allow"))
	}
}

// ---- request-id hardening (issue #84) ----

var generatedRequestID = regexp.MustCompile(`^[0-9a-f]{12}$`)

func TestRequestIDHardening(t *testing.T) {
	h := newTestServer(t)
	long64 := strings.Repeat("a", 64)
	long65 := strings.Repeat("a", 65)
	cases := []struct {
		name     string
		client   string
		wantEcho bool
	}{
		{"missing id generates one", "", false},
		{"valid id echoed", "web-frontend.42", true},
		{"boundary 64 chars echoed", long64, true},
		{"65 chars regenerated", long65, false},
		{"newline injection regenerated", "id\nX-Evil: 1", false},
		{"ansi escape regenerated", "id\x1b[31mred", false},
		{"space regenerated", "id with space", false},
		{"slash regenerated", "../etc/passwd", false},
		{"quote regenerated", `id"quote`, false},
		{"unicode regenerated", "идентификатор", false},
		{"tab regenerated", "id\ttab", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// Unauthenticated request on purpose: the 401 envelope echoes
			// the request id, so both the header and the envelope paths
			// are observable.
			headers := map[string]string{}
			if c.client != "" {
				headers["X-Request-Id"] = c.client
			}
			w := corsDo(t, h, http.MethodGet, "/v1/resources", "", headers)
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("want 401, got %d: %s", w.Code, w.Body.String())
			}
			got := w.Header().Get("X-Request-Id")
			if got == "" {
				t.Fatalf("X-Request-Id response header missing")
			}
			if c.wantEcho {
				if got != c.client {
					t.Fatalf("client id %q must be echoed, got %q", c.client, got)
				}
			} else {
				if got == c.client {
					t.Fatalf("unsafe client id must be regenerated, got it back verbatim")
				}
				if !generatedRequestID.MatchString(got) {
					t.Fatalf("regenerated id %q must be 12 lowercase hex chars", got)
				}
			}
			// The error envelope must carry the same (safe) id.
			if env := decode(t, w)["error"].(map[string]any)["request_id"]; env != got {
				t.Fatalf("envelope request_id = %v, want %q (injection surface)", env, got)
			}
		})
	}

	// Generated ids are unique per request.
	w1 := corsDo(t, h, http.MethodGet, "/v1/resources", "", nil)
	w2 := corsDo(t, h, http.MethodGet, "/v1/resources", "", nil)
	if w1.Header().Get("X-Request-Id") == w2.Header().Get("X-Request-Id") {
		t.Fatalf("two requests without a client id must get distinct ids")
	}
}

// ---- errors.Is-based mapping + wrapped validation (issue #84) ----

func TestStateStatusMappingUsesErrorsIs(t *testing.T) {
	ve := &state.ValidationError{Field: "kind", Message: "unknown kind"}
	cases := []struct {
		name       string
		err        error
		wantStatus int
		wantCode   string
	}{
		{"plain not found", state.ErrNotFound, http.StatusNotFound, CodeNotFound},
		{"wrapped not found", fmt.Errorf("store: %w", state.ErrNotFound), http.StatusNotFound, CodeNotFound},
		{"double-wrapped already exists", fmt.Errorf("l1: %w", fmt.Errorf("l2: %w", state.ErrAlreadyExists)), http.StatusConflict, CodeAlreadyExists},
		{"wrapped conflict", fmt.Errorf("cas: %w", state.ErrConflict), http.StatusConflict, CodeConflict},
		{"wrapped bad request", fmt.Errorf("cursor: %w", state.ErrBadRequest), http.StatusBadRequest, CodeBadRequest},
		{"wrapped validation error", fmt.Errorf("schema: %w", ve), http.StatusBadRequest, CodeValidation},
		{"validation sentinel", fmt.Errorf("ctx: %w", state.ErrValidation), http.StatusBadRequest, CodeValidation},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			stateStatus(w, httptest.NewRequest(http.MethodGet, "/v1/resources", nil), c.err)
			if w.Code != c.wantStatus {
				t.Fatalf("status = %d, want %d: %s", w.Code, c.wantStatus, w.Body.String())
			}
			if got := decode(t, w)["error"].(map[string]any)["code"]; got != c.wantCode {
				t.Fatalf("code = %v, want %q", got, c.wantCode)
			}
		})
	}

	// Unmapped errors stay a 500.
	w := httptest.NewRecorder()
	stateStatus(w, httptest.NewRequest(http.MethodGet, "/v1/resources", nil), fmt.Errorf("boom"))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("unmapped error: want 500, got %d", w.Code)
	}
}

func TestAsValidationUnwraps(t *testing.T) {
	inner := &state.ValidationError{Field: "spec", Message: "spec required"}
	wrapped := fmt.Errorf("upsert: %w", fmt.Errorf("validate: %w", inner))

	var ve *state.ValidationError
	if !asValidation(wrapped, &ve) {
		t.Fatalf("asValidation must unwrap the chain")
	}
	if ve != inner {
		t.Fatalf("asValidation must surface the inner error, got %+v", ve)
	}
	if !isValidation(wrapped) {
		t.Fatalf("wrapped ValidationError must be recognized as validation")
	}
	if !isValidation(fmt.Errorf("ctx: %w", state.ErrValidation)) {
		t.Fatalf("wrapped ErrValidation sentinel must be recognized")
	}

	// Non-validation errors stay unrecognized and leave the target nil.
	var out *state.ValidationError
	if asValidation(state.ErrNotFound, &out) || out != nil {
		t.Fatalf("ErrNotFound must not match ValidationError, got %+v", out)
	}
	if isValidation(state.ErrConflict) {
		t.Fatalf("ErrConflict is not validation")
	}
}
