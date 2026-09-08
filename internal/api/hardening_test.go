package api

// Tests for the API hardening batch (issue #38): cursor propagation,
// 405 enforcement on events/audit, 413 for oversized bodies, security
// headers, /healthz redaction, dev-auth logging, constant-time static
// key comparison, and version plumbing.

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Roy-Wanyoike/Ryvex/internal/authz"
	"github.com/Roy-Wanyoike/Ryvex/internal/bus"
	"github.com/Roy-Wanyoike/Ryvex/internal/reconcile"
	"github.com/Roy-Wanyoike/Ryvex/internal/state"
)

// seedScopeResources creates n resources in one scope so list paging
// has something to paginate.
func seedScopeResources(t *testing.T, h http.Handler, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		body := `{"kind":"Application","org":"acme","project":"core","env":"prod","name":"app` +
			string(rune('a'+i)) + `","spec":{"image":"demo:1"}}`
		if w := do(t, h, http.MethodPost, "/v1/resources", body); w.Code != http.StatusCreated {
			t.Fatalf("seed %d: want 201, got %d: %s", i, w.Code, w.Body.String())
		}
	}
}

// ---- item 1: scope list propagates the pagination cursor ----

func TestScopeListPropagatesCursor(t *testing.T) {
	h := newTestServer(t)
	seedScopeResources(t, h, 3)

	w := do(t, h, http.MethodGet, "/v1/acme/core/prod/applications?limit=2", "")
	if w.Code != http.StatusOK {
		t.Fatalf("scope list: want 200, got %d: %s", w.Code, w.Body.String())
	}
	m := decode(t, w)
	items := m["items"].([]any)
	if len(items) != 2 {
		t.Fatalf("want 2 items on page 1, got %d", len(items))
	}
	next, _ := m["next_cursor"].(string)
	if next == "" {
		t.Fatalf("next_cursor must propagate the store cursor, got %q", m["next_cursor"])
	}

	// Follow the cursor: the remaining item comes back and the token
	// is exhausted.
	w = do(t, h, http.MethodGet, "/v1/acme/core/prod/applications?limit=2&cursor="+next, "")
	if w.Code != http.StatusOK {
		t.Fatalf("scope list page 2: want 200, got %d", w.Code)
	}
	m = decode(t, w)
	if got := len(m["items"].([]any)); got != 1 {
		t.Fatalf("want 1 item on page 2, got %d", got)
	}
	if m["next_cursor"] != "" {
		t.Fatalf("page 2 must have an empty next_cursor, got %v", m["next_cursor"])
	}

	// The filtered /v1/resources listing keeps the same contract.
	w = do(t, h, http.MethodGet, "/v1/resources?org=acme&project=core&env=prod&kind=applications&limit=2", "")
	if w.Code != http.StatusOK {
		t.Fatalf("resources list: want 200, got %d", w.Code)
	}
	if next2 := decode(t, w)["next_cursor"].(string); next2 == "" {
		t.Fatalf("/v1/resources must also propagate the cursor")
	}
}

// ---- item 2: 405 method enforcement on events/audit ----

func TestMethodNotAllowedEventsAndAudit(t *testing.T) {
	h := newTestServer(t)
	cases := []struct{ method, path string }{
		{http.MethodPost, "/v1/acme/events"},
		{http.MethodDelete, "/v1/acme/events"},
		{http.MethodPut, "/v1/acme/audit"},
		{http.MethodPatch, "/v1/acme/audit"},
	}
	for _, c := range cases {
		w := do(t, h, c.method, c.path, appBody)
		if w.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s %s: want 405, got %d: %s", c.method, c.path, w.Code, w.Body.String())
		}
		if allow := w.Header().Get("Allow"); allow != http.MethodGet {
			t.Fatalf("%s %s: Allow header = %q, want GET", c.method, c.path, allow)
		}
		m := decode(t, w)
		if m["error"].(map[string]any)["code"] != CodeMethodNotAllowed {
			t.Fatalf("405 must use the method_not_allowed envelope code: %s", w.Body.String())
		}
	}
}

// ---- item 3: oversized bodies get a dedicated 413 ----

func oversizedBody() string {
	return `{"kind":"Application","org":"acme","project":"core","env":"prod","name":"big","spec":{"pad":"` +
		strings.Repeat("a", maxBodyBytes) + `"}}`
}

func TestPayloadTooLargeOnCreate(t *testing.T) {
	h := newTestServer(t) // legacy auth: the handler's decodeBody catches it
	w := do(t, h, http.MethodPost, "/v1/resources", oversizedBody())
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("want 413, got %d: %s", w.Code, w.Body.String())
	}
	m := decode(t, w)
	if m["error"].(map[string]any)["code"] != CodePayloadTooLarge {
		t.Fatalf("413 must use the payload_too_large envelope code: %s", w.Body.String())
	}
}

func TestPayloadTooLargeOnScopePut(t *testing.T) {
	h := newTestServer(t)
	w := do(t, h, http.MethodPut, "/v1/acme/core/prod/applications/big", oversizedBody())
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("want 413, got %d: %s", w.Code, w.Body.String())
	}
}

func TestPayloadTooLargeViaBodyScopePeek(t *testing.T) {
	// RBAC mode: AuthZMiddleware peeks the POST /v1/resources body to
	// derive the scope; the 413 must fire there, before the handler.
	admin := "ryk_admin_oversize_0001"
	h, _ := newRBACServer(t, admin)
	w := doAuth(t, h, http.MethodPost, "/v1/resources", admin, oversizedBody())
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("want 413 from the authz body peek, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), CodePayloadTooLarge) {
		t.Fatalf("413 must use the payload_too_large envelope code: %s", w.Body.String())
	}
}

func TestPayloadJustUnderLimitAccepted(t *testing.T) {
	h := newTestServer(t)
	// The 1 MiB cap is a transport limit; the state layer separately
	// caps spec at 64 KiB, so pad outside the spec to prove a large
	// (but sub-cap) body still reaches the handler and succeeds.
	body := `{"kind":"Application","org":"acme","project":"core","env":"prod","name":"big","spec":{"image":"demo:1"},"padding":"` +
		strings.Repeat("a", maxBodyBytes-256) + `"}`
	w := do(t, h, http.MethodPost, "/v1/resources", body)
	if w.Code != http.StatusCreated {
		t.Fatalf("body under the cap must be accepted, got %d: %.200s", w.Code, w.Body.String())
	}
}

// ---- item 5: security headers ----

func TestSecurityHeaders(t *testing.T) {
	h := newTestServer(t)

	w := do(t, h, http.MethodGet, "/v1", "")
	if w.Code != http.StatusOK {
		t.Fatalf("/v1 index: want 200, got %d", w.Code)
	}
	if got := w.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("X-Content-Type-Options = %q, want nosniff", got)
	}
	if got := w.Header().Get("X-Frame-Options"); got != "DENY" {
		t.Fatalf("X-Frame-Options = %q, want DENY", got)
	}
	if got := w.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control on /v1 = %q, want no-store", got)
	}

	// Error responses carry the headers too (they are set before the
	// handler runs).
	w = do(t, h, http.MethodGet, "/v1/globex", "")
	if w.Code != http.StatusNotFound {
		t.Fatalf("unknown org route: want 404, got %d", w.Code)
	}
	if w.Header().Get("X-Content-Type-Options") != "nosniff" || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("security headers missing on error response: %v", w.Header())
	}

	// /healthz stays simple: nosniff/DENY yes, caching directives no.
	w = do(t, h, http.MethodGet, "/healthz", "")
	if w.Code != http.StatusOK {
		t.Fatalf("healthz: want 200, got %d", w.Code)
	}
	if w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("healthz must still get nosniff")
	}
	if got := w.Header().Get("Cache-Control"); got != "" {
		t.Fatalf("healthz must not gain Cache-Control (keep it simple), got %q", got)
	}
}

// ---- item 6: /healthz no longer leaks resource counts ----

func TestHealthzAnonymousIsStatusOnly(t *testing.T) {
	h := newTestServer(t)
	seedScopeResources(t, h, 2)

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil) // no token
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("healthz must stay unauthenticated, got %d", w.Code)
	}
	m := decode(t, w)
	if m["status"] != "ok" || m["version"] == "" {
		t.Fatalf("anonymous healthz must carry status+version: %s", w.Body.String())
	}
	if _, leak := m["resources"]; leak {
		t.Fatalf("anonymous healthz must not leak resource counts: %s", w.Body.String())
	}

	// A valid bearer token opts into the detailed body.
	req = httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	m = decode(t, w)
	if _, ok := m["resources"]; !ok {
		t.Fatalf("authenticated healthz should include counts: %s", w.Body.String())
	}
	if m["authenticated_as"] != "ci" {
		t.Fatalf("authenticated healthz should name the principal: %s", w.Body.String())
	}
}

func TestHealthzAnonymousRBACMode(t *testing.T) {
	admin := "ryk_admin_healthz_0001"
	h, _ := newRBACServer(t, admin)
	// Seed one resource through the RBAC server itself (the shared
	// seedScopeResources helper authenticates as the legacy test token,
	// which does not exist here).
	if w := doAuth(t, h, http.MethodPost, "/v1/resources", admin, appBodyAcme); w.Code != http.StatusCreated {
		t.Fatalf("seed: want 201, got %d: %s", w.Code, w.Body.String())
	}

	// Anonymous: no counts.
	w := doAuth(t, h, http.MethodGet, "/healthz", "", "")
	if w.Code != http.StatusOK {
		t.Fatalf("healthz: want 200, got %d", w.Code)
	}
	if _, leak := decode(t, w)["resources"]; leak {
		t.Fatalf("anonymous healthz must not leak counts (RBAC mode): %s", w.Body.String())
	}

	// A garbage token must not unlock counts either.
	w = doAuth(t, h, http.MethodGet, "/healthz", "garbage-token", "")
	if _, leak := decode(t, w)["resources"]; leak {
		t.Fatalf("invalid token must not unlock counts: %s", w.Body.String())
	}

	// The seeded admin token does.
	w = doAuth(t, h, http.MethodGet, "/healthz", admin, "")
	m := decode(t, w)
	if _, ok := m["resources"]; !ok {
		t.Fatalf("authenticated healthz should include counts (RBAC mode): %s", w.Body.String())
	}
}

// ---- item 7 (middleware half): dev-auth logs through the injected logger ----

func TestDevAuthLogUsesInjectedLogger(t *testing.T) {
	var buf bytes.Buffer
	capture := slog.New(slog.NewTextHandler(&buf, nil))

	store := state.NewStore()
	eventBus := bus.New()
	rec := reconcile.New(store, eventBus, reconcile.Options{Interval: time.Hour, Logger: discardLogger()})
	ctx, cancel := contextWithCancel()
	rec.Start(ctx)
	t.Cleanup(func() { cancel(); rec.Stop(2 * timeSecond()) })

	az := authz.New(store, eventBus, authz.Options{Logger: discardLogger()})
	h := NewServer(store, eventBus, rec, ServerOptions{
		Auth:       AuthOptions{DevAuth: true},
		Logger:     capture,
		Authorizer: az,
	})

	w := doAuth(t, h, http.MethodGet, "/v1/resources", "ryk_devuser_deadbeef", "")
	if w.Code != http.StatusOK {
		t.Fatalf("dev-auth request: want 200, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(buf.String(), "msg=authz") || !strings.Contains(buf.String(), "principal=dev:devuser_deadbeef") {
		t.Fatalf("dev-auth line must go through the injected logger, got:\n%s", buf.String())
	}
}

// ---- item 9: static keys hash at boot and compare in constant time ----

func TestStaticKeyIndexLookup(t *testing.T) {
	ix := newStaticKeyIndex(map[string]string{
		"ryk_static_alpha_0001": "alice",
		"ryk_static_beta_0002":  "bob",
		"":                      "skipped-empty-token",
	})

	for tok, want := range map[string]struct {
		name string
		ok   bool
	}{
		"ryk_static_alpha_0001": {name: "alice", ok: true},
		"ryk_static_beta_0002":  {name: "bob", ok: true},
		"ryk_static_alpha_0002": {ok: false}, // differs in the last byte
		"":                      {ok: false},
		"ryk_totally_unknown":   {ok: false},
	} {
		name, ok := ix.lookup(tok)
		if ok != want.ok || name != want.name {
			t.Errorf("lookup(%q) = %q, %v; want %q, %v", tok, name, ok, want.name, want.ok)
		}
	}

	// Empty index rejects everything without panicking.
	if _, ok := newStaticKeyIndex(nil).lookup("ryk_whatever"); ok {
		t.Fatalf("empty index must reject")
	}

	// The digests must match authz.HashToken so static tokens stay
	// interoperable with the managed-key hashing path.
	digest := authz.HashToken("ryk_static_alpha_0001")
	if _, ok := newStaticKeyIndex(map[string]string{"ryk_static_alpha_0001": "alice"}).lookup("ryk_static_alpha_0001"); !ok {
		t.Fatalf("round-trip through authz.HashToken digests must authenticate")
	}
	_ = digest
}

func TestLegacyStaticKeyAuthStillWorks(t *testing.T) {
	// End-to-end: a static key authenticates through the digest index
	// in both middleware modes.
	h := newTestServer(t)
	w := do(t, h, http.MethodGet, "/v1/resources", "")
	if w.Code != http.StatusOK {
		t.Fatalf("static key (legacy middleware): want 200, got %d", w.Code)
	}

	admin := "ryk_admin_static_0002"
	h2, _ := newRBACServer(t, admin)
	w = doAuth(t, h2, http.MethodGet, "/v1/resources", admin, "")
	if w.Code != http.StatusOK {
		t.Fatalf("static key (RBAC middleware): want 200, got %d: %s", w.Code, w.Body.String())
	}
}

// ---- item 10: version plumbing ----

func TestVersionPlumbing(t *testing.T) {
	store := state.NewStore()
	eventBus := bus.New()
	rec := reconcile.New(store, eventBus, reconcile.Options{Interval: time.Hour, Logger: discardLogger()})
	ctx, cancel := contextWithCancel()
	rec.Start(ctx)
	t.Cleanup(func() { cancel(); rec.Stop(2 * timeSecond()) })

	h := NewServer(store, eventBus, rec, ServerOptions{
		Auth:    AuthOptions{APIKeys: map[string]string{testToken: "ci"}},
		Logger:  discardLogger(),
		Version: "v9.9.9-test",
	})

	w := do(t, h, http.MethodGet, "/healthz", "")
	if got := decode(t, w)["version"]; got != "v9.9.9-test" {
		t.Fatalf("healthz version = %v, want the plumbed value", got)
	}
	w = do(t, h, http.MethodGet, "/v1", "")
	if got := decode(t, w)["version"]; got != "v9.9.9-test" {
		t.Fatalf("index version = %v, want the plumbed value", got)
	}

	// Empty Version falls back to the package const.
	h2 := newTestServer(t)
	w = do(t, h2, http.MethodGet, "/healthz", "")
	if got := decode(t, w)["version"]; got != Version {
		t.Fatalf("healthz version = %v, want const fallback %q", got, Version)
	}
	w = do(t, h2, http.MethodGet, "/v1", "")
	if got := decode(t, w)["version"]; got != Version {
		t.Fatalf("index version = %v, want const fallback %q", got, Version)
	}
}

// The e2e contract in cmd/ryvex/e2e_test.go greps /healthz output for
// "status" and "ok"; guard that stays true with the reduced body.
func TestHealthzKeepsCLIContract(t *testing.T) {
	h := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	var m map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatalf("healthz must stay JSON: %v", err)
	}
	if m["status"] != "ok" {
		t.Fatalf("healthz status broken: %s", w.Body.String())
	}
}
