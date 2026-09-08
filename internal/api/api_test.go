package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Roy-Wanyoike/Ryvex/internal/bus"
	"github.com/Roy-Wanyoike/Ryvex/internal/reconcile"
	"github.com/Roy-Wanyoike/Ryvex/internal/state"
)

const testToken = "ryk_test_abcdef123456"

func newTestServer(t *testing.T) http.Handler {
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
		Auth:   AuthOptions{APIKeys: map[string]string{testToken: "ci"}},
		Logger: discardLogger(),
	})
}

func do(t *testing.T, h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var rdr *bytes.Reader
	if body == "" {
		rdr = bytes.NewReader(nil)
	} else {
		rdr = bytes.NewReader([]byte(body))
	}
	req := httptest.NewRequest(method, path, rdr)
	req.Header.Set("Authorization", "Bearer "+testToken)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func decode(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	if w.Code == http.StatusNoContent {
		return map[string]any{}
	}
	var m map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatalf("non-JSON response (%d): %s", w.Code, w.Body.String())
	}
	return m
}

const appBody = `{"kind":"Application","org":"acme","project":"core","env":"prod","name":"checkout","labels":{"managed-by":"ryvex"},"spec":{"image":"checkout:1.42.0","replicas":3}}`

func TestHealthzOpenAccess(t *testing.T) {
	h := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil) // no auth header
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("healthz must be unauthenticated, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), `"status":"ok"`) {
		t.Fatalf("unexpected healthz body: %s", w.Body.String())
	}
}

func TestUnauthorized(t *testing.T) {
	h := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/v1/resources", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", w.Code)
	}
	m := decode(t, w)
	if m["error"].(map[string]any)["code"] != CodeUnauthorized {
		t.Fatalf("error code mismatch: %s", w.Body.String())
	}
	if m["error"].(map[string]any)["request_id"] == "" {
		t.Fatalf("request_id missing from error envelope")
	}
}

func TestCreateListGetDeleteRoundtrip(t *testing.T) {
	h := newTestServer(t)

	// create
	w := do(t, h, http.MethodPost, "/v1/resources", appBody)
	if w.Code != http.StatusCreated {
		t.Fatalf("create: want 201, got %d: %s", w.Code, w.Body.String())
	}
	created := decode(t, w)
	id, _ := created["id"].(string)
	if id == "" {
		t.Fatalf("no id in create response: %s", w.Body.String())
	}
	if created["status"].(map[string]any)["phase"] != state.PhasePending {
		t.Fatalf("new resource should start Pending")
	}

	// duplicate create -> 409 already_exists
	w = do(t, h, http.MethodPost, "/v1/resources", appBody)
	if w.Code != http.StatusConflict {
		t.Fatalf("duplicate: want 409, got %d", w.Code)
	}

	// list
	w = do(t, h, http.MethodGet, "/v1/resources?org=acme&kind=applications", "")
	if w.Code != http.StatusOK {
		t.Fatalf("list: want 200, got %d", w.Code)
	}
	items := decode(t, w)["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("want 1 item, got %d", len(items))
	}

	// get by id
	w = do(t, h, http.MethodGet, "/v1/resources/"+id, "")
	if w.Code != http.StatusOK {
		t.Fatalf("get: want 200, got %d", w.Code)
	}

	// get missing -> 404
	w = do(t, h, http.MethodGet, "/v1/resources/r-nonexistent", "")
	if w.Code != http.StatusNotFound {
		t.Fatalf("missing: want 404, got %d", w.Code)
	}

	// delete
	w = do(t, h, http.MethodDelete, "/v1/resources/"+id, "")
	if w.Code != http.StatusNoContent {
		t.Fatalf("delete: want 204, got %d", w.Code)
	}
	w = do(t, h, http.MethodGet, "/v1/resources/"+id, "")
	if w.Code != http.StatusNotFound {
		t.Fatalf("after delete: want 404, got %d", w.Code)
	}
}

func TestValidationRejected(t *testing.T) {
	h := newTestServer(t)
	w := do(t, h, http.MethodPost, "/v1/resources",
		`{"kind":"Widget","org":"acme","project":"core","env":"prod","name":"x","spec":{}}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for unknown kind, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), CodeValidation) {
		t.Fatalf("want validation_failed code, got %s", w.Body.String())
	}
	// malformed JSON
	w = do(t, h, http.MethodPost, "/v1/resources", `{"kind":`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for bad JSON, got %d", w.Code)
	}
}

func TestScopeAddressingAndPutCAS(t *testing.T) {
	h := newTestServer(t)

	// PUT create (upsert)
	w := do(t, h, http.MethodPut, "/v1/acme/core/prod/applications/checkout", appBody)
	if w.Code != http.StatusCreated {
		t.Fatalf("upsert create: want 201, got %d: %s", w.Code, w.Body.String())
	}
	first := decode(t, w)
	gen := int64(first["generation"].(float64))

	// GET via scope path
	w = do(t, h, http.MethodGet, "/v1/acme/core/prod/applications/checkout", "")
	if w.Code != http.StatusOK {
		t.Fatalf("scope get: want 200, got %d", w.Code)
	}

	// PUT with matching generation -> 200
	updated := fmt.Sprintf(`{"kind":"Application","org":"acme","project":"core","env":"prod","name":"checkout","labels":{"managed-by":"ryvex"},"spec":{"image":"checkout:1.42.0","replicas":9},"generation":%d}`, gen)
	w = do(t, h, http.MethodPut, "/v1/acme/core/prod/applications/checkout", updated)
	if w.Code != http.StatusOK {
		t.Fatalf("cas put: want 200, got %d: %s", w.Code, w.Body.String())
	}
	if int64(decode(t, w)["generation"].(float64)) != gen+1 {
		t.Fatalf("generation should advance on spec change")
	}

	// PUT with stale generation -> 409 conflict
	w = do(t, h, http.MethodPut, "/v1/acme/core/prod/applications/checkout", updated)
	if w.Code != http.StatusConflict {
		t.Fatalf("stale cas: want 409, got %d", w.Code)
	}

	// scope list by kind
	w = do(t, h, http.MethodGet, "/v1/acme/core/prod/applications", "")
	if w.Code != http.StatusOK || len(decode(t, w)["items"].([]any)) != 1 {
		t.Fatalf("scope list failed: %d %s", w.Code, w.Body.String())
	}

	// DELETE via scope
	w = do(t, h, http.MethodDelete, "/v1/acme/core/prod/applications/checkout", "")
	if w.Code != http.StatusNoContent {
		t.Fatalf("scope delete: want 204, got %d", w.Code)
	}
}

func TestEventsAndAudit(t *testing.T) {
	h := newTestServer(t)
	do(t, h, http.MethodPost, "/v1/resources", appBody)

	w := do(t, h, http.MethodGet, "/v1/acme/events", "")
	if w.Code != http.StatusOK {
		t.Fatalf("events: want 200, got %d", w.Code)
	}
	evts := decode(t, w)["events"].([]any)
	if len(evts) == 0 {
		t.Fatalf("expected at least one event")
	}
	first := evts[0].(map[string]any)
	if !strings.HasPrefix(first["subject"].(string), "ryvex.resource.") {
		t.Fatalf("subject must use the ryvex namespace: %v", first)
	}

	w = do(t, h, http.MethodGet, "/v1/acme/audit", "")
	if w.Code != http.StatusOK {
		t.Fatalf("audit: want 200, got %d", w.Code)
	}
	entries := decode(t, w)["entries"].([]any)
	if len(entries) == 0 {
		t.Fatalf("expected audit entries")
	}
	e0 := entries[0].(map[string]any)
	if e0["action"] != "created" || e0["actor"] != "ci" {
		t.Fatalf("unexpected audit head: %v", e0)
	}
}

func TestReconcileTriggerRoute(t *testing.T) {
	h := newTestServer(t)
	w := do(t, h, http.MethodPost, "/v1/resources", appBody)
	id := decode(t, w)["id"].(string)

	w = do(t, h, http.MethodPost, "/v1/acme/reconcile/"+id, "")
	if w.Code != http.StatusAccepted {
		t.Fatalf("reconcile trigger: want 202, got %d", w.Code)
	}
	// wrong org must 404
	w = do(t, h, http.MethodPost, "/v1/globex/reconcile/"+id, "")
	if w.Code != http.StatusNotFound {
		t.Fatalf("cross-org trigger: want 404, got %d", w.Code)
	}
}

func TestMethodNotAllowed(t *testing.T) {
	h := newTestServer(t)
	w := do(t, h, http.MethodPatch, "/v1/resources", "")
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("want 405, got %d", w.Code)
	}
	if w.Header().Get("Allow") == "" {
		t.Fatalf("Allow header required on 405")
	}
}

func TestAPIIndex(t *testing.T) {
	h := newTestServer(t)
	w := do(t, h, http.MethodGet, "/v1", "")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Ryvex") {
		t.Fatalf("api index broken: %d %s", w.Code, w.Body.String())
	}
}
