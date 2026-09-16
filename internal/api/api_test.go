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

// waitUntil polls cond every 5ms until it holds or the timeout
// expires: the eventual-consistency pattern from the #66 webhook fix
// ("wait for the audit trail, not the wire") for synchronizing with
// asynchronous background writers instead of racing them.
func waitUntil(t *testing.T, what string, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// auditTrail fetches an org's audit entries through the API.
// ListAudit is newest-first.
func auditTrail(t *testing.T, h http.Handler, org string) []any {
	t.Helper()
	w := do(t, h, http.MethodGet, "/v1/"+org+"/audit", "")
	if w.Code != http.StatusOK {
		t.Fatalf("audit: want 200, got %d", w.Code)
	}
	return decode(t, w)["entries"].([]any)
}

// findAuditEntry returns the first audit entry matching the given
// action and actor, or nil.
func findAuditEntry(entries []any, action, actor string) map[string]any {
	for _, e := range entries {
		m, ok := e.(map[string]any)
		if !ok {
			continue
		}
		if m["action"] == action && m["actor"] == actor {
			return m
		}
	}
	return nil
}

func TestEventsAndAudit(t *testing.T) {
	h := newTestServer(t)
	do(t, h, http.MethodPost, "/v1/resources", appBody)

	// No poll needed here: the created event is published synchronously
	// inside the POST handler before the 201 is written, and the
	// reconciler's async status_changed events share the same subject
	// namespace, so the prefix assertion holds under any interleaving.
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

	// Issue #70: newTestServer runs real reconciler workers whose
	// initial scan appends a status_changed entry (actor "reconciler")
	// to the same audit log asynchronously, so asserting the head
	// straight off the wire races that write. Wait for the audit trail
	// itself instead (same pattern as the #66 webhook fix).
	waitUntil(t, "created/ci audit entry", 5*time.Second, func() bool {
		return findAuditEntry(auditTrail(t, h, "acme"), "created", "ci") != nil
	})

	entries := auditTrail(t, h, "acme")
	if len(entries) == 0 {
		t.Fatalf("expected audit entries")
	}
	if findAuditEntry(entries, "created", "ci") == nil {
		t.Fatalf("created/ci entry missing from the settled audit trail: %v", entries)
	}
	// Head semantics under a live reconciler: the newest-first head is
	// legitimately either the API's created/ci entry or the
	// reconciler's async status_changed write — asserting a particular
	// winner is what made this test flaky. Assert the head is one of
	// the two legitimate writers for this timeline instead.
	head := entries[0].(map[string]any)
	switch {
	case head["action"] == "created" && head["actor"] == "ci":
		// API create still leads the trail.
	case head["action"] == "status_changed" && head["actor"] == "reconciler":
		// The reconciler's async status write won the head — valid.
	default:
		t.Fatalf("unexpected audit head: %v", head)
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
