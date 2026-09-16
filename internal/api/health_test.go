package api

// Dependency-aware health tests (issue #71): /readyz must 503 while a
// dependency fails and 200 again once it recovers; /healthz must keep
// its 200 liveness contract while reporting dependency state honestly;
// a failed audit query must surface a 500 envelope instead of an empty
// success. The failure paths are simulated with thin wrappers around
// the real in-memory store/bus that fail only the health-relevant
// methods.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Roy-Wanyoike/Ryvex/internal/bus"
	"github.com/Roy-Wanyoike/Ryvex/internal/reconcile"
	"github.com/Roy-Wanyoike/Ryvex/internal/state"
)

// probeStore delegates everything to the real in-memory store except
// the health paths, which it can fail on demand.
type probeStore struct {
	*state.Store
	pingErr  error
	countErr error
	auditErr error
}

func (p *probeStore) Ping(_ context.Context) error { return p.pingErr }

func (p *probeStore) Count() (int, error) {
	if p.countErr != nil {
		return 0, p.countErr
	}
	return p.Store.Count()
}

func (p *probeStore) ListAudit(o state.AuditOptions) ([]state.AuditEntry, error) {
	if p.auditErr != nil {
		return nil, p.auditErr
	}
	return p.Store.ListAudit(o)
}

// probeBus delegates to the real in-memory bus but can fail the
// bus.HealthChecker capability.
type probeBus struct {
	*bus.Bus
	healthErr error
}

func (p *probeBus) Healthy() error { return p.healthErr }

// newProbeServer wires a server whose dependencies can be failed
// per-test. No reconciler loop: probes must not race background work.
func newProbeServer(t *testing.T, store state.Backend, b bus.BusI) http.Handler {
	t.Helper()
	rec := reconcile.New(store, b, reconcile.Options{Interval: time.Hour, Logger: discardLogger()})
	return NewServer(store, b, rec, ServerOptions{
		Auth:   AuthOptions{APIKeys: map[string]string{testToken: "ci"}},
		Logger: discardLogger(),
	})
}

func getBody(t *testing.T, h http.Handler, path string) (int, map[string]any, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil) // no auth: probes are open
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	var m map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatalf("probe %s returned non-JSON (%d): %s", path, w.Code, w.Body.String())
	}
	return w.Code, m, w.Body.String()
}

func depsOf(t *testing.T, m map[string]any) map[string]any {
	t.Helper()
	deps, ok := m["dependencies"].(map[string]any)
	if !ok {
		t.Fatalf("probe body missing dependencies map: %v", m)
	}
	return deps
}

func TestReadyzReadyWhileDependenciesAnswer(t *testing.T) {
	h := newProbeServer(t, state.NewStore(), bus.New())
	code, m, _ := getBody(t, h, "/readyz")
	if code != http.StatusOK {
		t.Fatalf("readyz with healthy dependencies: want 200, got %d: %v", code, m)
	}
	if m["status"] != "ready" {
		t.Fatalf("status = %v, want ready", m["status"])
	}
	deps := depsOf(t, m)
	if deps["store"] != "ok" || deps["bus"] != "ok" {
		t.Fatalf("dependencies = %v, want store=ok bus=ok", deps)
	}
}

// TestReadyzStoreDown: a dead store must hold the pod out of rotation
// (503) and the error detail must stay in the logs, not the body.
func TestReadyzStoreDown(t *testing.T) {
	pingErr := errors.New("store ping failed deliberately")
	h := newProbeServer(t, &probeStore{Store: state.NewStore(), pingErr: pingErr}, bus.New())
	code, m, raw := getBody(t, h, "/readyz")
	if code != http.StatusServiceUnavailable {
		t.Fatalf("readyz with dead store: want 503, got %d: %v", code, m)
	}
	if m["status"] != "unavailable" {
		t.Fatalf("status = %v, want unavailable", m["status"])
	}
	deps := depsOf(t, m)
	if deps["store"] != "unavailable" {
		t.Fatalf("dependencies.store = %v, want unavailable", deps["store"])
	}
	if deps["bus"] != "ok" {
		t.Fatalf("healthy bus must stay ok, got %v", deps["bus"])
	}
	if strings.Contains(strings.ToLower(raw), "deliberately") {
		t.Fatalf("probe body must not leak error detail: %s", raw)
	}
}

// TestReadyzBusDown: a bus that reports unhealthy also blocks readiness.
func TestReadyzBusDown(t *testing.T) {
	h := newProbeServer(t, state.NewStore(),
		&probeBus{Bus: bus.New(), healthErr: errors.New("bus disconnected")})
	code, m, _ := getBody(t, h, "/readyz")
	if code != http.StatusServiceUnavailable {
		t.Fatalf("readyz with dead bus: want 503, got %d: %v", code, m)
	}
	deps := depsOf(t, m)
	if deps["bus"] != "unavailable" || deps["store"] != "ok" {
		t.Fatalf("dependencies = %v, want bus=unavailable store=ok", deps)
	}
}

// TestHealthzStaysLiveWhenStoreDown: liveness stays tolerant (200) but
// must report the degraded dependency truthfully in the body.
func TestHealthzStaysLiveWhenStoreDown(t *testing.T) {
	h := newProbeServer(t, &probeStore{Store: state.NewStore(), pingErr: errors.New("down")}, bus.New())
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("healthz must keep 200 liveness semantics, got %d", w.Code)
	}
	var m map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatalf("healthz non-JSON: %s", w.Body.String())
	}
	if m["status"] != "degraded" {
		t.Fatalf("status = %v, want degraded", m["status"])
	}
	if deps := depsOf(t, m); deps["store"] != "unavailable" {
		t.Fatalf("dependencies.store = %v, want unavailable", deps["store"])
	}
}

// TestHealthzHealthyReportsDependencies: the happy path names both
// dependencies and keeps the pre-#71 anonymous contract (no counts).
func TestHealthzHealthyReportsDependencies(t *testing.T) {
	h := newProbeServer(t, state.NewStore(), bus.New())
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("healthz: want 200, got %d", w.Code)
	}
	var m map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatalf("healthz non-JSON: %s", w.Body.String())
	}
	if m["status"] != "ok" {
		t.Fatalf("status = %v, want ok", m["status"])
	}
	if deps := depsOf(t, m); deps["store"] != "ok" || deps["bus"] != "ok" {
		t.Fatalf("dependencies = %v, want store=ok bus=ok", deps)
	}
	if strings.Contains(w.Body.String(), "resources") {
		t.Fatalf("anonymous healthz must not leak resource counts: %s", w.Body.String())
	}
}

// TestHealthzCountFailureDegradesHonest: even when the ping passes, a
// failed resource count must degrade the body instead of lying.
func TestHealthzCountFailureDegradesHonest(t *testing.T) {
	h := newProbeServer(t,
		&probeStore{Store: state.NewStore(), countErr: errors.New("count boom")},
		bus.New())
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("healthz liveness must stay 200, got %d", w.Code)
	}
	var m map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatalf("healthz non-JSON: %s", w.Body.String())
	}
	if m["status"] != "degraded" {
		t.Fatalf("status = %v, want degraded after count failure", m["status"])
	}
	if _, present := m["resources"]; present {
		t.Fatalf("resources must be omitted when the count fails: %v", m)
	}
}

// TestAuditSurfacesStoreErrors: a failed audit query is a 500 error
// envelope, never an empty-but-successful compliance log (issue #71).
func TestAuditSurfacesStoreErrors(t *testing.T) {
	h := newProbeServer(t,
		&probeStore{Store: state.NewStore(), auditErr: errors.New("audit boom")},
		bus.New())
	w := do(t, h, http.MethodGet, "/v1/acme/audit", "")
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("audit with failing store: want 500, got %d: %s", w.Code, w.Body.String())
	}
	m := decode(t, w)
	errObj, ok := m["error"].(map[string]any)
	if !ok {
		t.Fatalf("audit failure must use the error envelope: %s", w.Body.String())
	}
	if errObj["code"] != CodeInternal {
		t.Fatalf("error code = %v, want %s", errObj["code"], CodeInternal)
	}
}

// TestReadyzOpenUnderRBAC: /readyz must be reachable without a token
// in RBAC mode too (the k8s probe has no key).
func TestReadyzOpenUnderRBAC(t *testing.T) {
	h, _ := newRBACServer(t, "ryk_admin_readyz_0001")
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("readyz must be unauthenticated in RBAC mode, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"status":"ready"`) {
		t.Fatalf("unexpected readyz body: %s", w.Body.String())
	}
}
