// Package statetest is the reusable, backend-agnostic behavioral
// suite for state.Store implementations. The in-memory reference
// store and every durable backend (internal/state/pgstore) run the
// exact same cases, so semantics can never drift between backends.
package statetest

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/Roy-Wanyoike/Ryvex/internal/state"
)

// Store is the minimal surface the suite exercises. *state.Store and
// the Postgres store both satisfy it.
type Store interface {
	CreateResource(r *state.Resource, opts state.WriteOptions) (*state.Resource, error)
	GetResource(id string) (*state.Resource, error)
	GetByLogicalKey(org, project, env, kind, name string) (*state.Resource, error)
	ListResources(o state.ListOptions) ([]*state.Resource, string, error)
	UpdateResource(id string, fn func(*state.Resource) error, o state.UpdateOptions) (*state.Resource, error)
	UpdateStatus(id string, phase, message string, actor state.WriteOptions) error
	DeleteResource(id string, opts state.WriteOptions) error
	Count() (int, error)
	CountByKindPhase() (map[string]map[string]int64, error)
	ListAudit(o state.AuditOptions) ([]state.AuditEntry, error)
	AppendAudit(e state.AuditEntry) (state.AuditEntry, error)
	Ping(ctx context.Context) error
}

// RunSuite runs the full behavioral parity suite against a fresh store
// per case. newStore must return an empty store; callers are
// responsible for teardown (the pgstore harness truncates its tables).
func RunSuite(t *testing.T, newStore func(t *testing.T) Store) {
	t.Run("CreateAndFetch", func(t *testing.T) { testCreateAndFetch(t, newStore(t)) })
	t.Run("CreatePreservesExplicitPhase", func(t *testing.T) { testCreatePreservesExplicitPhase(t, newStore(t)) })
	t.Run("CreateNilLabelsRoundtrip", func(t *testing.T) { testCreateNilLabelsRoundtrip(t, newStore(t)) })
	t.Run("DuplicateCreateFails", func(t *testing.T) { testDuplicateCreateFails(t, newStore(t)) })
	t.Run("ValidationMatrix", func(t *testing.T) { testValidationMatrix(t, newStore(t)) })
	t.Run("FetchMissing", func(t *testing.T) { testFetchMissing(t, newStore(t)) })
	t.Run("UpdateCAS", func(t *testing.T) { testUpdateCAS(t, newStore(t)) })
	t.Run("UpdateNoOpNoAudit", func(t *testing.T) { testUpdateNoOpNoAudit(t, newStore(t)) })
	t.Run("UpdateNoOpPreservesUpdatedAt", func(t *testing.T) { testUpdateNoOpPreservesUpdatedAt(t, newStore(t)) })
	t.Run("UpdateValidationRejected", func(t *testing.T) { testUpdateValidationRejected(t, newStore(t)) })
	t.Run("UpdateMissingID", func(t *testing.T) { testUpdateMissingID(t, newStore(t)) })
	t.Run("StatusOwnedByReconciler", func(t *testing.T) { testStatusOwnedByReconciler(t, newStore(t)) })
	t.Run("UpdateStatusAlwaysAudits", func(t *testing.T) { testUpdateStatusAlwaysAudits(t, newStore(t)) })
	t.Run("UpdateStatusMissingID", func(t *testing.T) { testUpdateStatusMissingID(t, newStore(t)) })
	t.Run("ListFiltersAndPagination", func(t *testing.T) { testListFiltersAndPagination(t, newStore(t)) })
	t.Run("ListOrderStable", func(t *testing.T) { testListOrderStable(t, newStore(t)) })
	t.Run("ListLimitClamp", func(t *testing.T) { testListLimitClamp(t, newStore(t)) })
	t.Run("ListCursorPastEnd", func(t *testing.T) { testListCursorPastEnd(t, newStore(t)) })
	t.Run("ListPaginationBeyondMaxLimit", func(t *testing.T) { testListPaginationBeyondMaxLimit(t, newStore(t)) })
	t.Run("Delete", func(t *testing.T) { testDelete(t, newStore(t)) })
	t.Run("DeleteMissingID", func(t *testing.T) { testDeleteMissingID(t, newStore(t)) })
	t.Run("AuditTrail", func(t *testing.T) { testAuditTrail(t, newStore(t)) })
	t.Run("AuditReasonNotRecorded", func(t *testing.T) { testAuditReasonNotRecorded(t, newStore(t)) })
	t.Run("AppendAudit", func(t *testing.T) { testAppendAudit(t, newStore(t)) })
	t.Run("AuditListEmptyOptions", func(t *testing.T) { testAuditListEmptyOptions(t, newStore(t)) })
	t.Run("AuditCursorPagination", func(t *testing.T) { testAuditCursorPagination(t, newStore(t)) })
	t.Run("Count", func(t *testing.T) { testCount(t, newStore(t)) })
	t.Run("CountByKindPhase", func(t *testing.T) { testCountByKindPhase(t, newStore(t)) })
	t.Run("PingHealthy", func(t *testing.T) { testPingHealthy(t, newStore(t)) })
}

// The must* helpers below fail the test when a backend reports an
// error (issue #71): a healthy backend must never fail these paths,
// so error returns are asserted once here instead of at every call
// site.

// mustListAudit fetches audit entries, failing the test on error.
func mustListAudit(t *testing.T, s Store, o state.AuditOptions) []state.AuditEntry {
	t.Helper()
	entries, err := s.ListAudit(o)
	if err != nil {
		t.Fatalf("ListAudit(%+v): %v", o, err)
	}
	return entries
}

// mustCount returns the resource count, failing the test on error.
func mustCount(t *testing.T, s Store) int {
	t.Helper()
	n, err := s.Count()
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	return n
}

// mustCountByKindPhase returns the kind/phase snapshot, failing the
// test on error.
func mustCountByKindPhase(t *testing.T, s Store) map[string]map[string]int64 {
	t.Helper()
	snap, err := s.CountByKindPhase()
	if err != nil {
		t.Fatalf("CountByKindPhase: %v", err)
	}
	return snap
}

// mustAppendAudit appends a caller-built entry, failing the test on
// error.
func mustAppendAudit(t *testing.T, s Store, e state.AuditEntry) state.AuditEntry {
	t.Helper()
	got, err := s.AppendAudit(e)
	if err != nil {
		t.Fatalf("AppendAudit(%s): %v", e.Action, err)
	}
	return got
}

// testPingHealthy: every backend answers Ping with nil when it can
// serve requests. On the Postgres backend this is a real database
// round trip (issue #71).
func testPingHealthy(t *testing.T, s Store) {
	t.Helper()
	if err := s.Ping(context.Background()); err != nil {
		t.Fatalf("Ping on a healthy backend must succeed, got %v", err)
	}
}

// mkRes builds a valid resource with the standard test label/spec.
func mkRes(kind, org, proj, env, name string) *state.Resource {
	return &state.Resource{
		Kind: kind, Org: org, Project: proj, Env: env, Name: name,
		Labels: map[string]string{"managed-by": "ryvex"},
		Spec:   map[string]any{"replicas": 2},
	}
}

// testCreateAndFetch covers the original TestCreateAndFetch: normalised
// defaults on create, fetch by opaque ID and by logical address.
// Note: spec numbers compare as float64 — every backend round-trips
// spec through JSON, exactly like the reference DeepCopy does.
func testCreateAndFetch(t *testing.T, s Store) {
	got, err := s.CreateResource(mkRes("Application", "acme", "core", "prod", "checkout"), state.WriteOptions{Actor: "test"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if len(got.ID) != 18 || got.ID[:2] != "r-" || got.Generation != 1 || got.Status.Phase != state.PhasePending {
		t.Fatalf("unexpected stored resource: %+v", got)
	}
	if got.Status.ObservedGen != 0 || got.CreatedAt.IsZero() || got.UpdatedAt.IsZero() || got.Status.UpdatedAt.IsZero() {
		t.Fatalf("create must stamp timestamps and zero observed generation: %+v", got)
	}
	if got.Labels["managed-by"] != "ryvex" || got.Spec["replicas"] != any(float64(2)) {
		t.Fatalf("labels/spec not preserved: %+v", got)
	}
	byID, err := s.GetResource(got.ID)
	if err != nil {
		t.Fatalf("get by id: %v", err)
	}
	if byID.Name != "checkout" || byID.Kind != "Application" {
		t.Fatalf("roundtrip mismatch: %+v", byID)
	}
	if !byID.CreatedAt.Equal(got.CreatedAt) || !byID.UpdatedAt.Equal(got.UpdatedAt) || !byID.Status.UpdatedAt.Equal(got.Status.UpdatedAt) {
		t.Fatalf("timestamps must round-trip exactly: %+v vs %+v", byID, got)
	}
	byKey, err := s.GetByLogicalKey("acme", "core", "prod", "Application", "checkout")
	if err != nil || byKey.ID != got.ID {
		t.Fatalf("get by logical key: %v", err)
	}
}

// testCreatePreservesExplicitPhase: a caller-provided non-empty phase
// survives create (only the empty default becomes Pending), while the
// observed generation is always reset.
func testCreatePreservesExplicitPhase(t *testing.T, s Store) {
	t.Helper()
	r := mkRes("Application", "acme", "core", "prod", "prephased")
	r.Status.Phase = state.PhaseReady
	r.Status.ObservedGen = 99 // must not survive
	got, err := s.CreateResource(r, state.WriteOptions{Actor: "test"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if got.Status.Phase != state.PhaseReady {
		t.Fatalf("explicit phase lost, got %q", got.Status.Phase)
	}
	if got.Status.ObservedGen != 0 {
		t.Fatalf("observed generation must reset to 0 on create, got %d", got.Status.ObservedGen)
	}
}

// testCreateNilLabelsRoundtrip: nil labels stay nil (not an empty map)
// across a round-trip.
func testCreateNilLabelsRoundtrip(t *testing.T, s Store) {
	t.Helper()
	r := mkRes("Policy", "acme", "core", "prod", "no-labels")
	r.Labels = nil
	got, err := s.CreateResource(r, state.WriteOptions{Actor: "test"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	back, err := s.GetResource(got.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if back.Labels != nil {
		t.Fatalf("nil labels must stay nil, got %+v", back.Labels)
	}
}

// testDuplicateCreateFails covers the original TestDuplicateCreateFails.
func testDuplicateCreateFails(t *testing.T, s Store) {
	t.Helper()
	if _, err := s.CreateResource(mkRes("Bucket", "acme", "core", "prod", "artifacts"), state.WriteOptions{Actor: "t"}); err != nil {
		t.Fatalf("first create: %v", err)
	}
	_, err := s.CreateResource(mkRes("Bucket", "acme", "core", "prod", "artifacts"), state.WriteOptions{Actor: "t"})
	if !errors.Is(err, state.ErrAlreadyExists) {
		t.Fatalf("want ErrAlreadyExists, got %v", err)
	}
	// the same address with a different kind is a different resource
	if _, err := s.CreateResource(mkRes("Cache", "acme", "core", "prod", "artifacts"), state.WriteOptions{Actor: "t"}); err != nil {
		t.Fatalf("same name different kind: %v", err)
	}
}

// testValidationMatrix covers the original TestValidation cases: the
// store must validate BEFORE any state is touched.
func testValidationMatrix(t *testing.T, s Store) {
	t.Helper()
	cases := []struct {
		name string
		mut  func(*state.Resource)
	}{
		{"bad kind", func(r *state.Resource) { r.Kind = "Widget" }},
		{"uppercase name", func(r *state.Resource) { r.Name = "Checkout" }},
		{"dots in name", func(r *state.Resource) { r.Name = "checkout.1" }},
		{"empty org", func(r *state.Resource) { r.Org = "" }},
		{"bad label key", func(r *state.Resource) { r.Labels = map[string]string{"app.kubernetes.io/name": "x"} }},
		{"nil spec", func(r *state.Resource) { r.Spec = nil }},
	}
	for _, tc := range cases {
		r := mkRes("Application", "acme", "core", "prod", "ok-name")
		tc.mut(r)
		if _, err := s.CreateResource(r, state.WriteOptions{Actor: "t"}); !errors.Is(err, state.ErrValidation) {
			t.Errorf("%s: want ErrValidation, got %v", tc.name, err)
		}
	}
	// validation happens before the duplicate check: an invalid
	// resource at a taken address reports validation, not existence.
	if _, err := s.CreateResource(mkRes("Node", "acme", "core", "prod", "dup"), state.WriteOptions{Actor: "t"}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	bad := mkRes("Node", "acme", "core", "prod", "dup")
	bad.Kind = "Widget"
	if _, err := s.CreateResource(bad, state.WriteOptions{Actor: "t"}); !errors.Is(err, state.ErrValidation) {
		t.Errorf("invalid duplicate: want ErrValidation, got %v", err)
	}
	if n := mustCount(t, s); n != 1 {
		t.Errorf("failed creates must not leave rows behind, count=%d", n)
	}
}

// testFetchMissing: unknown IDs and addresses are ErrNotFound.
func testFetchMissing(t *testing.T, s Store) {
	t.Helper()
	if _, err := s.GetResource("r-0000000000000000"); !errors.Is(err, state.ErrNotFound) {
		t.Fatalf("get missing by id: want ErrNotFound, got %v", err)
	}
	if _, err := s.GetByLogicalKey("acme", "core", "prod", "Application", "ghost"); !errors.Is(err, state.ErrNotFound) {
		t.Fatalf("get missing by key: want ErrNotFound, got %v", err)
	}
}

// testUpdateCAS covers the original TestUpdateCAS: generation bumps on
// real change, stale CAS conflicts, no-op keeps the generation.
func testUpdateCAS(t *testing.T, s Store) {
	r, _ := s.CreateResource(mkRes("Application", "acme", "core", "prod", "web"), state.WriteOptions{Actor: "t"})

	up, err := s.UpdateResource(r.ID, func(cur *state.Resource) error {
		cur.Spec = map[string]any{"replicas": 5}
		return nil
	}, state.UpdateOptions{WriteOptions: state.WriteOptions{Actor: "t"}, ExpectedGeneration: r.Generation})
	if err != nil {
		t.Fatalf("cas update: %v", err)
	}
	if up.Generation != 2 {
		t.Fatalf("want generation 2, got %d", up.Generation)
	}

	// stale generation must conflict
	_, err = s.UpdateResource(r.ID, func(cur *state.Resource) error { return nil },
		state.UpdateOptions{WriteOptions: state.WriteOptions{Actor: "t"}, ExpectedGeneration: 1})
	if !errors.Is(err, state.ErrConflict) {
		t.Fatalf("want ErrConflict, got %v", err)
	}

	// no-op update must not bump generation
	same, err := s.UpdateResource(r.ID, func(cur *state.Resource) error { return nil }, state.UpdateOptions{WriteOptions: state.WriteOptions{Actor: "t"}})
	if err != nil {
		t.Fatalf("no-op: %v", err)
	}
	if same.Generation != 2 {
		t.Fatalf("no-op bumped generation to %d", same.Generation)
	}

	// CAS with the current generation succeeds even for a no-op
	okUp, err := s.UpdateResource(r.ID, func(cur *state.Resource) error { return nil },
		state.UpdateOptions{WriteOptions: state.WriteOptions{Actor: "t"}, ExpectedGeneration: 2})
	if err != nil || okUp.Generation != 2 {
		t.Fatalf("current-generation CAS no-op: gen=%d err=%v", okUp.Generation, err)
	}

	// labels-only change bumps too
	lab, err := s.UpdateResource(r.ID, func(cur *state.Resource) error {
		cur.Labels = map[string]string{"managed-by": "ryvex", "team": "payments"}
		return nil
	}, state.UpdateOptions{WriteOptions: state.WriteOptions{Actor: "t"}})
	if err != nil {
		t.Fatalf("labels update: %v", err)
	}
	if lab.Generation != 3 {
		t.Fatalf("labels change must bump generation, got %d", lab.Generation)
	}
	back, _ := s.GetResource(r.ID)
	if back.Spec["replicas"] != any(float64(5)) || back.Labels["team"] != "payments" {
		t.Fatalf("update not persisted: %+v", back)
	}
}

// testUpdateNoOpNoAudit: a no-op update must not write an "updated"
// audit entry (only real changes are audited).
func testUpdateNoOpNoAudit(t *testing.T, s Store) {
	t.Helper()
	r, _ := s.CreateResource(mkRes("Deployment", "acme", "core", "prod", "api"), state.WriteOptions{Actor: "t"})
	if _, err := s.UpdateResource(r.ID, func(cur *state.Resource) error { return nil }, state.UpdateOptions{WriteOptions: state.WriteOptions{Actor: "bob"}}); err != nil {
		t.Fatalf("no-op update: %v", err)
	}
	for _, e := range mustListAudit(t, s, state.AuditOptions{Org: "acme"}) {
		if e.Action == "updated" {
			t.Fatalf("no-op update produced an audit entry: %+v", e)
		}
	}
}

// testUpdateNoOpPreservesUpdatedAt pins the byte-identical heartbeat
// invariant across backends (memory: issue #108; pgstore: issue #115):
// a no-op update must leave UpdatedAt exactly where the last real
// change left it — in the returned copy and in storage — while a real
// change still stamps a fresh UpdatedAt alongside the generation bump.
func testUpdateNoOpPreservesUpdatedAt(t *testing.T, s Store) {
	t.Helper()
	r, _ := s.CreateResource(mkRes("Application", "acme", "core", "prod", "heartbeat"), state.WriteOptions{Actor: "t"})

	// Guarantee the clock has moved past the previous stamp so a
	// backend that re-stamps on no-op is observable on every
	// precision (pgstore truncates to microseconds).
	time.Sleep(2 * time.Millisecond)

	// Real change: UpdatedAt advances with the generation bump.
	changed, err := s.UpdateResource(r.ID, func(cur *state.Resource) error {
		cur.Spec = map[string]any{"replicas": 3}
		return nil
	}, state.UpdateOptions{WriteOptions: state.WriteOptions{Actor: "t"}})
	if err != nil {
		t.Fatalf("change update: %v", err)
	}
	if !changed.UpdatedAt.After(r.UpdatedAt) {
		t.Fatalf("real change must advance UpdatedAt: create=%v changed=%v", r.UpdatedAt, changed.UpdatedAt)
	}

	time.Sleep(2 * time.Millisecond)

	// No-op heartbeat: UpdatedAt must be preserved, not re-stamped.
	same, err := s.UpdateResource(r.ID, func(cur *state.Resource) error { return nil },
		state.UpdateOptions{WriteOptions: state.WriteOptions{Actor: "t"}})
	if err != nil {
		t.Fatalf("no-op update: %v", err)
	}
	if same.Generation != changed.Generation {
		t.Fatalf("no-op bumped generation: %d -> %d", changed.Generation, same.Generation)
	}
	if !same.UpdatedAt.Equal(changed.UpdatedAt) {
		t.Fatalf("no-op update re-stamped UpdatedAt: %v -> %v", changed.UpdatedAt, same.UpdatedAt)
	}
	back, err := s.GetResource(r.ID)
	if err != nil {
		t.Fatalf("get after no-op: %v", err)
	}
	if !back.UpdatedAt.Equal(changed.UpdatedAt) {
		t.Fatalf("stored UpdatedAt must survive a no-op update: want %v, got %v", changed.UpdatedAt, back.UpdatedAt)
	}
}

// testUpdateValidationRejected: fn output is validated; the generation
// and stored state are untouched on rejection.
func testUpdateValidationRejected(t *testing.T, s Store) {
	t.Helper()
	r, _ := s.CreateResource(mkRes("Application", "acme", "core", "prod", "validme"), state.WriteOptions{Actor: "t"})
	_, err := s.UpdateResource(r.ID, func(cur *state.Resource) error {
		cur.Kind = "Widget"
		return nil
	}, state.UpdateOptions{WriteOptions: state.WriteOptions{Actor: "t"}})
	if !errors.Is(err, state.ErrValidation) {
		t.Fatalf("want ErrValidation from update, got %v", err)
	}
	back, _ := s.GetResource(r.ID)
	if back.Kind != "Application" || back.Generation != 1 {
		t.Fatalf("rejected update must not persist: %+v", back)
	}
}

// testUpdateMissingID.
func testUpdateMissingID(t *testing.T, s Store) {
	t.Helper()
	_, err := s.UpdateResource("r-0000000000000000", func(cur *state.Resource) error { return nil }, state.UpdateOptions{WriteOptions: state.WriteOptions{Actor: "t"}})
	if !errors.Is(err, state.ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

// testStatusOwnedByReconciler covers the original
// TestStatusOwnedByReconciler: status changes stamp the observed
// generation without touching the spec generation.
func testStatusOwnedByReconciler(t *testing.T, s Store) {
	t.Helper()
	r, _ := s.CreateResource(mkRes("Database", "acme", "core", "prod", "orders"), state.WriteOptions{Actor: "t"})
	if err := s.UpdateStatus(r.ID, state.PhaseProvisioning, "bootstrapping", state.WriteOptions{Actor: "reconciler"}); err != nil {
		t.Fatalf("update status: %v", err)
	}
	got, _ := s.GetResource(r.ID)
	if got.Status.Phase != state.PhaseProvisioning || got.Status.Message != "bootstrapping" || got.Status.ObservedGen != got.Generation {
		t.Fatalf("status not stamped: %+v", got.Status)
	}
	if got.Status.UpdatedAt.IsZero() {
		t.Fatalf("status update must stamp status.updated_at")
	}
	if got.Generation != 1 {
		t.Fatalf("status change must not bump spec generation, got %d", got.Generation)
	}
	// the transition is audited with the reconciler identity
	entries := mustListAudit(t, s, state.AuditOptions{Org: "acme"})
	if len(entries) == 0 || entries[0].Action != "status_changed" || entries[0].Actor != "reconciler" {
		t.Fatalf("status change not audited: %+v", entries)
	}
}

// testUpdateStatusAlwaysAudits: re-stamping the same phase/message
// still records a status_changed entry (reference semantics) and
// leaves the generation alone.
func testUpdateStatusAlwaysAudits(t *testing.T, s Store) {
	t.Helper()
	r, _ := s.CreateResource(mkRes("Database", "acme", "core", "prod", "twice"), state.WriteOptions{Actor: "t"})
	_ = s.UpdateStatus(r.ID, state.PhaseReady, "converged", state.WriteOptions{Actor: "reconciler"})
	_ = s.UpdateStatus(r.ID, state.PhaseReady, "converged", state.WriteOptions{Actor: "reconciler"})
	got, _ := s.GetResource(r.ID)
	if got.Generation != 1 {
		t.Fatalf("status updates must not bump generation, got %d", got.Generation)
	}
	if got.Status.ObservedGen != 1 {
		t.Fatalf("observed generation must track spec generation, got %d", got.Status.ObservedGen)
	}
	n := 0
	for _, e := range mustListAudit(t, s, state.AuditOptions{Org: "acme"}) {
		if e.Action == "status_changed" {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("want 2 status_changed entries, got %d", n)
	}
}

// testUpdateStatusMissingID.
func testUpdateStatusMissingID(t *testing.T, s Store) {
	t.Helper()
	if err := s.UpdateStatus("r-0000000000000000", state.PhaseReady, "", state.WriteOptions{Actor: "reconciler"}); !errors.Is(err, state.ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

// testListFiltersAndPagination covers the original
// TestListFiltersAndPagination (5+1 resources, pages of two) plus
// project/env filter checks.
func testListFiltersAndPagination(t *testing.T, s Store) {
	for _, n := range []string{"a", "b", "c", "d", "e"} {
		if _, err := s.CreateResource(mkRes("Node", "acme", "core", "prod", n), state.WriteOptions{Actor: "t"}); err != nil {
			t.Fatalf("seed %s: %v", n, err)
		}
	}
	_, err := s.CreateResource(mkRes("Node", "globex", "core", "prod", "x"), state.WriteOptions{Actor: "t"})
	if err != nil {
		t.Fatalf("seed globex: %v", err)
	}

	items, next, err := s.ListResources(state.ListOptions{Limit: 2})
	if err != nil || len(items) != 2 || next == "" {
		t.Fatalf("page 1: %d items next=%q err %v", len(items), next, err)
	}
	items2, next2, err := s.ListResources(state.ListOptions{Limit: 2, Cursor: next})
	if err != nil || len(items2) != 2 || next2 == "" {
		t.Fatalf("page 2: %d items next=%q err %v", len(items2), next2, err)
	}
	items3, next3, err := s.ListResources(state.ListOptions{Limit: 2, Cursor: next2})
	if err != nil || len(items3) != 2 || next3 != "" {
		t.Fatalf("page 3 should hold the final two items: %d items next=%q err %v", len(items3), next3, err)
	}
	seen := map[string]bool{items[0].ID: true, items2[0].ID: true, items3[0].ID: true}
	if len(seen) != 3 {
		t.Fatalf("pagination returned the same item twice")
	}
	if _, _, err := s.ListResources(state.ListOptions{Cursor: "@@bad@@"}); !errors.Is(err, state.ErrBadRequest) {
		t.Fatalf("bad cursor should be ErrBadRequest, got %v", err)
	}

	// project/env filters (extra seed does not disturb the pagination
	// flow asserted above)
	other := mkRes("Node", "acme", "sandbox", "dev", "a")
	if _, err := s.CreateResource(other, state.WriteOptions{Actor: "t"}); err != nil {
		t.Fatalf("seed sandbox: %v", err)
	}
	items, _, err = s.ListResources(state.ListOptions{Org: "acme", Kind: "Node"})
	if err != nil || len(items) != 6 {
		t.Fatalf("acme nodes: got %d items err %v", len(items), err)
	}
	items, _, err = s.ListResources(state.ListOptions{Org: "acme", Project: "core", Kind: "Node"})
	if err != nil || len(items) != 5 {
		t.Fatalf("acme/core nodes: got %d items err %v", len(items), err)
	}
	items, _, err = s.ListResources(state.ListOptions{Org: "acme", Project: "sandbox", Env: "dev"})
	if err != nil || len(items) != 1 || items[0].Name != "a" {
		t.Fatalf("project+env filter: got %d items err %v", len(items), err)
	}
	items, _, err = s.ListResources(state.ListOptions{Org: "acme", Kind: "Database"})
	if err != nil || len(items) != 0 {
		t.Fatalf("empty filter result: got %d items err %v", len(items), err)
	}
}

// testListOrderStable: list order is (created_at, id) ascending so
// cursor pagination is deterministic.
func testListOrderStable(t *testing.T, s Store) {
	for _, n := range []string{"n1", "n2", "n3", "n4"} {
		if _, err := s.CreateResource(mkRes("Node", "acme", "core", "prod", n), state.WriteOptions{Actor: "t"}); err != nil {
			t.Fatalf("seed %s: %v", n, err)
		}
	}
	items, _, err := s.ListResources(state.ListOptions{Org: "acme"})
	if err != nil || len(items) != 4 {
		t.Fatalf("list: %d items err %v", len(items), err)
	}
	if !sort.SliceIsSorted(items, func(i, j int) bool {
		if !items[i].CreatedAt.Equal(items[j].CreatedAt) {
			return items[i].CreatedAt.Before(items[j].CreatedAt)
		}
		return items[i].ID < items[j].ID
	}) {
		t.Fatalf("list not ordered by (created_at, id)")
	}
}

// testListLimitClamp: limits outside 1..200 fall back to the default
// page size of 50.
func testListLimitClamp(t *testing.T, s Store) {
	t.Helper()
	for i := 0; i < 51; i++ {
		name := string(rune('a'+i/26)) + string(rune('a'+i%26))
		if _, err := s.CreateResource(mkRes("Cache", "acme", "core", "prod", name), state.WriteOptions{Actor: "t"}); err != nil {
			t.Fatalf("seed %d: %v", i, err)
		}
	}
	items, next, err := s.ListResources(state.ListOptions{Limit: 300})
	if err != nil || len(items) != 50 || next == "" {
		t.Fatalf("limit>200 must clamp to 50: got %d items next=%q err %v", len(items), next, err)
	}
	items, next, err = s.ListResources(state.ListOptions{})
	if err != nil || len(items) != 50 || next == "" {
		t.Fatalf("default limit is 50: got %d items next=%q err %v", len(items), next, err)
	}
}

// testListCursorPastEnd: an offset beyond the result set yields an
// empty final page with no next cursor.
func testListCursorPastEnd(t *testing.T, s Store) {
	t.Helper()
	if _, err := s.CreateResource(mkRes("Cache", "acme", "core", "prod", "only"), state.WriteOptions{Actor: "t"}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	items, next, err := s.ListResources(state.ListOptions{Limit: 5, Cursor: state.EncodeCursor(10)})
	if err != nil || len(items) != 0 || next != "" {
		t.Fatalf("cursor past end: %d items next=%q err %v", len(items), next, err)
	}
}

// testListPaginationBeyondMaxLimit: paging across the 200 max page
// size boundary (issue #39) — 205 seeded resources, pages of 200 + 5,
// every seeded ID returned exactly once and no cursor confusion at
// the boundary.
func testListPaginationBeyondMaxLimit(t *testing.T, s Store) {
	t.Helper()
	want := make(map[string]bool, 205)
	for i := 0; i < 205; i++ {
		r, err := s.CreateResource(mkRes("Cache", "acme", "core", "prod", fmt.Sprintf("bulk-%03d", i)), state.WriteOptions{Actor: "t"})
		if err != nil {
			t.Fatalf("seed %d: %v", i, err)
		}
		want[r.ID] = true
	}

	seen := make(map[string]bool, len(want))
	items, next, err := s.ListResources(state.ListOptions{Limit: 200})
	if err != nil || len(items) != 200 || next == "" {
		t.Fatalf("page 1: %d items next=%q err %v", len(items), next, err)
	}
	for _, r := range items {
		seen[r.ID] = true
	}
	items, next, err = s.ListResources(state.ListOptions{Limit: 200, Cursor: next})
	if err != nil || len(items) != 5 || next != "" {
		t.Fatalf("page 2: %d items next=%q err %v", len(items), next, err)
	}
	for _, r := range items {
		seen[r.ID] = true
	}
	if len(seen) != len(want) {
		t.Fatalf("pagination returned %d distinct IDs for %d seeded resources (gaps or duplicates)", len(seen), len(want))
	}
}

// testDelete covers the original TestDelete: deletion removes the
// resource, frees the logical address, and is audited.
func testDelete(t *testing.T, s Store) {
	t.Helper()
	r, _ := s.CreateResource(mkRes("Cache", "acme", "core", "prod", "sessions"), state.WriteOptions{Actor: "t"})
	if err := s.DeleteResource(r.ID, state.WriteOptions{Actor: "t"}); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := s.GetResource(r.ID); !errors.Is(err, state.ErrNotFound) {
		t.Fatalf("want ErrNotFound after delete, got %v", err)
	}
	if _, err := s.GetByLogicalKey("acme", "core", "prod", "Cache", "sessions"); !errors.Is(err, state.ErrNotFound) {
		t.Fatalf("logical key must be freed, got %v", err)
	}
	// address must be reusable
	if _, err := s.CreateResource(mkRes("Cache", "acme", "core", "prod", "sessions"), state.WriteOptions{Actor: "t"}); err != nil {
		t.Fatalf("recreate at same address: %v", err)
	}
	deleted := 0
	for _, e := range mustListAudit(t, s, state.AuditOptions{Org: "acme"}) {
		if e.Action == "deleted" {
			deleted++
			if e.ResourceID != r.ID || e.Kind != "Cache" || e.LogicalKey != "acme/core/prod/Cache/sessions" {
				t.Fatalf("deleted audit entry malformed: %+v", e)
			}
		}
	}
	if deleted != 1 {
		t.Fatalf("want exactly 1 deleted audit entry, got %d", deleted)
	}
}

// testDeleteMissingID.
func testDeleteMissingID(t *testing.T, s Store) {
	t.Helper()
	if err := s.DeleteResource("r-0000000000000000", state.WriteOptions{Actor: "t"}); !errors.Is(err, state.ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

// testAuditTrail covers the original TestAuditTrail: newest-first
// ordering, org prefix filter, kind filter.
func testAuditTrail(t *testing.T, s Store) {
	t.Helper()
	r, _ := s.CreateResource(mkRes("Secret", "acme", "core", "prod", "api-key"), state.WriteOptions{Actor: "alice", Reason: "bootstrap"})
	_, _ = s.UpdateResource(r.ID, func(cur *state.Resource) error { return nil }, state.UpdateOptions{WriteOptions: state.WriteOptions{Actor: "bob"}})
	_ = s.DeleteResource(r.ID, state.WriteOptions{Actor: "carol"})

	entries := mustListAudit(t, s, state.AuditOptions{Org: "acme"})
	if len(entries) < 2 {
		t.Fatalf("expected at least 2 audit entries, got %d", len(entries))
	}
	if entries[0].Actor != "carol" || entries[0].Action != "deleted" {
		t.Fatalf("audit not newest-first: %+v", entries[0])
	}
	if entries[0].LogicalKey != "acme/core/prod/Secret/api-key" {
		t.Fatalf("audit logical key malformed: %+v", entries[0])
	}
	filtered := mustListAudit(t, s, state.AuditOptions{Kind: "Secret", Limit: 10})
	if len(filtered) == 0 {
		t.Fatalf("kind filter dropped everything")
	}
	// org filter is a prefix match on logical key: other orgs excluded
	if _, err := s.CreateResource(mkRes("Cache", "globex", "core", "prod", "g1"), state.WriteOptions{Actor: "t"}); err != nil {
		t.Fatalf("seed globex: %v", err)
	}
	acmeOnly := mustListAudit(t, s, state.AuditOptions{Org: "acme"})
	for _, e := range acmeOnly {
		if len(e.LogicalKey) < 5 || e.LogicalKey[:5] != "acme/" {
			t.Fatalf("org filter leaked foreign entry: %+v", e)
		}
	}
	globex := mustListAudit(t, s, state.AuditOptions{Org: "globex"})
	if len(globex) != 1 || globex[0].Action != "created" {
		t.Fatalf("globex audit: %+v", globex)
	}
}

// testAuditReasonNotRecorded: store-generated entries never carry the
// WriteOptions.Reason (the reference store drops it; webhook-style
// reasons only arrive via AppendAudit).
func testAuditReasonNotRecorded(t *testing.T, s Store) {
	t.Helper()
	if _, err := s.CreateResource(mkRes("Secret", "acme", "core", "prod", "why"), state.WriteOptions{Actor: "alice", Reason: "bootstrap"}); err != nil {
		t.Fatalf("create: %v", err)
	}
	for _, e := range mustListAudit(t, s, state.AuditOptions{Org: "acme"}) {
		if e.Reason != "" {
			t.Fatalf("reason must not leak from WriteOptions: %+v", e)
		}
	}
}

// testAppendAudit: caller-built entries get ID/Time filled in, are
// returned completed and are filterable like any other entry.
func testAppendAudit(t *testing.T, s Store) {
	t.Helper()
	e := mustAppendAudit(t, s, state.AuditEntry{
		Actor:      "webhook-dispatcher",
		Action:     "webhook_delivered",
		Kind:       "Subscription",
		LogicalKey: "acme/core/prod/Subscription/hook",
		Generation: 1,
		Reason:     "ryvex.resource.acme.subscription.created attempt 1/6",
	})
	if e.ID == "" || len(e.ID) < 3 || e.Time.IsZero() {
		t.Fatalf("AppendAudit must fill ID and Time: %+v", e)
	}
	entries := mustListAudit(t, s, state.AuditOptions{Org: "acme"})
	if len(entries) != 1 || entries[0].Action != "webhook_delivered" || entries[0].Reason == "" {
		t.Fatalf("appended entry not listed: %+v", entries)
	}
	if got := mustListAudit(t, s, state.AuditOptions{Org: "other"}); len(got) != 0 {
		t.Fatalf("org prefix filter must exclude other orgs: %+v", got)
	}
	if got := mustListAudit(t, s, state.AuditOptions{Kind: "Subscription"}); len(got) != 1 {
		t.Fatalf("kind filter must include appended entry: %+v", got)
	}
}

// testAuditListEmptyOptions: ListAudit with completely empty options
// (no org, no kind, zero limit) must return the log with default-limit
// semantics and newest-first order. On the Postgres backend this exact
// call used to render `WHERE  ORDER BY` — invalid SQL — and come back
// empty (issue #39).
func testAuditListEmptyOptions(t *testing.T, s Store) {
	t.Helper()
	r1, err := s.CreateResource(mkRes("Application", "acme", "core", "prod", "first"), state.WriteOptions{Actor: "alice"})
	if err != nil {
		t.Fatalf("seed 1: %v", err)
	}
	r2, err := s.CreateResource(mkRes("Node", "globex", "core", "prod", "second"), state.WriteOptions{Actor: "bob"})
	if err != nil {
		t.Fatalf("seed 2: %v", err)
	}

	entries := mustListAudit(t, s, state.AuditOptions{})
	if len(entries) != 2 {
		t.Fatalf("empty options must list every entry (default limit), got %d: %+v", len(entries), entries)
	}
	if entries[0].ResourceID != r2.ID || entries[1].ResourceID != r1.ID {
		t.Fatalf("empty options must stay newest-first: %+v", entries)
	}
	if n := mustListAudit(t, s, state.AuditOptions{Limit: -5}); len(n) != 2 {
		t.Fatalf("non-positive limit must clamp to the default, got %d entries", len(n))
	}
	if n := mustListAudit(t, s, state.AuditOptions{Limit: 1}); len(n) != 1 || n[0].ResourceID != r2.ID {
		t.Fatalf("limit 1 must keep only the newest entry: %+v", n)
	}
}

// testAuditCursorPagination covers the #107 audit feed cursor at the
// store layer: offsets address the filtered newest-first sequence with
// the same shared v2 tokens the resource listing issues, so a cursor
// walk concatenates into exactly the unpaginated listing (continuity,
// no repeats, no gaps), an offset past the end clamps to an empty page
// and a malformed token is ErrBadRequest. Runs for every backend, so
// the Postgres store must accept and apply byte-identical tokens.
func testAuditCursorPagination(t *testing.T, s Store) {
	t.Helper()
	for i := 0; i < 7; i++ {
		if _, err := s.CreateResource(mkRes("Application", "acme", "core", "prod", fmt.Sprintf("cursor-%d", i)), state.WriteOptions{Actor: "t"}); err != nil {
			t.Fatalf("seed acme %d: %v", i, err)
		}
	}
	if _, err := s.CreateResource(mkRes("Application", "globex", "core", "prod", "other"), state.WriteOptions{Actor: "t"}); err != nil {
		t.Fatalf("seed globex: %v", err)
	}

	full := mustListAudit(t, s, state.AuditOptions{Org: "acme"})
	if len(full) != 7 {
		t.Fatalf("unfiltered acme listing = %d entries, want 7", len(full))
	}

	// Walk offset 0,3,6 with page size 3; every page must be the
	// corresponding slice of the full listing (continuity check).
	var walked []state.AuditEntry
	for offset := 0; offset < len(full); offset += 3 {
		page := mustListAudit(t, s, state.AuditOptions{Org: "acme", Limit: 3, Cursor: state.EncodeCursor(uint64(offset))})
		walked = append(walked, page...)
	}
	if len(walked) != len(full) {
		t.Fatalf("cursor walk yielded %d entries, want %d", len(walked), len(full))
	}
	for i := range walked {
		if walked[i].ID != full[i].ID {
			t.Fatalf("walk position %d = %s, want %s (continuity broken)", i, walked[i].ID, full[i].ID)
		}
	}

	// Offsets past the end (and past any #85 eviction window) clamp to
	// an empty page without erroring.
	if got := mustListAudit(t, s, state.AuditOptions{Org: "acme", Limit: 3, Cursor: state.EncodeCursor(99)}); len(got) != 0 {
		t.Fatalf("offset past the end must clamp to an empty page, got %d", len(got))
	}
	if _, err := s.ListAudit(state.AuditOptions{Org: "acme", Cursor: "@@bad@@"}); !errors.Is(err, state.ErrBadRequest) {
		t.Fatalf("malformed audit cursor: want ErrBadRequest, got %v", err)
	}
}

// testCount.
func testCount(t *testing.T, s Store) {
	t.Helper()
	if n := mustCount(t, s); n != 0 {
		t.Fatalf("fresh store must be empty, count=%d", n)
	}
	for _, n := range []string{"a", "b", "c"} {
		if _, err := s.CreateResource(mkRes("Node", "acme", "core", "prod", n), state.WriteOptions{Actor: "t"}); err != nil {
			t.Fatalf("seed %s: %v", n, err)
		}
	}
	if n := mustCount(t, s); n != 3 {
		t.Fatalf("want count 3, got %d", n)
	}
}

// testCountByKindPhase: per-kind/per-phase snapshot for the metrics
// gauge.
func testCountByKindPhase(t *testing.T, s Store) {
	t.Helper()
	a1, _ := s.CreateResource(mkRes("Application", "acme", "core", "prod", "one"), state.WriteOptions{Actor: "t"})
	if _, err := s.CreateResource(mkRes("Application", "acme", "core", "prod", "two"), state.WriteOptions{Actor: "t"}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := s.CreateResource(mkRes("Node", "acme", "core", "prod", "n1"), state.WriteOptions{Actor: "t"}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	_ = s.UpdateStatus(a1.ID, state.PhaseReady, "converged", state.WriteOptions{Actor: "reconciler"})

	snap := mustCountByKindPhase(t, s)
	if snap["Application"]["Ready"] != 1 || snap["Application"]["Pending"] != 1 || snap["Node"]["Pending"] != 1 {
		t.Fatalf("unexpected snapshot: %+v", snap)
	}
}

// ---- audit retention (issue #85) ----

// RunAuditRetentionSuite runs the bounded-audit-retention cases
// (issue #85) against a store whose retention cap is configured SMALL
// by the factory: cap must equal the cap the factory installs (the
// memory backend passes state.WithAuditCap(cap); see the
// internal/state store_test call site).
//
// It is deliberately NOT part of RunSuite, and it runs for the memory
// backend only. Parity note for pgstore: the Postgres backend asserts
// NO cap instead of running these cases — its audit table is the
// durable compliance record (issue #85 acceptance criteria), so
// unbounded growth there is correct behaviour, not a leak; a ring
// eviction case would neither apply nor be honest to run against it.
// Everything retention must not disturb — newest-first ordering,
// filter semantics, limit clamping, AppendAudit completion — is
// already proven for every backend by RunSuite above; the cases below
// additionally prove that retention preserves the offset-cursor
// guarantees (v2 8-byte base64url tokens, see state cursor docs):
// cursors never error and never loop across the eviction boundary,
// and evicted entries are simply absent.
func RunAuditRetentionSuite(t *testing.T, cap int, newStore func(t *testing.T) Store) {
	t.Run("AuditCapRespectedUnderSustainedWrites", func(t *testing.T) { testAuditCapRespected(t, newStore(t), cap) })
	t.Run("AuditNewestFirstAcrossEvictionBoundary", func(t *testing.T) { testAuditNewestFirstAtBoundary(t, newStore(t), cap) })
	t.Run("AuditCursorWalkAcrossEvictionTerminates", func(t *testing.T) { testAuditCursorWalkAcrossEviction(t, newStore(t), cap) })
}

// retentionEntry builds a distinguishable webhook-style audit entry:
// the write ordinal rides in Reason so ordering assertions can name
// exactly which write a listed entry came from.
func retentionEntry(ordinal int) state.AuditEntry {
	return state.AuditEntry{
		Actor:      "webhook-dispatcher",
		Action:     "webhook_delivered",
		Kind:       "Subscription",
		LogicalKey: "acme/core/prod/Subscription/hook",
		Reason:     fmt.Sprintf("attempt %d", ordinal),
	}
}

// testAuditCapRespected: sustained writes at 2× cap must leave
// exactly cap entries retained — the newest ones — with the evicted
// oldest simply absent and no error anywhere.
func testAuditCapRespected(t *testing.T, s Store, cap int) {
	t.Helper()
	for i := 0; i < 2*cap; i++ {
		mustAppendAudit(t, s, retentionEntry(i))
	}
	entries := mustListAudit(t, s, state.AuditOptions{Org: "acme", Limit: 500})
	if len(entries) != cap {
		t.Fatalf("cap %d not respected under sustained writes: %d entries retained", cap, len(entries))
	}
	if entries[0].Reason != fmt.Sprintf("attempt %d", 2*cap-1) {
		t.Fatalf("newest entry lost: %+v", entries[0])
	}
	if entries[cap-1].Reason != fmt.Sprintf("attempt %d", cap) {
		t.Fatalf("oldest retained entry wrong: %+v (writes 0..%d must be evicted)", entries[cap-1], cap-1)
	}
	for _, e := range entries {
		if e.ID == "" || e.Time.IsZero() {
			t.Fatalf("retained entry missing ID/Time: %+v", e)
		}
	}
}

// testAuditNewestFirstAtBoundary: at one-past-the-cap the listing
// stays strictly newest-first and the boundary sits exactly where
// oldest-first eviction puts it (writes cap-1..0 evicted, cap.. kept).
func testAuditNewestFirstAtBoundary(t *testing.T, s Store, cap int) {
	t.Helper()
	for i := 0; i < cap+3; i++ {
		mustAppendAudit(t, s, retentionEntry(i))
	}
	entries := mustListAudit(t, s, state.AuditOptions{Limit: 500})
	if len(entries) != cap {
		t.Fatalf("retained %d entries, want cap %d", len(entries), cap)
	}
	for k, e := range entries {
		want := fmt.Sprintf("attempt %d", cap+2-k) // newest-first: cap+2 .. 3
		if e.Reason != want {
			t.Fatalf("entry %d = %q, want %q (newest-first broken at the eviction boundary)", k, e.Reason, want)
		}
	}
}

// testAuditCursorWalkAcrossEviction: offset cursors built from the
// shared v2 helpers (the tokens the list pagination mints) must never
// error and never loop across the eviction boundary. A stale cursor
// minted before a write burst still decodes; offsets that now land
// past the retained window clamp to an empty page; the walk
// terminates; and the newest entry keeps outranking everything else
// while the ring rolls mid-walk.
func testAuditCursorWalkAcrossEviction(t *testing.T, s Store, cap int) {
	t.Helper()
	// Burst past the cap so the ring is full and evicting.
	for i := 0; i < 2*cap; i++ {
		mustAppendAudit(t, s, retentionEntry(i))
	}
	// A cursor minted before the burst (mid-window offset) must still
	// decode — eviction must not corrupt the token space.
	stale := state.EncodeCursor(1)
	if n, err := state.DecodeCursor(stale); err != nil || n != 1 {
		t.Fatalf("stale cursor across eviction: decoded (%d, %v), want (1, nil)", n, err)
	}

	const pageLimit = 3
	maxSteps := 100 * cap // hard bound: a walk must always terminate
	offset := 0
	steps := 0
	for steps = 0; steps < maxSteps; steps++ {
		decoded, err := state.DecodeCursor(state.EncodeCursor(uint64(offset)))
		if err != nil {
			t.Fatalf("offset %d must encode+decode without error across eviction: %v", offset, err)
		}
		if decoded != uint64(offset) {
			t.Fatalf("cursor roundtrip drifted: %d -> %d", offset, decoded)
		}
		window := mustListAudit(t, s, state.AuditOptions{Limit: 500})
		if offset >= len(window) {
			break // past the retained window: empty page, walk terminates
		}
		end := offset + pageLimit
		if end > len(window) {
			end = len(window)
		}
		page := window[offset:end]
		for _, e := range page {
			if e.LogicalKey != "acme/core/prod/Subscription/hook" {
				t.Fatalf("phantom entry outside the ring at offset %d: %+v", offset, e)
			}
		}
		offset = end
		// Keep the ring rolling between pages: eviction mid-walk must
		// never stall, error or loop the walk.
		mustAppendAudit(t, s, retentionEntry(1000+steps))
	}
	if steps == maxSteps {
		t.Fatalf("cursor walk across the eviction boundary did not terminate within %d steps", maxSteps)
	}
	if offset < cap {
		t.Fatalf("walk stopped at offset %d before covering the cap-sized window", offset)
	}
	// newest-first survives mid-walk appends: the newest entry is the
	// most recent append.
	fresh := mustListAudit(t, s, state.AuditOptions{Limit: 1})
	if len(fresh) != 1 || fresh[0].Reason != fmt.Sprintf("attempt %d", 1000+steps-1) {
		t.Fatalf("newest-first broken after mid-walk appends: %+v", fresh)
	}
	// an offset far beyond anything the window can hold decodes fine
	// and simply pages empty — absent, never an error
	if _, err := state.DecodeCursor(state.EncodeCursor(uint64(10*cap + 42))); err != nil {
		t.Fatalf("far-future offset must decode: %v", err)
	}
}
