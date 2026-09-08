package state

import (
	"errors"
	"testing"
)

func mkRes(kind, org, proj, env, name string) *Resource {
	return &Resource{
		Kind: kind, Org: org, Project: proj, Env: env, Name: name,
		Labels: map[string]string{"managed-by": "ryvex"},
		Spec:   map[string]any{"replicas": 2},
	}
}

func TestCreateAndFetch(t *testing.T) {
	s := NewStore()
	got, err := s.CreateResource(mkRes("Application", "acme", "core", "prod", "checkout"), WriteOptions{Actor: "test"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if got.ID == "" || got.Generation != 1 || got.Status.Phase != PhasePending {
		t.Fatalf("unexpected stored resource: %+v", got)
	}
	byID, err := s.GetResource(got.ID)
	if err != nil {
		t.Fatalf("get by id: %v", err)
	}
	if byID.Name != "checkout" {
		t.Fatalf("roundtrip mismatch: %+v", byID)
	}
	byKey, err := s.GetByLogicalKey("acme", "core", "prod", "Application", "checkout")
	if err != nil || byKey.ID != got.ID {
		t.Fatalf("get by logical key: %v", err)
	}
}

func TestDuplicateCreateFails(t *testing.T) {
	s := NewStore()
	if _, err := s.CreateResource(mkRes("Bucket", "acme", "core", "prod", "artifacts"), WriteOptions{Actor: "t"}); err != nil {
		t.Fatalf("first create: %v", err)
	}
	_, err := s.CreateResource(mkRes("Bucket", "acme", "core", "prod", "artifacts"), WriteOptions{Actor: "t"})
	if !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("want ErrAlreadyExists, got %v", err)
	}
}

func TestValidation(t *testing.T) {
	s := NewStore()
	cases := []struct {
		name string
		mut  func(*Resource)
	}{
		{"bad kind", func(r *Resource) { r.Kind = "Widget" }},
		{"uppercase name", func(r *Resource) { r.Name = "Checkout" }},
		{"dots in name", func(r *Resource) { r.Name = "checkout.1" }},
		{"empty org", func(r *Resource) { r.Org = "" }},
		{"bad label key", func(r *Resource) { r.Labels = map[string]string{"app.kubernetes.io/name": "x"} }},
		{"nil spec", func(r *Resource) { r.Spec = nil }},
	}
	for _, tc := range cases {
		r := mkRes("Application", "acme", "core", "prod", "ok-name")
		tc.mut(r)
		if _, err := s.CreateResource(r, WriteOptions{Actor: "t"}); !errors.Is(err, ErrValidation) {
			t.Errorf("%s: want ErrValidation, got %v", tc.name, err)
		}
	}
}

func TestUpdateCAS(t *testing.T) {
	s := NewStore()
	r, _ := s.CreateResource(mkRes("Application", "acme", "core", "prod", "web"), WriteOptions{Actor: "t"})

	up, err := s.UpdateResource(r.ID, func(cur *Resource) error {
		cur.Spec = map[string]any{"replicas": 5}
		return nil
	}, UpdateOptions{WriteOptions: WriteOptions{Actor: "t"}, ExpectedGeneration: r.Generation})
	if err != nil {
		t.Fatalf("cas update: %v", err)
	}
	if up.Generation != 2 {
		t.Fatalf("want generation 2, got %d", up.Generation)
	}

	// stale generation must conflict
	_, err = s.UpdateResource(r.ID, func(cur *Resource) error { return nil },
		UpdateOptions{WriteOptions: WriteOptions{Actor: "t"}, ExpectedGeneration: 1})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("want ErrConflict, got %v", err)
	}

	// no-op update must not bump generation
	same, err := s.UpdateResource(r.ID, func(cur *Resource) error { return nil }, UpdateOptions{WriteOptions: WriteOptions{Actor: "t"}})
	if err != nil {
		t.Fatalf("no-op: %v", err)
	}
	if same.Generation != 2 {
		t.Fatalf("no-op bumped generation to %d", same.Generation)
	}
}

func TestStatusOwnedByReconciler(t *testing.T) {
	s := NewStore()
	r, _ := s.CreateResource(mkRes("Database", "acme", "core", "prod", "orders"), WriteOptions{Actor: "t"})
	if err := s.UpdateStatus(r.ID, PhaseProvisioning, "bootstrapping", WriteOptions{Actor: "reconciler"}); err != nil {
		t.Fatalf("update status: %v", err)
	}
	got, _ := s.GetResource(r.ID)
	if got.Status.Phase != PhaseProvisioning || got.Status.ObservedGen != got.Generation {
		t.Fatalf("status not stamped: %+v", got.Status)
	}
	if got.Generation != 1 {
		t.Fatalf("status change must not bump spec generation, got %d", got.Generation)
	}
}

func TestListFiltersAndPagination(t *testing.T) {
	s := NewStore()
	for _, n := range []string{"a", "b", "c", "d", "e"} {
		if _, err := s.CreateResource(mkRes("Node", "acme", "core", "prod", n), WriteOptions{Actor: "t"}); err != nil {
			t.Fatalf("seed %s: %v", n, err)
		}
	}
	_, err := s.CreateResource(mkRes("Node", "globex", "core", "prod", "x"), WriteOptions{Actor: "t"})
	if err != nil {
		t.Fatalf("seed globex: %v", err)
	}

	items, _, err := s.ListResources(ListOptions{Org: "acme", Kind: "Node"})
	if err != nil || len(items) != 5 {
		t.Fatalf("acme nodes: got %d items err %v", len(items), err)
	}
	items, next, err := s.ListResources(ListOptions{Limit: 2})
	if err != nil || len(items) != 2 || next == "" {
		t.Fatalf("page 1: %d items next=%q err %v", len(items), next, err)
	}
	items2, next2, err := s.ListResources(ListOptions{Limit: 2, Cursor: next})
	if err != nil || len(items2) != 2 || next2 == "" {
		t.Fatalf("page 2: %d items next=%q err %v", len(items2), next2, err)
	}
	items3, next3, err := s.ListResources(ListOptions{Limit: 2, Cursor: next2})
	if err != nil || len(items3) != 2 || next3 != "" {
		t.Fatalf("page 3 should hold the final two items: %d items next=%q err %v", len(items3), next3, err)
	}
	if items[0].ID == items2[0].ID || items2[0].ID == items3[0].ID {
		t.Fatalf("pagination returned the same item twice")
	}
	if _, _, err := s.ListResources(ListOptions{Cursor: "@@bad@@"}); !errors.Is(err, ErrBadRequest) {
		t.Fatalf("bad cursor should be ErrBadRequest, got %v", err)
	}
}

func TestDelete(t *testing.T) {
	s := NewStore()
	r, _ := s.CreateResource(mkRes("Cache", "acme", "core", "prod", "sessions"), WriteOptions{Actor: "t"})
	if err := s.DeleteResource(r.ID, WriteOptions{Actor: "t"}); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := s.GetResource(r.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound after delete, got %v", err)
	}
	// address must be reusable
	if _, err := s.CreateResource(mkRes("Cache", "acme", "core", "prod", "sessions"), WriteOptions{Actor: "t"}); err != nil {
		t.Fatalf("recreate at same address: %v", err)
	}
}

func TestAuditTrail(t *testing.T) {
	s := NewStore()
	r, _ := s.CreateResource(mkRes("Secret", "acme", "core", "prod", "api-key"), WriteOptions{Actor: "alice", Reason: "bootstrap"})
	_, _ = s.UpdateResource(r.ID, func(cur *Resource) error { return nil }, UpdateOptions{WriteOptions: WriteOptions{Actor: "bob"}})
	_ = s.DeleteResource(r.ID, WriteOptions{Actor: "carol"})

	entries := s.ListAudit(AuditOptions{Org: "acme"})
	if len(entries) < 2 {
		t.Fatalf("expected at least 2 audit entries, got %d", len(entries))
	}
	if entries[0].Actor != "carol" || entries[0].Action != "deleted" {
		t.Fatalf("audit not newest-first: %+v", entries[0])
	}
	filtered := s.ListAudit(AuditOptions{Kind: "Secret", Limit: 10})
	if len(filtered) == 0 {
		t.Fatalf("kind filter dropped everything")
	}
}
