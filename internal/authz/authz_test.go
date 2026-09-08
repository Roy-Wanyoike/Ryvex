package authz

import (
	"context"
	"testing"

	"github.com/Roy-Wanyoike/Ryvex/internal/bus"
	"github.com/Roy-Wanyoike/Ryvex/internal/state"
)

func keyRes(principal string, roles, scopes []string, active bool) *state.Resource {
	return &state.Resource{
		Kind: state.KindAPIKey, Org: state.ReservedOrg, Project: "system", Env: "system", Name: principal,
		Spec: map[string]any{
			"principal": principal,
			"roles":     toAny(roles...),
			"scopes":    toAny(scopes...),
			"key_hash":  HashToken("ryk_" + principal),
			"active":    active,
		},
	}
}

func toAny(ss ...string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}

func newAuthz(t *testing.T, res ...*state.Resource) (*Authorizer, *state.Store) {
	t.Helper()
	store := state.NewStore()
	for _, r := range res {
		if _, err := store.CreateResource(r, state.WriteOptions{Actor: "test"}); err != nil {
			t.Fatalf("seed key %s: %v", r.Name, err)
		}
	}
	az := New(store, bus.New(), Options{})
	if err := az.Refresh(); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	return az, store
}

func TestScopeMatches(t *testing.T) {
	cases := []struct {
		scope, org, project string
		want                bool
	}{
		{"org/acme", "acme", "", true},
		{"org/acme", "acme", "core", true},
		{"org/acme", "globex", "core", false},
		{"org/acme/project/core", "acme", "core", true},
		{"org/acme/project/core", "acme", "billing", false},
		{"org/acme/project/core", "acme", "", false}, // project-scoped needs a project
		{"org/*", "acme", "core", false},             // wildcard never matches a real org
		{"acme", "acme", "", false},                  // missing org/ prefix
		{"", "acme", "", false},
	}
	for _, tc := range cases {
		if got := ScopeMatches(tc.scope, tc.org, tc.project); got != tc.want {
			t.Errorf("ScopeMatches(%q,%q,%q)=%v want %v", tc.scope, tc.org, tc.project, got, tc.want)
		}
	}
}

func TestAuthenticateAndRoleMatrix(t *testing.T) {
	az, _ := newAuthz(t,
		keyRes("root", []string{state.RoleAdmin}, []string{"org/*"}, true),
		keyRes("acme-ops", []string{state.RoleOperator}, []string{"org/acme"}, true),
		keyRes("acme-view", []string{state.RoleViewer}, []string{"org/acme/project/core"}, true),
		keyRes("disabled", []string{state.RoleAdmin}, []string{"org/*"}, false),
	)

	// unknown token never authenticates
	if _, ok := az.Authenticate("ryk_nobody"); ok {
		t.Fatalf("unknown token authenticated")
	}
	// disabled keys never authenticate even with a valid digest
	if _, ok := az.Authenticate("ryk_disabled"); ok {
		t.Fatalf("disabled key authenticated")
	}

	// Authorize answers by PRINCIPAL (Authenticate maps token -> principal).
	admin := "root"
	ops := "acme-ops"
	view := "acme-view"

	cases := []struct {
		name         string
		principal    string
		org, project string
		write        bool
		want         bool
	}{
		{"admin write anywhere", admin, "globex", "x", true, true},
		{"admin read anywhere", admin, "acme", "core", false, true},
		{"operator write in org", ops, "acme", "core", true, true},
		{"operator write other org", ops, "globex", "x", true, false},
		{"operator read in org", ops, "acme", "", false, true},
		{"operator read other org", ops, "globex", "", false, false},
		{"viewer read in project", view, "acme", "core", false, true},
		{"viewer write in project", view, "acme", "core", true, false},
		{"viewer read other project", view, "acme", "billing", false, false},
	}
	for _, tc := range cases {
		if got := az.Authorize(tc.principal, tc.org, tc.project, tc.write).Allowed; got != tc.want {
			t.Errorf("%s: allowed=%v want %v", tc.name, got, tc.want)
		}
	}
	if d := az.Authorize("nobody", "acme", "", false); d.Allowed {
		t.Fatalf("unknown principal allowed")
	}
}

func TestRefreshPicksUpNewKeys(t *testing.T) {
	az, store := newAuthz(t)
	if _, ok := az.Authenticate("ryk_late"); ok {
		t.Fatalf("key authenticated before creation")
	}
	r := keyRes("late", []string{state.RoleAdmin}, nil, true)
	if _, err := store.CreateResource(r, state.WriteOptions{Actor: "test"}); err != nil {
		t.Fatalf("create: %v", err)
	}
	// bus-less authorizer needs a manual refresh
	if err := az.Refresh(); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	p, ok := az.Authenticate("ryk_late")
	if !ok || p != "late" {
		t.Fatalf("refresh did not pick up new key: p=%q ok=%v", p, ok)
	}
}

func TestRefreshOnKeyEvent(t *testing.T) {
	store := state.NewStore()
	b := bus.New()
	az := New(store, b, Options{})
	if err := az.Refresh(); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	r := keyRes("live", []string{state.RoleAdmin}, nil, true)
	if _, err := store.CreateResource(r, state.WriteOptions{Actor: "test"}); err != nil {
		t.Fatalf("create: %v", err)
	}
	b.Publish(bus.Event{Org: state.ReservedOrg, Kind: state.KindAPIKey, Type: bus.EventCreated, Name: "live"})
	// event-triggered refresh is synchronous in the handler
	if p, ok := az.Authenticate("ryk_live"); !ok || p != "live" {
		t.Fatalf("event refresh failed: p=%q ok=%v", p, ok)
	}
}

func TestPeriodicRefreshStops(t *testing.T) {
	az, _ := newAuthz(t)
	ctx, cancel := context.WithCancel(context.Background())
	az.Start(ctx)
	cancel() // must not leak or panic
}

func TestAuditDenied(t *testing.T) {
	az, store := newAuthz(t)
	az.AuditDenied("ops", "acme", "core", "POST", "/v1/resources", "no scope covers org/acme/project/core")
	entries := store.ListAudit(state.AuditOptions{Limit: 10})
	if len(entries) != 1 {
		t.Fatalf("want 1 audit entry, got %d", len(entries))
	}
	e := entries[0]
	if e.Action != "authz_denied" || e.Actor != "ops" || e.LogicalKey != "acme/core" {
		t.Fatalf("unexpected audit entry: %+v", e)
	}
}
