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

	"github.com/Roy-Wanyoike/Ryvex/internal/authz"
	"github.com/Roy-Wanyoike/Ryvex/internal/bus"
	"github.com/Roy-Wanyoike/Ryvex/internal/reconcile"
	"github.com/Roy-Wanyoike/Ryvex/internal/state"
)

func timeHour() time.Duration   { return time.Hour }
func timeSecond() time.Duration { return 2 * time.Second }
func contextWithCancel() (context.Context, context.CancelFunc) {
	return context.WithCancel(context.Background())
}

// newRBACServer boots a server with RBAC enabled: one static admin
// key (seeded as an admin key resource, as ryvexd does at boot).
func newRBACServer(t *testing.T, adminToken string) (http.Handler, *state.Store) {
	t.Helper()
	store := state.NewStore()
	eventBus := bus.New()
	rec := reconcile.New(store, eventBus, reconcile.Options{Interval: timeHour(), Logger: discardLogger()})
	ctx, cancel := contextWithCancel()
	rec.Start(ctx)
	t.Cleanup(func() {
		cancel()
		rec.Stop(2 * timeSecond())
	})

	az := authz.New(store, eventBus, authz.Options{Logger: discardLogger()})
	if err := SeedAdminKey(store, "root", adminToken, discardLogger()); err != nil {
		t.Fatalf("seed admin: %v", err)
	}
	if err := az.Refresh(); err != nil {
		t.Fatalf("authz refresh: %v", err)
	}

	h := NewServer(store, eventBus, rec, ServerOptions{
		Auth:       AuthOptions{APIKeys: map[string]string{adminToken: "root"}},
		Logger:     discardLogger(),
		Authorizer: az,
	})
	return h, store
}

func doAuth(t *testing.T, h http.Handler, method, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	var rdr *bytes.Reader
	if body == "" {
		rdr = bytes.NewReader(nil)
	} else {
		rdr = bytes.NewReader([]byte(body))
	}
	req := httptest.NewRequest(method, path, rdr)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func mintKey(t *testing.T, h http.Handler, adminToken, principal, role, org, project string) (token, keyID string) {
	t.Helper()
	body := fmt.Sprintf(`{"principal":%q,"roles":[%q],"org":%q,"project":%q}`, principal, role, org, project)
	w := doAuth(t, h, http.MethodPost, "/v1/keys", adminToken, body)
	if w.Code != http.StatusCreated {
		t.Fatalf("mint %s: want 201, got %d: %s", principal, w.Code, w.Body.String())
	}
	var resp struct {
		Token string `json:"token"`
		ID    string `json:"id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("mint response: %v", err)
	}
	if !strings.HasPrefix(resp.Token, TokenPrefix) || resp.ID == "" {
		t.Fatalf("minted response malformed: token=%q id=%q", resp.Token, resp.ID)
	}
	return resp.Token, resp.ID
}

const appBodyAcme = `{"kind":"Application","org":"acme","project":"core","env":"prod","name":"rbac-demo","spec":{"image":"demo:1"}}`
const appBodyGlobex = `{"kind":"Application","org":"globex","project":"core","env":"prod","name":"rbac-demo","spec":{"image":"demo:1"}}`

func TestRBACOperatorScopedToOrg(t *testing.T) {
	admin := "ryk_admin_root_0001"
	h, store := newRBACServer(t, admin)
	ops, _ := mintKey(t, h, admin, "acme-ops", "operator", "acme", "")

	// read inside scope: allowed (org-wide, empty project)
	if w := doAuth(t, h, http.MethodGet, "/v1/resources?org=acme", ops, ""); w.Code != http.StatusOK {
		t.Fatalf("operator read inside scope: want 200, got %d", w.Code)
	}
	// write inside scope: allowed
	if w := doAuth(t, h, http.MethodPost, "/v1/resources", ops, appBodyAcme); w.Code != http.StatusCreated {
		t.Fatalf("operator write inside scope: want 201, got %d: %s", w.Code, w.Body.String())
	}
	// read outside scope: denied
	if w := doAuth(t, h, http.MethodGet, "/v1/globex/events", ops, ""); w.Code != http.StatusForbidden {
		t.Fatalf("operator read outside scope: want 403, got %d", w.Code)
	}
	// write outside scope: denied
	w := doAuth(t, h, http.MethodPost, "/v1/resources", ops, appBodyGlobex)
	if w.Code != http.StatusForbidden {
		t.Fatalf("operator write outside scope: want 403, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), CodeForbidden) {
		t.Fatalf("403 must use the frozen envelope code: %s", w.Body.String())
	}
	// denial must be audited
	entries := store.ListAudit(state.AuditOptions{Org: "globex", Limit: 10})
	if len(entries) == 0 {
		t.Fatalf("authz_denied entries missing")
	}
	if entries[0].Action != "authz_denied" {
		t.Fatalf("unexpected audit action: %+v", entries[0])
	}
}

func TestRBACViewerReadOnly(t *testing.T) {
	admin := "ryk_admin_root_0002"
	h, _ := newRBACServer(t, admin)
	view, _ := mintKey(t, h, admin, "acme-view", "viewer", "acme", "core")

	if w := doAuth(t, h, http.MethodGet, "/v1/acme/core/prod/applications", view, ""); w.Code != http.StatusOK {
		t.Fatalf("viewer read inside scope: want 200, got %d", w.Code)
	}
	if w := doAuth(t, h, http.MethodPost, "/v1/resources", view, appBodyAcme); w.Code != http.StatusForbidden {
		t.Fatalf("viewer write: want 403, got %d", w.Code)
	}
	if w := doAuth(t, h, http.MethodDelete, "/v1/acme/core/prod/applications/checkout", view, ""); w.Code != http.StatusForbidden {
		t.Fatalf("viewer delete: want 403, got %d", w.Code)
	}
}

func TestRBACKeyManagementIsAdminOnly(t *testing.T) {
	admin := "ryk_admin_root_0003"
	h, _ := newRBACServer(t, admin)
	ops, opsID := mintKey(t, h, admin, "acme-ops", "operator", "acme", "")

	// operator cannot mint keys
	if w := doAuth(t, h, http.MethodPost, "/v1/keys", ops, `{"principal":"x","roles":["admin"],"org":"acme"}`); w.Code != http.StatusForbidden {
		t.Fatalf("operator minting keys: want 403, got %d", w.Code)
	}
	// operator cannot list keys
	if w := doAuth(t, h, http.MethodGet, "/v1/keys", ops, ""); w.Code != http.StatusForbidden {
		t.Fatalf("operator listing keys: want 403, got %d", w.Code)
	}
	// admin can list; hashes are redacted (no key_hash in payload)
	w := doAuth(t, h, http.MethodGet, "/v1/keys", admin, "")
	if w.Code != http.StatusOK {
		t.Fatalf("admin list keys: want 200, got %d", w.Code)
	}
	if strings.Contains(w.Body.String(), "key_hash") {
		t.Fatalf("key hashes must never be served: %s", w.Body.String())
	}
	// admin can revoke the operator key
	if w := doAuth(t, h, http.MethodDelete, "/v1/keys/"+opsID, admin, ""); w.Code != http.StatusNoContent && w.Code != http.StatusOK {
		t.Fatalf("admin revoke: want 2xx, got %d: %s", w.Code, w.Body.String())
	}
	// revoked token is dead immediately
	if w := doAuth(t, h, http.MethodGet, "/v1/resources?org=acme", ops, ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("revoked token: want 401, got %d", w.Code)
	}
}

func TestRBACDisableKeyImmediately(t *testing.T) {
	admin := "ryk_admin_root_0004"
	h, _ := newRBACServer(t, admin)
	ops, opsID := mintKey(t, h, admin, "acme-ops", "operator", "acme", "")

	if w := doAuth(t, h, http.MethodPut, "/v1/keys/"+opsID, admin, `{"active":false}`); w.Code != http.StatusOK {
		t.Fatalf("disable key: want 200, got %d: %s", w.Code, w.Body.String())
	}
	if w := doAuth(t, h, http.MethodGet, "/v1/resources?org=acme", ops, ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("disabled key must not authenticate: want 401, got %d", w.Code)
	}
}

func TestRBACDevAuthUnchanged(t *testing.T) {
	store := state.NewStore()
	eventBus := bus.New()
	rec := reconcile.New(store, eventBus, reconcile.Options{Interval: timeHour(), Logger: discardLogger()})
	ctx, cancel := contextWithCancel()
	rec.Start(ctx)
	t.Cleanup(func() { cancel(); rec.Stop(2 * timeSecond()) })

	az := authz.New(store, eventBus, authz.Options{Logger: discardLogger()})
	h := NewServer(store, eventBus, rec, ServerOptions{
		Auth:       AuthOptions{DevAuth: true},
		Logger:     discardLogger(),
		Authorizer: az,
	})

	// any well-formed ryk_ token keeps full access in dev mode
	if w := doAuth(t, h, http.MethodPost, "/v1/resources", "ryk_anything_goes", appBodyAcme); w.Code != http.StatusCreated {
		t.Fatalf("dev-auth write: want 201, got %d: %s", w.Code, w.Body.String())
	}
	// garbage tokens still rejected
	if w := doAuth(t, h, http.MethodGet, "/v1/resources", "not-a-ryk-token", ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("garbage token: want 401, got %d", w.Code)
	}
}

func TestRBACCrossOrgBodyScope(t *testing.T) {
	admin := "ryk_admin_root_0005"
	h, _ := newRBACServer(t, admin)
	// project-scoped operator: only org=acme project=core
	tok, _ := mintKey(t, h, admin, "core-ops", "operator", "acme", "core")

	// write inside the exact project: allowed
	if w := doAuth(t, h, http.MethodPost, "/v1/resources", tok, appBodyAcme); w.Code != http.StatusCreated {
		t.Fatalf("project-scoped write inside: want 201, got %d: %s", w.Code, w.Body.String())
	}
	// same org, different project: denied (body-derived scope)
	other := strings.Replace(appBodyAcme, `"project":"core"`, `"project":"billing"`, 1)
	if w := doAuth(t, h, http.MethodPost, "/v1/resources", tok, other); w.Code != http.StatusForbidden {
		t.Fatalf("project-scoped write outside: want 403, got %d", w.Code)
	}
	// scope-path write outside project: denied
	if w := doAuth(t, h, http.MethodPut, "/v1/acme/billing/prod/applications/x", tok, appBodyAcme); w.Code != http.StatusForbidden {
		t.Fatalf("scope-path write outside project: want 403, got %d", w.Code)
	}
}
