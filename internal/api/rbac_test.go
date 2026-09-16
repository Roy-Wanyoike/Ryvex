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
	entries, err := store.ListAudit(state.AuditOptions{Org: "globex", Limit: 10})
	if err != nil {
		t.Fatalf("ListAudit: %v", err)
	}
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

// ---- issue #73: bootstrap keys are governed by the /v1/keys lifecycle ----

// bootstrapKeyID lists the keys and returns the resource ID backing a
// principal (bootstrap keys included: they are APIKey resources).
func bootstrapKeyID(t *testing.T, h http.Handler, adminToken, principal string) string {
	t.Helper()
	w := doAuth(t, h, http.MethodGet, "/v1/keys", adminToken, "")
	if w.Code != http.StatusOK {
		t.Fatalf("list keys: want 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Keys []struct {
			ID        string `json:"id"`
			Principal string `json:"principal"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("list keys decode: %v", err)
	}
	for _, k := range resp.Keys {
		if k.Principal == principal {
			return k.ID
		}
	}
	t.Fatalf("no APIKey resource for principal %q", principal)
	return ""
}

func TestBootstrapKeyDeleteRevokesImmediately(t *testing.T) {
	admin := "ryk_admin_boot_0001"
	h, _ := newRBACServer(t, admin)
	// Control: a managed (non-bootstrap) key must be unaffected by
	// bootstrap revocation.
	ops, opsID := mintKey(t, h, admin, "acme-ops", "operator", "acme", "")

	bootID := bootstrapKeyID(t, h, admin, "root")
	if bootID == "" || bootID == opsID {
		t.Fatalf("bootstrap key lookup failed: id=%q ops=%q", bootID, opsID)
	}
	// Sanity: the bootstrap token authenticates (managed path) before
	// revocation, on /v1 and on the /healthz probe tier.
	if w := doAuth(t, h, http.MethodGet, "/v1/resources?org=acme", admin, ""); w.Code != http.StatusOK {
		t.Fatalf("bootstrap token before revoke: want 200, got %d", w.Code)
	}
	if w := doAuth(t, h, http.MethodGet, "/healthz", admin, ""); !strings.Contains(w.Body.String(), "authenticated_as") {
		t.Fatalf("bootstrap token must classify on /healthz before revoke: %s", w.Body.String())
	}

	if w := doAuth(t, h, http.MethodDelete, "/v1/keys/"+bootID, admin, ""); w.Code != http.StatusNoContent {
		t.Fatalf("delete bootstrap key: want 204, got %d: %s", w.Code, w.Body.String())
	}

	// The regression in #73: the static digest index used to keep the
	// --api-keys token admin forever. The resource is gone, so the next
	// request must be a 401 — no restart, no residual static path.
	if w := doAuth(t, h, http.MethodGet, "/v1/resources?org=acme", admin, ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("revoked bootstrap token: want 401, got %d: %s", w.Code, w.Body.String())
	}
	// /healthz classifies the revoked token as anonymous again.
	if w := doAuth(t, h, http.MethodGet, "/healthz", admin, ""); strings.Contains(w.Body.String(), "authenticated_as") {
		t.Fatalf("revoked bootstrap token must probe as anonymous: %s", w.Body.String())
	}
	// Non-bootstrap keys keep working.
	if w := doAuth(t, h, http.MethodGet, "/v1/resources?org=acme", ops, ""); w.Code != http.StatusOK {
		t.Fatalf("managed key after bootstrap revoke: want 200, got %d", w.Code)
	}
}

func TestBootstrapKeyDemoteEnforced(t *testing.T) {
	admin := "ryk_admin_boot_0002"
	h, _ := newRBACServer(t, admin)
	bootID := bootstrapKeyID(t, h, admin, "root")

	// Demote admin → operator scoped to org/acme. The scopes must move
	// off "org/*" in the same update: the wildcard is admin-only syntax
	// and the store rejects the demotion otherwise.
	body := `{"roles":["operator"],"scopes":["org/acme"]}`
	if w := doAuth(t, h, http.MethodPut, "/v1/keys/"+bootID, admin, body); w.Code != http.StatusOK {
		t.Fatalf("demote bootstrap key: want 200, got %d: %s", w.Code, w.Body.String())
	}

	// Enforcement follows the demoted role without a restart: the token
	// still authenticates, but only with operator powers inside acme.
	if w := doAuth(t, h, http.MethodGet, "/v1/resources?org=acme", admin, ""); w.Code != http.StatusOK {
		t.Fatalf("demoted read inside scope: want 200, got %d", w.Code)
	}
	if w := doAuth(t, h, http.MethodPost, "/v1/resources", admin, appBodyAcme); w.Code != http.StatusCreated {
		t.Fatalf("demoted write inside scope: want 201, got %d: %s", w.Code, w.Body.String())
	}
	if w := doAuth(t, h, http.MethodPost, "/v1/resources", admin, appBodyGlobex); w.Code != http.StatusForbidden {
		t.Fatalf("demoted write outside scope: want 403, got %d", w.Code)
	}
	// Admin terrain (key management) is gone.
	if w := doAuth(t, h, http.MethodGet, "/v1/keys", admin, ""); w.Code != http.StatusForbidden {
		t.Fatalf("demoted key management: want 403, got %d", w.Code)
	}
}

func TestBootstrapKeyDisableRevokes(t *testing.T) {
	admin := "ryk_admin_boot_0003"
	h, _ := newRBACServer(t, admin)
	bootID := bootstrapKeyID(t, h, admin, "root")
	if w := doAuth(t, h, http.MethodPut, "/v1/keys/"+bootID, admin, `{"active":false}`); w.Code != http.StatusOK {
		t.Fatalf("disable bootstrap key: want 200, got %d: %s", w.Code, w.Body.String())
	}
	if w := doAuth(t, h, http.MethodGet, "/v1/resources?org=acme", admin, ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("disabled bootstrap token: want 401, got %d", w.Code)
	}
}

func TestBootstrapKeyRotationWithoutRestart(t *testing.T) {
	admin := "ryk_admin_boot_0004"
	h, _ := newRBACServer(t, admin)
	// Rotate through the lifecycle: mint a replacement admin key, then
	// revoke the bootstrap key. Both steps are plain /v1/keys calls.
	replacement, _ := mintKey(t, h, admin, "root-v2", "admin", "acme", "")
	bootID := bootstrapKeyID(t, h, admin, "root")
	if w := doAuth(t, h, http.MethodDelete, "/v1/keys/"+bootID, admin, ""); w.Code != http.StatusNoContent {
		t.Fatalf("delete bootstrap key: want 204, got %d", w.Code)
	}
	// The rotated-out token is dead; the rotated-in one is admin. No
	// restart, no flag change, no residual static grant.
	if w := doAuth(t, h, http.MethodGet, "/v1/keys", admin, ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("rotated-out bootstrap token: want 401, got %d", w.Code)
	}
	if w := doAuth(t, h, http.MethodGet, "/v1/keys", replacement, ""); w.Code != http.StatusOK {
		t.Fatalf("rotated-in admin token: want 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestSeedAdminKeyCollisionSemantics(t *testing.T) {
	store := state.NewStore()
	tok1 := "ryk_boot_root_0001"
	tok2 := "ryk_boot_root_0002"
	if err := SeedAdminKey(store, "root", tok1, discardLogger()); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// Idempotent restart with the same token: untouched, still valid.
	if err := SeedAdminKey(store, "root", tok1, discardLogger()); err != nil {
		t.Fatalf("re-seed same token: %v", err)
	}
	// Principal collision with a different token: no-op — the resource
	// view stays authoritative, so the new token never authenticates
	// (issue #73 removed the static path that used to grant it admin).
	if err := SeedAdminKey(store, "root", tok2, discardLogger()); err != nil {
		t.Fatalf("colliding seed: %v", err)
	}
	az := authz.New(store, bus.New(), authz.Options{Logger: discardLogger()})
	if err := az.Refresh(); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if p, ok := az.Authenticate(tok1); !ok || p != "root" {
		t.Fatalf("original bootstrap token must keep authenticating: p=%q ok=%v", p, ok)
	}
	if _, ok := az.Authenticate(tok2); ok {
		t.Fatalf("colliding bootstrap token must not authenticate")
	}
}
