// Package authz implements org/project-scoped RBAC for Ryvex API
// keys (issue #16). Managed keys are APIKey resources in the reserved
// state namespace; the Authorizer keeps an in-memory hash→key cache
// refreshed from the store (on key events, periodically, and on
// demand) and answers two questions:
//
//	Authenticate(token) — which principal owns this bearer token?
//	Authorize(principal, org, project, write) — may it act here?
//
// Roles: admin (everywhere), operator (read/write inside its scopes),
// viewer (read-only inside its scopes). Scope "org/<org>" covers all
// projects in the org; "org/<org>/project/<project>" covers exactly
// that project. No matching scope → deny. Inactive keys never
// authenticate.
package authz

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"io"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/Roy-Wanyoike/Ryvex/internal/bus"
	"github.com/Roy-Wanyoike/Ryvex/internal/state"
)

// Decision is the outcome of an authorization check.
type Decision struct {
	Allowed bool
	Reason  string
}

func allow(reason string) Decision { return Decision{Allowed: true, Reason: reason} }
func deny(reason string) Decision  { return Decision{Allowed: false, Reason: reason} }

// KeyInfo is the authorization view of a managed API key.
type KeyInfo struct {
	ID        string
	Principal string
	Roles     []string
	Scopes    []string
	Active    bool
}

// RefreshInterval is the periodic cache reload cadence; key events on
// the bus trigger an immediate refresh, this is the safety net.
const RefreshInterval = 30 * time.Second

// KeyEventPattern matches key-resource events. Key resources live in
// the reserved org "ryvex" (kind apikey), so their subjects look like
// ryvex.resource.ryvex.apikey.created — the tail wildcard catches
// every event type.
const KeyEventPattern = "ryvex.resource.ryvex.>"

// hashEntry pairs a token digest with its key. The slice (not a map)
// is deliberate: Authenticate compares digests in constant time, and
// insertion order makes the match deterministic.
type hashEntry struct {
	hash string // sha256 hex of the bearer token
	info KeyInfo
}

// Authorizer answers authentication and authorization questions for
// managed API keys. It is safe for concurrent use.
type Authorizer struct {
	store state.Backend
	log   *slog.Logger

	mu          sync.RWMutex
	byHash      []hashEntry
	byPrincipal map[string]KeyInfo
}

// Options configures New.
type Options struct {
	// Logger receives refresh/skip diagnostics; nil discards.
	Logger *slog.Logger
}

// New builds an Authorizer over the store and subscribes to key
// resource events on the bus (nil bus skips the subscription). Call
// Refresh once before first use, and Start to enable the periodic
// safety-net refresh.
func New(store state.Backend, b bus.BusI, o Options) *Authorizer {
	if o.Logger == nil {
		o.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	a := &Authorizer{store: store, log: o.Logger, byPrincipal: map[string]KeyInfo{}}
	if b != nil {
		b.Subscribe(KeyEventPattern, func(bus.Event) {
			if err := a.Refresh(); err != nil {
				a.log.Error("authz: key cache refresh failed", "err", err)
			}
		})
	}
	return a
}

// HashToken derives the stored digest of a bearer token: the
// lowercase hex sha256 of the full "ryk_…" string. Tokens are never
// persisted; only this digest is.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// Refresh reloads every APIKey resource from the store and rebuilds
// the hash and principal caches. Malformed key resources are skipped
// with a warning (they can never authenticate). Safe to call at any
// time from any goroutine.
func (a *Authorizer) Refresh() error {
	var hashes []hashEntry
	principals := map[string]KeyInfo{}
	cursor := ""
	for {
		page, next, err := a.store.ListResources(state.ListOptions{
			Org:    state.ReservedOrg,
			Kind:   state.KindAPIKey,
			Limit:  200,
			Cursor: cursor,
		})
		if err != nil {
			return err
		}
		for _, res := range page {
			spec, err := state.ParseAPIKeySpec(res.Spec)
			if err != nil {
				a.log.Warn("authz: skipping malformed APIKey resource", "id", res.ID, "err", err)
				continue
			}
			info := KeyInfo{
				ID:        res.ID,
				Principal: spec.Principal,
				Roles:     spec.Roles,
				Scopes:    spec.Scopes,
				Active:    spec.Active,
			}
			hashes = append(hashes, hashEntry{hash: spec.KeyHash, info: info})
			if _, dup := principals[spec.Principal]; !dup {
				principals[spec.Principal] = info
			}
		}
		if next == "" || len(page) == 0 {
			break
		}
		cursor = next
	}
	a.mu.Lock()
	a.byHash = hashes
	a.byPrincipal = principals
	a.mu.Unlock()
	a.log.Debug("authz: key cache refreshed", "keys", len(hashes))
	return nil
}

// Authenticate resolves a bearer token to its principal. Disabled
// keys never authenticate. The digest comparison is constant-time.
func (a *Authorizer) Authenticate(token string) (string, bool) {
	if token == "" {
		return "", false
	}
	digest := HashToken(token)
	a.mu.RLock()
	defer a.mu.RUnlock()
	for _, e := range a.byHash {
		if subtle.ConstantTimeCompare([]byte(e.hash), []byte(digest)) == 1 {
			if !e.info.Active {
				return "", false
			}
			return e.info.Principal, true
		}
	}
	return "", false
}

// Lookup returns the cached key information for a principal.
func (a *Authorizer) Lookup(principal string) (KeyInfo, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	info, ok := a.byPrincipal[principal]
	return info, ok
}

// Authorize decides whether the principal may act on org/project.
// project may be empty for org-wide requests. admin → allow
// everywhere; viewer → read-only inside its scopes; operator →
// read/write inside its scopes; no matching scope → deny.
func (a *Authorizer) Authorize(principal, org, project string, write bool) Decision {
	a.mu.RLock()
	info, ok := a.byPrincipal[principal]
	a.mu.RUnlock()
	if !ok {
		return deny("unknown principal")
	}
	if !info.Active {
		return deny("key is disabled")
	}
	if hasRole(info.Roles, state.RoleAdmin) {
		return allow("admin role")
	}
	if write && hasRole(info.Roles, state.RoleViewer) {
		return deny("viewer role is read-only")
	}
	for _, scope := range info.Scopes {
		if ScopeMatches(scope, org, project) {
			if write {
				return allow("write granted by scope " + scope)
			}
			return allow("read granted by scope " + scope)
		}
	}
	return deny("no scope covers " + scopeTarget(org, project))
}

// AppendAudit records a caller-built audit entry (used by the API
// layer for authz_denied outcomes) in the underlying store.
func (a *Authorizer) AppendAudit(e state.AuditEntry) state.AuditEntry {
	return a.store.AppendAudit(e)
}

// AuditDenied records an authz_denied entry attributed to the
// principal for a rejected request, filterable under the target org.
func (a *Authorizer) AuditDenied(actor, org, project, method, path, reason string) {
	lk := ""
	if org != "" {
		lk = org + "/" + project
	}
	a.AppendAudit(state.AuditEntry{
		Actor:      actor,
		Action:     "authz_denied",
		LogicalKey: lk,
		Reason:     method + " " + path + ": " + reason,
	})
}

// Start launches the periodic refresh loop; it exits when ctx is
// cancelled.
func (a *Authorizer) Start(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(RefreshInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := a.Refresh(); err != nil {
					a.log.Error("authz: periodic key cache refresh failed", "err", err)
				}
			}
		}
	}()
}

// ScopeMatches reports whether scope covers the org/project target.
// "org/<org>" covers every project in the org (project may be empty
// for org-wide requests); "org/<org>/project/<project>" covers only
// that exact project. The "org/*" wildcard never matches a real org —
// admin keys bypass scope checks entirely.
func ScopeMatches(scope, org, project string) bool {
	rest, ok := strings.CutPrefix(scope, "org/")
	if !ok {
		return false
	}
	if o, p, found := strings.Cut(rest, "/project/"); found {
		return o == org && project != "" && p == project
	}
	return rest == org
}

// HasRole reports whether roles contains role.
func HasRole(roles []string, role string) bool {
	for _, r := range roles {
		if r == role {
			return true
		}
	}
	return false
}

func hasRole(roles []string, role string) bool { return HasRole(roles, role) }

func scopeTarget(org, project string) string {
	if project == "" {
		return "org/" + org
	}
	return "org/" + org + "/project/" + project
}
