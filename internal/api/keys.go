package api

import (
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
	"strings"

	"github.com/Roy-Wanyoike/Ryvex/internal/authz"
	"github.com/Roy-Wanyoike/Ryvex/internal/bus"
	"github.com/Roy-Wanyoike/Ryvex/internal/state"
)

// This file is the keys service (issue #16): managed API keys live as
// KindAPIKey resources in the reserved namespace (org=ryvex,
// project=system, env=system) and are minted, listed, updated and
// revoked here. Token plaintext is shown exactly once at creation;
// only the sha256 digest is stored, and the digest is never served.

// tokenHexLen is the entropy of a minted token: "ryk_" + 32 hex chars.
const tokenHexLen = 32

// KeyView is the wire representation of a managed key. The key_hash
// field is deliberately omitted — hashes are redacted on every read.
type KeyView struct {
	ID        string   `json:"id"`
	Principal string   `json:"principal"`
	Roles     []string `json:"roles"`
	Scopes    []string `json:"scopes"`
	Active    bool     `json:"active"`
	CreatedAt string   `json:"created_at,omitempty"`
	UpdatedAt string   `json:"updated_at,omitempty"`
}

type createKeyRequest struct {
	Principal string   `json:"principal"`
	Roles     []string `json:"roles"`
	Scopes    []string `json:"scopes"`
	// Org/Project are sugar: when scopes is empty the scope is derived
	// as org/<org>[/project/<project>]; when org is empty it defaults
	// to the org of scopes[0].
	Org     string `json:"org"`
	Project string `json:"project"`
}

type updateKeyRequest struct {
	Roles  *[]string `json:"roles"`
	Scopes *[]string `json:"scopes"`
	Active *bool     `json:"active"`
}

// KeyService implements the key lifecycle over a state backend.
type KeyService struct {
	store state.Backend
	log   *slog.Logger
}

// NewKeyService builds a keys service.
func NewKeyService(store state.Backend, log *slog.Logger) *KeyService {
	return &KeyService{store: store, log: log}
}

// newToken mints "ryk_" + 32 hex chars from crypto/rand.
func newToken() (string, error) {
	var b [tokenHexLen / 2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return TokenPrefix + hex.EncodeToString(b[:]), nil
}

// Create mints a token, stores the key resource and returns the
// plaintext token (exactly once) plus the stored view.
func (k *KeyService) Create(actor string, req createKeyRequest) (string, KeyView, error) {
	scopes, org := req.Scopes, req.Org
	if len(scopes) == 0 {
		switch {
		case org != "":
			if req.Project != "" {
				scopes = []string{"org/" + org + "/project/" + req.Project}
			} else {
				scopes = []string{"org/" + org}
			}
		case authz.HasRole(req.Roles, state.RoleAdmin):
			scopes = []string{"org/*"} // admin ignores scopes; placeholder for readability
		default:
			return "", KeyView{}, &state.ValidationError{Field: "scopes", Message: "scopes or org is required for operator/viewer keys"}
		}
	} else if org == "" {
		if o, ok := scopeOrg(scopes[0]); ok {
			org = o // documented default: org = scope[0]'s org
		}
	}

	token, err := newToken()
	if err != nil {
		return "", KeyView{}, err
	}
	hash := authz.HashToken(token)

	// Enforce exactly one key resource per hash even though a fresh
	// 128-bit token makes collisions practically impossible.
	if existing, err := k.listResources(); err == nil {
		for _, res := range existing {
			if spec, err := state.ParseAPIKeySpec(res.Spec); err == nil && spec.KeyHash == hash {
				return "", KeyView{}, state.ErrAlreadyExists
			}
		}
	}

	created, err := k.store.CreateResource(
		state.NewAPIKeyResource(req.Principal, req.Roles, scopes, hash),
		state.WriteOptions{Actor: actor, Reason: "keys api: create"},
	)
	if err != nil {
		return "", KeyView{}, err
	}
	view, err := resourceToKeyView(created)
	if err != nil {
		return "", KeyView{}, err
	}
	return token, view, nil
}

// List returns every managed key, hashes redacted.
func (k *KeyService) List() ([]KeyView, error) {
	resources, err := k.listResources()
	if err != nil {
		return nil, err
	}
	out := make([]KeyView, 0, len(resources))
	for _, res := range resources {
		view, err := resourceToKeyView(res)
		if err != nil {
			k.log.Warn("keys: skipping malformed APIKey resource", "id", res.ID, "err", err)
			continue
		}
		out = append(out, view)
	}
	return out, nil
}

// Update applies PATCH-style role/scope/active changes by key ID.
func (k *KeyService) Update(actor, id string, req updateKeyRequest) (KeyView, error) {
	res, err := k.store.GetResource(id)
	if err != nil {
		return KeyView{}, err
	}
	if res.Kind != state.KindAPIKey {
		return KeyView{}, state.ErrNotFound
	}
	updated, err := k.store.UpdateResource(id, func(cur *state.Resource) error {
		if req.Roles != nil {
			cur.Spec["roles"] = anyStrings(*req.Roles)
		}
		if req.Scopes != nil {
			cur.Spec["scopes"] = anyStrings(*req.Scopes)
		}
		if req.Active != nil {
			cur.Spec["active"] = *req.Active
		}
		return nil
	}, state.UpdateOptions{
		WriteOptions: state.WriteOptions{Actor: actor, Reason: "keys api: update"},
	})
	if err != nil {
		return KeyView{}, err
	}
	return resourceToKeyView(updated)
}

// Delete revokes a key by ID. Revocation is immediate: the API layer
// refreshes the authorizer cache after the store delete.
func (k *KeyService) Delete(actor, id string) error {
	res, err := k.store.GetResource(id)
	if err != nil {
		return err
	}
	if res.Kind != state.KindAPIKey {
		return state.ErrNotFound
	}
	return k.store.DeleteResource(id, state.WriteOptions{Actor: actor, Reason: "keys api: delete"})
}

// SeedAdminKey registers a static bootstrap token (e.g. from
// --api-keys) as an admin key resource with scopes ["org/*"]. It is
// idempotent: an already-registered principal is left untouched.
func SeedAdminKey(store state.Backend, principal, token string, log *slog.Logger) error {
	_, err := store.CreateResource(
		state.NewAPIKeyResource(principal, []string{state.RoleAdmin}, []string{"org/*"}, authz.HashToken(token)),
		state.WriteOptions{Actor: "bootstrap", Reason: "static api key bootstrap"},
	)
	switch {
	case err == state.ErrAlreadyExists:
		if log != nil {
			log.Debug("keys: bootstrap admin key already registered", "principal", principal)
		}
		return nil
	case err != nil:
		return err
	}
	if log != nil {
		log.Info("keys: bootstrap admin key registered", "principal", principal)
	}
	return nil
}

// listResources pages through every APIKey resource in the reserved
// namespace.
func (k *KeyService) listResources() ([]*state.Resource, error) {
	var out []*state.Resource
	cursor := ""
	for {
		page, next, err := k.store.ListResources(state.ListOptions{
			Org:    state.ReservedOrg,
			Kind:   state.KindAPIKey,
			Limit:  200,
			Cursor: cursor,
		})
		if err != nil {
			return nil, err
		}
		out = append(out, page...)
		if next == "" || len(page) == 0 {
			break
		}
		cursor = next
	}
	return out, nil
}

func resourceToKeyView(res *state.Resource) (KeyView, error) {
	spec, err := state.ParseAPIKeySpec(res.Spec)
	if err != nil {
		return KeyView{}, err
	}
	return KeyView{
		ID:        res.ID,
		Principal: spec.Principal,
		Roles:     spec.Roles,
		Scopes:    spec.Scopes,
		Active:    spec.Active,
		CreatedAt: res.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
		UpdatedAt: res.UpdatedAt.UTC().Format("2006-01-02T15:04:05Z"),
	}, nil
}

// scopeOrg extracts the org from "org/<org>" or
// "org/<org>/project/<project>".
func scopeOrg(scope string) (string, bool) {
	rest, ok := strings.CutPrefix(scope, "org/")
	if !ok {
		return "", false
	}
	if i := strings.Index(rest, "/project/"); i >= 0 {
		rest = rest[:i]
	}
	if rest == "" || rest == "*" {
		return "", false
	}
	return rest, true
}

// ---- HTTP handlers (admin-only; identity comes from AuthZMiddleware) ----

func (s *Server) requireAdmin(w http.ResponseWriter, r *http.Request) (Identity, bool) {
	ident, ok := IdentityFrom(r.Context())
	if !ok || !ident.Admin {
		s.denyAdmin(w, r, ident)
		return Identity{}, false
	}
	return ident, true
}

func (s *Server) denyAdmin(w http.ResponseWriter, r *http.Request, ident Identity) {
	const reason = "admin role required for key management"
	writeError(w, r, http.StatusForbidden, CodeForbidden, reason)
	if s.authorizer != nil {
		s.authorizer.AuditDenied(ident.Principal, "", "", r.Method, r.URL.Path, reason)
	}
}

func (s *Server) handleKeysCreate(w http.ResponseWriter, r *http.Request) {
	ident, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	var req createKeyRequest
	if err := decodeBody(r, &req); err != nil {
		stateStatus(w, r, err)
		return
	}
	token, view, err := s.keys.Create(ident.Principal, req)
	if err != nil {
		stateStatus(w, r, err)
		return
	}
	s.publishKeyEvent(bus.EventCreated, view, ident.Principal)
	// Make the new key usable immediately (the bus subscription also
	// refreshes; this covers async bus backends).
	_ = s.authorizer.Refresh()
	writeJSON(w, http.StatusCreated, map[string]any{
		"token":     token, // plaintext shown exactly once
		"id":        view.ID,
		"principal": view.Principal,
		"roles":     view.Roles,
		"scopes":    view.Scopes,
		"active":    view.Active,
	})
}

func (s *Server) handleKeysList(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}
	keys, err := s.keys.List()
	if err != nil {
		stateStatus(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"keys": keys, "count": len(keys)})
}

func (s *Server) handleKeysUpdate(w http.ResponseWriter, r *http.Request) {
	ident, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	var req updateKeyRequest
	if err := decodeBody(r, &req); err != nil {
		stateStatus(w, r, err)
		return
	}
	view, err := s.keys.Update(ident.Principal, r.PathValue("id"), req)
	if err != nil {
		stateStatus(w, r, err)
		return
	}
	s.publishKeyEvent(bus.EventUpdated, view, ident.Principal)
	_ = s.authorizer.Refresh()
	writeJSON(w, http.StatusOK, view)
}

func (s *Server) handleKeysDelete(w http.ResponseWriter, r *http.Request) {
	ident, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	if err := s.keys.Delete(ident.Principal, id); err != nil {
		stateStatus(w, r, err)
		return
	}
	_ = s.authorizer.Refresh()
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) publishKeyEvent(eventType string, view KeyView, actor string) {
	s.bus.Publish(bus.Event{
		Type:       eventType,
		Org:        state.ReservedOrg,
		Project:    state.ReservedProject,
		Env:        state.ReservedEnv,
		Kind:       state.KindAPIKey,
		Name:       view.Principal,
		ResourceID: view.ID,
		Actor:      actor,
	})
}

// anyStrings converts a []string to the []any representation used in
// resource specs.
func anyStrings(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}
