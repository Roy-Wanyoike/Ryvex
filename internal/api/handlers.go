package api

import (
	"net/http"
	"strings"
	"time"

	"github.com/Roy-Wanyoike/Ryvex/internal/bus"
	"github.com/Roy-Wanyoike/Ryvex/internal/state"
)

func timeNow() time.Time { return time.Now() }

// ---- resources ----

func (s *Server) handleCreate(w http.ResponseWriter, r *http.Request) {
	var in state.Resource
	if err := decodeBody(r, &in); err != nil {
		stateStatus(w, r, err)
		return
	}
	in.ID = "" // server-owned
	created, err := s.store.CreateResource(&in, state.WriteOptions{Actor: ActorFrom(r.Context())})
	if err != nil {
		stateStatus(w, r, err)
		return
	}
	s.bus.Publish(bus.Event{
		Type: bus.EventCreated,
		Org:  created.Org, Project: created.Project, Env: created.Env,
		Kind: created.Kind, Name: created.Name, ResourceID: created.ID,
		Generation: created.Generation, Phase: created.Status.Phase,
		Actor: ActorFrom(r.Context()),
	})
	writeJSON(w, http.StatusCreated, created)
}

func (s *Server) handleList(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	page, next, err := s.store.ListResources(state.ListOptions{
		Org:     q.Get("org"),
		Project: q.Get("project"),
		Env:     q.Get("env"),
		Kind:    matchKind(q.Get("kind")),
		Limit:   queryInt(r, "limit", 50),
		Cursor:  q.Get("cursor"),
	})
	if err != nil {
		stateStatus(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items":       page,
		"next_cursor": next,
	})
}

func (s *Server) handleGetByID(w http.ResponseWriter, r *http.Request) {
	res, err := s.store.GetResource(r.PathValue("id"))
	if err != nil {
		stateStatus(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleDeleteByID(w http.ResponseWriter, r *http.Request) {
	res, err := s.store.GetResource(r.PathValue("id"))
	if err != nil {
		stateStatus(w, r, err)
		return
	}
	if err := s.store.DeleteResource(res.ID, state.WriteOptions{Actor: ActorFrom(r.Context()), Reason: "api delete"}); err != nil {
		stateStatus(w, r, err)
		return
	}
	s.bus.Publish(bus.Event{
		Type: bus.EventDeleted,
		Org:  res.Org, Project: res.Project, Env: res.Env,
		Kind: res.Kind, Name: res.Name, ResourceID: res.ID,
		Generation: res.Generation, Actor: ActorFrom(r.Context()),
	})
	w.WriteHeader(http.StatusNoContent)
}

// ---- scope-addressed resources (/v1/{org}/{project}/{env}/{kind}[/{name}]) ----

func (s *Server) handleScopeList(w http.ResponseWriter, r *http.Request, seg []string) {
	res, _, err := s.store.ListResources(state.ListOptions{
		Org: seg[0], Project: seg[1], Env: seg[2], Kind: matchKind(seg[3]),
		Limit: queryInt(r, "limit", 50), Cursor: r.URL.Query().Get("cursor"),
	})
	if err != nil {
		stateStatus(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": res, "next_cursor": ""})
}

func (s *Server) handleScopeGet(w http.ResponseWriter, r *http.Request) {
	res, err := s.store.GetByLogicalKey(
		r.PathValue("org"), r.PathValue("project"), r.PathValue("env"),
		matchKind(r.PathValue("kind")), r.PathValue("name"))
	if err != nil {
		stateStatus(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleScopePut(w http.ResponseWriter, r *http.Request) {
	org := r.PathValue("org")
	kind := matchKind(r.PathValue("kind"))
	name := r.PathValue("name")

	var in state.Resource
	if err := decodeBody(r, &in); err != nil {
		stateStatus(w, r, err)
		return
	}

	existing, err := s.store.GetByLogicalKey(org, r.PathValue("project"), r.PathValue("env"), kind, name)
	switch {
	case err == state.ErrNotFound:
		// Upsert semantics: PUT to a fresh address creates the resource.
		in.Org, in.Project, in.Env, in.Kind, in.Name = org, r.PathValue("project"), r.PathValue("env"), kind, name
		in.ID = ""
		created, cerr := s.store.CreateResource(&in, state.WriteOptions{Actor: ActorFrom(r.Context()), Reason: "api put"})
		if cerr != nil {
			stateStatus(w, r, cerr)
			return
		}
		s.bus.Publish(bus.Event{
			Type: bus.EventCreated,
			Org:  created.Org, Project: created.Project, Env: created.Env,
			Kind: created.Kind, Name: created.Name, ResourceID: created.ID,
			Generation: created.Generation, Phase: created.Status.Phase,
			Actor: ActorFrom(r.Context()),
		})
		writeJSON(w, http.StatusCreated, created)
		return
	case err != nil:
		stateStatus(w, r, err)
		return
	}

	updated, err := s.store.UpdateResource(existing.ID, func(cur *state.Resource) error {
		cur.Spec = in.Spec
		if in.Labels != nil {
			cur.Labels = in.Labels
		}
		return nil
	}, state.UpdateOptions{
		WriteOptions:       state.WriteOptions{Actor: ActorFrom(r.Context()), Reason: "api put"},
		ExpectedGeneration: in.Generation, // optional CAS: client echoes generation it read
	})
	if err != nil {
		stateStatus(w, r, err)
		return
	}
	s.bus.Publish(bus.Event{
		Type: bus.EventUpdated,
		Org:  updated.Org, Project: updated.Project, Env: updated.Env,
		Kind: updated.Kind, Name: updated.Name, ResourceID: updated.ID,
		Generation: updated.Generation, Phase: updated.Status.Phase,
		Actor: ActorFrom(r.Context()),
	})
	writeJSON(w, http.StatusOK, updated)
}

func (s *Server) handleScopeDelete(w http.ResponseWriter, r *http.Request) {
	res, err := s.store.GetByLogicalKey(
		r.PathValue("org"), r.PathValue("project"), r.PathValue("env"),
		matchKind(r.PathValue("kind")), r.PathValue("name"))
	if err != nil {
		stateStatus(w, r, err)
		return
	}
	if err := s.store.DeleteResource(res.ID, state.WriteOptions{Actor: ActorFrom(r.Context()), Reason: "api delete"}); err != nil {
		stateStatus(w, r, err)
		return
	}
	s.bus.Publish(bus.Event{
		Type: bus.EventDeleted,
		Org:  res.Org, Project: res.Project, Env: res.Env,
		Kind: res.Kind, Name: res.Name, ResourceID: res.ID,
		Generation: res.Generation, Actor: ActorFrom(r.Context()),
	})
	w.WriteHeader(http.StatusNoContent)
}

// matchKind resolves case-insensitively; simple plurals
// ("databases") and irregulars ("policies") are accepted for
// ergonomics. Unknown strings pass through untouched and fail later
// validation.
func matchKind(raw string) string {
	lower := strings.ToLower(raw)
	for k := range state.Kinds {
		if strings.EqualFold(k, lower) {
			return k
		}
	}
	if v, ok := map[string]string{"policies": state.KindPolicy}[lower]; ok {
		return v
	}
	if trimmed := strings.TrimSuffix(lower, "s"); trimmed != lower {
		for k := range state.Kinds {
			if strings.EqualFold(k, trimmed) {
				return k
			}
		}
	}
	return raw
}

// ---- observability ----

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request, org string) {
	evts := s.bus.Recent(org, queryInt(r, "limit", 100))
	if evts == nil {
		evts = []bus.Event{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": evts, "count": len(evts)})
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request, org string) {
	entries := s.store.ListAudit(state.AuditOptions{
		Org:   org,
		Kind:  matchKind(r.URL.Query().Get("kind")),
		Limit: queryInt(r, "limit", 100),
	})
	if entries == nil {
		entries = []state.AuditEntry{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": entries, "count": len(entries)})
}

func (s *Server) handleReconcile(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	res, err := s.store.GetResource(id)
	if err != nil {
		stateStatus(w, r, err)
		return
	}
	if r.PathValue("org") != res.Org {
		writeError(w, r, http.StatusNotFound, CodeNotFound, "resource not found in this org")
		return
	}
	s.reconciler.Trigger(id)
	writeJSON(w, http.StatusAccepted, map[string]any{
		"status": "accepted", "resource_id": id, "reason": "manual reconcile trigger",
	})
}
