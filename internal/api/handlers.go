package api

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Roy-Wanyoike/Ryvex/internal/bus"
	"github.com/Roy-Wanyoike/Ryvex/internal/state"

	"go.opentelemetry.io/otel/attribute"
)

func timeNow() time.Time { return time.Now() }

// maxFeedPage caps the page size of the events and audit feeds (issue
// #107). 500 matches the audit listing's historical ceiling; the
// console asks 100. Both limits stay well inside the fetch budgets
// below, so the limit+1 "more exists" probes are always honored
// verbatim by every backend and next_cursor is exact at any page size.
const maxFeedPage = 500

// ---- resources ----

func (s *Server) handleCreate(w http.ResponseWriter, r *http.Request) {
	var in state.Resource
	if err := decodeBody(r, &in); err != nil {
		bodyStatus(w, r, err)
		return
	}
	in.ID = "" // server-owned
	// Issue #83: store writes are spanned at the handler call site so
	// the span nests under this request's server span.
	ctx, span := s.startStoreSpan(r.Context(), "store.create",
		attribute.String("ryvex.resource.kind", in.Kind),
		attribute.String("ryvex.resource.org", in.Org),
		attribute.String("ryvex.resource.project", in.Project),
		attribute.String("ryvex.resource.name", in.Name),
	)
	created, err := s.store.CreateResource(&in, state.WriteOptions{Actor: ActorFrom(ctx)})
	endStoreSpan(span, err)
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
	ctx, span := s.startStoreSpan(r.Context(), "store.delete",
		attribute.String("ryvex.resource.id", res.ID),
		attribute.String("ryvex.resource.kind", res.Kind),
	)
	err = s.store.DeleteResource(res.ID, state.WriteOptions{Actor: ActorFrom(ctx), Reason: "api delete"})
	endStoreSpan(span, err)
	if err != nil {
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

// handleScopeList serves GET /v1/{org}/{project}/{env}/{kind}. The
// store's pagination cursor is propagated to next_cursor (issue #38):
// clients page through large scopes with the same ?cursor= contract as
// the filtered /v1/resources listing.
func (s *Server) handleScopeList(w http.ResponseWriter, r *http.Request, seg []string) {
	res, next, err := s.store.ListResources(state.ListOptions{
		Org: seg[0], Project: seg[1], Env: seg[2], Kind: matchKind(seg[3]),
		Limit: queryInt(r, "limit", 50), Cursor: r.URL.Query().Get("cursor"),
	})
	if err != nil {
		stateStatus(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": res, "next_cursor": next})
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
		bodyStatus(w, r, err)
		return
	}

	existing, err := s.store.GetByLogicalKey(org, r.PathValue("project"), r.PathValue("env"), kind, name)
	switch {
	case err == state.ErrNotFound:
		// Upsert semantics: PUT to a fresh address creates the resource.
		in.Org, in.Project, in.Env, in.Kind, in.Name = org, r.PathValue("project"), r.PathValue("env"), kind, name
		in.ID = ""
		// Issue #83: store-create child span (nests under the server span).
		ctx, span := s.startStoreSpan(r.Context(), "store.create",
			attribute.String("ryvex.resource.kind", in.Kind),
			attribute.String("ryvex.resource.org", in.Org),
			attribute.String("ryvex.resource.project", in.Project),
			attribute.String("ryvex.resource.name", in.Name),
		)
		created, cerr := s.store.CreateResource(&in, state.WriteOptions{Actor: ActorFrom(ctx), Reason: "api put"})
		endStoreSpan(span, cerr)
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

	// Issue #72: the node agent re-sends byte-identical PUTs between
	// spec refreshes specifically to avoid event churn, so publication
	// of EventUpdated is gated on an actual transition. The mutation
	// callback snapshots the store's authoritative pre-image — taken
	// here, under the store's write lock, NOT from the earlier GET,
	// which a concurrent writer could invalidate — and compares it to
	// the post-mutation state with the store's own canonical predicate
	// (state.SpecLabelsEqual), i.e. exactly the check that decides the
	// generation bump and the audit entry below. The published and
	// stored change decisions therefore cannot drift. CAS, generation
	// and audit semantics are unchanged: a no-op heartbeat still
	// answers 200 with the same generation and writes no audit entry —
	// it just no longer floods the events feed, the webhook dispatcher
	// and ryvex_bus_events_published_total.
	var changed bool
	// Issue #83: store-update child span. The closure runs under the
	// store's write lock; the span only brackets the call.
	ctx, span := s.startStoreSpan(r.Context(), "store.update",
		attribute.String("ryvex.resource.id", existing.ID),
		attribute.String("ryvex.resource.kind", existing.Kind),
		attribute.Int64("ryvex.resource.generation", in.Generation),
	)
	updated, err := s.store.UpdateResource(existing.ID, func(cur *state.Resource) error {
		prev := cur.DeepCopy()
		cur.Spec = in.Spec
		if in.Labels != nil {
			cur.Labels = in.Labels
		}
		changed = !state.SpecLabelsEqual(prev, cur)
		return nil
	}, state.UpdateOptions{
		WriteOptions:       state.WriteOptions{Actor: ActorFrom(ctx), Reason: "api put"},
		ExpectedGeneration: in.Generation, // optional CAS: client echoes generation it read
	})
	endStoreSpan(span, err)
	if err != nil {
		stateStatus(w, r, err)
		return
	}
	if changed {
		s.bus.Publish(bus.Event{
			Type: bus.EventUpdated,
			Org:  updated.Org, Project: updated.Project, Env: updated.Env,
			Kind: updated.Kind, Name: updated.Name, ResourceID: updated.ID,
			Generation: updated.Generation, Phase: updated.Status.Phase,
			Actor: ActorFrom(r.Context()),
		})
	}
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
	ctx, span := s.startStoreSpan(r.Context(), "store.delete",
		attribute.String("ryvex.resource.id", res.ID),
		attribute.String("ryvex.resource.kind", res.Kind),
	)
	err = s.store.DeleteResource(res.ID, state.WriteOptions{Actor: ActorFrom(ctx), Reason: "api delete"})
	endStoreSpan(span, err)
	if err != nil {
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

// handleEvents serves GET /v1/{org}/events. Issue #107: the feed is
// cursor-paginated with the exact wire contract of the resources
// listing — ?cursor= in, "next_cursor" out in the same envelope
// position — so the console's Load-more (issue #86) can reach events
// beyond the first page instead of the feed silently truncating.
//
// Cursor design: sequence-based. Every bus backend stamps a monotonic
// publish sequence into the event ID ("evt-<n>", see eventSeq), and a
// cursor is that sequence encoded with the shared v2 cursor token
// format (state.EncodeCursor): "everything strictly older than the
// oldest event already delivered". Pages advance newest→oldest, the
// minted sequence strictly decreases per page, so a walk terminates
// and can never loop; a stale cursor (ring rolled past it) filters to
// an empty page with next_cursor="" — the same never-error, never-loop
// contract as the #85 audit eviction; a malformed token is a 400
// bad_request, same as the resources listing.
//
// Backend parity: on the in-memory ring a cursor page fetches the
// whole reachable history (bus.RingSize caps the ring), so pagination
// is exact. The JetStream backend (#15) replays through a bounded
// ScanCap message scan, so its walk reaches the newest scan window and
// clamps to an empty page beyond it — identical to a stale cursor,
// never an error. The durable-replay ?from= face is unchanged (frozen
// wire shape, no next_cursor); from and cursor are mutually exclusive.
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request, org string) {
	limit := queryInt(r, "limit", 100)
	if limit <= 0 || limit > maxFeedPage {
		limit = 100
	}
	cursor := r.URL.Query().Get("cursor")

	// --- durable events (issue #15): optional `from` sequence replay ---
	// When the bus supports sequence replay (the JetStream backend
	// implements bus.Replayer) and the caller passes from=<stream
	// sequence>, return events after that sequence together with
	// last_seq so callers can resume the stream. Additive: the
	// in-memory bus does not implement bus.Replayer, so from is
	// ignored and the frozen wire shape is unchanged there.
	if r.URL.Query().Has("from") {
		if cursor != "" {
			writeError(w, r, http.StatusBadRequest, CodeBadRequest,
				"from and cursor are mutually exclusive query parameters")
			return
		}
		if replay, ok := s.bus.(bus.Replayer); ok {
			from, err := strconv.ParseUint(r.URL.Query().Get("from"), 10, 64)
			if err != nil {
				writeError(w, r, http.StatusBadRequest, CodeValidation,
					"invalid from: must be an unsigned integer (event stream sequence)")
				return
			}
			evts, last, err := replay.RecentFrom(org, limit, from)
			if err != nil {
				s.log.Error("event replay failed", "org", org, "err", err)
				writeError(w, r, http.StatusInternalServerError, CodeInternal, "event replay failed")
				return
			}
			if evts == nil {
				evts = []bus.Event{}
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"events": evts, "count": len(evts), "last_seq": last,
			})
			return
		}
	}
	// --- end durable events ---

	before := uint64(0)
	if cursor != "" {
		n, err := state.DecodeCursor(cursor)
		if err != nil {
			// Same mapping as the resources listing: a malformed
			// pagination token is a 400 bad_request, never a 500.
			writeError(w, r, http.StatusBadRequest, CodeBadRequest,
				"invalid cursor: must be an events feed pagination token")
			return
		}
		before = n // 0 decodes to "before nothing" = plain newest-first page
	}

	evts, next, err := s.eventPage(org, limit, before)
	if err != nil {
		s.log.Error("event query failed", "org", org, "err", err)
		writeError(w, r, http.StatusInternalServerError, CodeInternal, "event query failed")
		return
	}
	if evts == nil {
		evts = []bus.Event{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"events": evts, "count": len(evts), "next_cursor": next,
	})
}

// eventPage returns one newest-first page of at most limit events and
// the next_cursor token ("" when exhausted). before > 0 restricts the
// page to events strictly older than that publish sequence (issue
// #107). "More exists" is detected exactly, never guessed: without a
// cursor the bus is asked for limit+1 events; with a cursor the page
// filters a complete reachable-history snapshot — the memory ring
// retains at most bus.RingSize events and Recent(org, bus.RingSize)
// returns every one of them, so the filter's outcome is authoritative.
// Bounded-scan backends (JetStream, issue #15) reach their newest scan
// window and clamp to an empty page beyond it, like a stale cursor.
func (s *Server) eventPage(org string, limit int, before uint64) ([]bus.Event, string, error) {
	fetch := limit + 1 // probe: one extra event proves more exist
	if before > 0 {
		fetch = bus.RingSize // complete snapshot of reachable history
	}
	all, err := s.bus.Recent(org, fetch)
	if err != nil {
		return nil, "", err
	}
	if before > 0 {
		older := make([]bus.Event, 0, len(all))
		for _, e := range all {
			if seq, ok := eventSeq(e); ok && seq < before {
				older = append(older, e)
			}
		}
		all = older
	}
	next := ""
	if len(all) > limit {
		all = all[:limit]
		// The cursor is the oldest delivered event's sequence: the
		// next page resumes strictly below it, so sequences decrease
		// monotonically across pages — the walk cannot loop.
		if seq, ok := eventSeq(all[limit-1]); ok {
			next = state.EncodeCursor(seq)
		}
	}
	return all, next, nil
}

// eventSeq extracts the monotonic publish sequence the bus stamps into
// every event ID ("evt-<n>"). The memory ring mints it in Publish and
// the JetStream bus mints it on publish and fills it on replay, so the
// feed cursor stays backend-agnostic without widening bus.BusI (a
// read-only convention, issue #107). ok=false for exotic IDs the
// built-in buses never produce: the handler then degrades to a
// non-paginated page (next_cursor="") instead of guessing.
func eventSeq(e bus.Event) (uint64, bool) {
	const prefix = "evt-"
	if !strings.HasPrefix(e.ID, prefix) {
		return 0, false
	}
	n, err := strconv.ParseUint(strings.TrimPrefix(e.ID, prefix), 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

// handleAudit serves GET /v1/{org}/audit. Issue #107: the feed is
// cursor-paginated with the exact wire contract of the resources
// listing — ?cursor= in, "next_cursor" out in the same envelope
// position — reusing the store's v2 offset-cursor machinery (#85
// semantics: stale offsets clamp to an empty page, malformed tokens
// are a 400) so the console's Load-more (issue #86) reaches audit
// tails beyond the first page.
func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request, org string) {
	limit := queryInt(r, "limit", 100)
	if limit <= 0 || limit > maxFeedPage {
		limit = 100
	}
	cursor := r.URL.Query().Get("cursor")
	// The numeric offset is needed to mint the next token; the store
	// re-decodes the token itself, so both layers share one cursor
	// vocabulary and one bound (maxCursorOffset).
	offset := 0
	if cursor != "" {
		n, err := state.DecodeCursor(cursor)
		if err != nil {
			writeError(w, r, http.StatusBadRequest, CodeBadRequest,
				"invalid cursor: must be an audit feed pagination token")
			return
		}
		offset = int(n)
	}
	// Probe one entry past the page: limit+1 is always honored
	// verbatim (limit <= maxFeedPage <= the stores' 1000 query
	// ceiling), so "more exists" is exact, never guessed.
	entries, err := s.store.ListAudit(state.AuditOptions{
		Org:    org,
		Kind:   matchKind(r.URL.Query().Get("kind")),
		Limit:  limit + 1,
		Cursor: cursor,
	})
	if err != nil {
		if errors.Is(err, state.ErrBadRequest) {
			// Defensive: the token was decoded above, so the store
			// should agree; keep the resources-listing mapping if a
			// backend ever disagrees.
			stateStatus(w, r, err)
			return
		}
		// A failed audit query must not masquerade as an empty
		// compliance log (issue #71): surface a 500 envelope instead.
		s.log.Error("audit query failed", "org", org, "err", err)
		writeError(w, r, http.StatusInternalServerError, CodeInternal, "audit query failed")
		return
	}
	next := ""
	if len(entries) > limit {
		entries = entries[:limit]
		// Offset arithmetic cannot overflow: a minted offset is always
		// below the retained count (the probe returned limit+1).
		next = state.EncodeCursor(uint64(offset + limit))
	}
	if entries == nil {
		entries = []state.AuditEntry{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"entries": entries, "count": len(entries), "next_cursor": next,
	})
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
