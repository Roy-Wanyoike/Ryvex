package api

// Tests for issue #107: the events and audit feeds are cursor-paginated
// with the same wire contract as the resources listing (?cursor= in,
// "next_cursor" out at the same envelope position), so the console's
// Load-more (issue #86) can walk feeds past their first page instead of
// the control plane silently truncating them.
//
// The scenarios below run against the full handler stack — a live
// ryvexd face on the memory backend (no reconciler, so feed contents
// are exact) — and cover the acceptance matrix:
//
//   - a feed longer than the console's page size pages via next_cursor
//     and the walk reaches every entry (the Load-more engagement test),
//   - the walk terminates with next_cursor="" and never repeats an
//     entry (sequence/offset strictly advance),
//   - a well-formed stale cursor clamps to an empty page with
//     next_cursor="" — never an error (the #85 eviction contract),
//   - a malformed cursor is a 400 bad_request, like the resources
//     listing,
//   - the audit walk survives the #85 retention ring: entries evicted
//     mid-walk neither error nor loop the walk, and an offset minted
//     before eviction still decodes (clamped when past the window).

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/Roy-Wanyoike/Ryvex/internal/bus"
	"github.com/Roy-Wanyoike/Ryvex/internal/state"
)

// newFeedServer builds the handler stack with no reconciler: its async
// status_changed writes would make feed contents non-exact. The store
// handle is returned for eviction assertions (state.Store.AuditEvicted).
func newFeedServer(t *testing.T) (http.Handler, *state.Store) {
	t.Helper()
	store := state.NewStore()
	eventBus := bus.New()
	h := NewServer(store, eventBus, nil, ServerOptions{
		Auth:   AuthOptions{APIKeys: map[string]string{testToken: "ci"}},
		Logger: discardLogger(),
	})
	return h, store
}

// newCappedFeedServer is newFeedServer with a small #85 audit-retention
// ring so eviction scenarios fit in a test.
func newCappedFeedServer(t *testing.T, cap int) (http.Handler, *state.Store) {
	t.Helper()
	store := state.NewStore(state.WithAuditCap(cap))
	eventBus := bus.New()
	h := NewServer(store, eventBus, nil, ServerOptions{
		Auth:   AuthOptions{APIKeys: map[string]string{testToken: "ci"}},
		Logger: discardLogger(),
	})
	return h, store
}

// createResource POSTs one application resource and fails the test on
// anything but 201. Returns the server-assigned resource ID.
func createResource(t *testing.T, h http.Handler, org, name string) string {
	t.Helper()
	body := fmt.Sprintf(`{"kind":"Application","org":%q,"project":"core","env":"prod","name":%q,`+
		`"spec":{"image":"%s:1.0.0","replicas":1}}`, org, name, name)
	w := do(t, h, http.MethodPost, "/v1/resources", body)
	if w.Code != http.StatusCreated {
		t.Fatalf("create %s/%s: want 201, got %d: %s", org, name, w.Code, w.Body.String())
	}
	id, _ := decode(t, w)["id"].(string)
	if id == "" {
		t.Fatalf("create %s/%s: response missing id: %s", org, name, w.Body.String())
	}
	return id
}

// feedStringField pulls a string field off a JSON-decoded envelope.
func feedStringField(t *testing.T, m map[string]any, key string) string {
	t.Helper()
	v, ok := m[key].(string)
	if !ok {
		t.Fatalf("response field %q missing or not a string: %v", key, m)
	}
	return v
}

// TestEventsFeedCursorWalkConsoleLoadMore is the Load-more engagement
// scenario from issue #107: a live ryvexd on the memory backend holding
// more events than the console's page size (FEED_PAGE_SIZE = 100). The
// first page must carry a next_cursor, following it must append the
// remaining events exactly once, and the walk must terminate with
// next_cursor="" — the long tail is reachable, in newest-first order.
func TestEventsFeedCursorWalkConsoleLoadMore(t *testing.T) {
	h, _ := newFeedServer(t)

	// 120 acme events interleaved with 20 globex events: the cursor must
	// stay org-scoped on every page. Publish order e000..e119 makes the
	// expected acme walk strictly newest-first (e119..e000).
	for i := 0; i < 120; i++ {
		createResource(t, h, "acme", fmt.Sprintf("app-%03d", i))
		if i%6 == 0 {
			createResource(t, h, "globex", fmt.Sprintf("gapp-%03d", i))
		}
	}

	const page = 100 // the console's FEED_PAGE_SIZE
	var walked []string
	seen := map[string]bool{}
	cursor := ""
	for step := 0; ; step++ {
		if step > 5 { // 120 events / page 100 ⇒ at most 2 pages; 5 is a runaway guard
			t.Fatalf("cursor walk did not terminate after %d pages", step)
		}
		path := fmt.Sprintf("/v1/acme/events?limit=%d", page)
		if cursor != "" {
			path += "&cursor=" + cursor
		}
		w := do(t, h, http.MethodGet, path, "")
		if w.Code != http.StatusOK {
			t.Fatalf("events page %d: want 200, got %d: %s", step, w.Code, w.Body.String())
		}
		m := decode(t, w)
		next := feedStringField(t, m, "next_cursor") // the key must exist even when exhausted
		evts, ok := m["events"].([]any)
		if !ok {
			t.Fatalf("events page %d: events array missing: %v", step, m)
		}
		for _, e := range evts {
			name, _ := e.(map[string]any)["name"].(string)
			if seen[name] {
				t.Fatalf("event %s delivered twice across the walk", name)
			}
			seen[name] = true
			walked = append(walked, name)
		}
		if len(evts) == page && next == "" && step == 0 {
			t.Fatalf("full page %d carried no next_cursor — the tail would be unreachable", page)
		}
		if next == "" {
			break
		}
		cursor = next
	}

	if len(walked) != 120 {
		t.Fatalf("walk reached %d acme events, want all 120", len(walked))
	}
	for i, name := range walked {
		want := fmt.Sprintf("app-%03d", 119-i)
		if name != want {
			t.Fatalf("walk position %d = %s, want %s (newest-first)", i, name, want)
		}
	}
}

// TestEventsFeedCursorPageBoundaries pins the exhausted-feed shapes: a
// feed shorter than one page answers next_cursor="" immediately, and a
// multi-page walk lands on a final short page with next_cursor="".
func TestEventsFeedCursorPageBoundaries(t *testing.T) {
	h, _ := newFeedServer(t)
	for i := 0; i < 5; i++ {
		createResource(t, h, "acme", fmt.Sprintf("app-%d", i))
	}

	// Short feed: single page, no cursor offered.
	w := do(t, h, http.MethodGet, "/v1/acme/events?limit=50", "")
	if w.Code != http.StatusOK {
		t.Fatalf("events: want 200, got %d", w.Code)
	}
	m := decode(t, w)
	if got := len(m["events"].([]any)); got != 5 {
		t.Fatalf("short feed returned %d events, want 5", got)
	}
	if next := feedStringField(t, m, "next_cursor"); next != "" {
		t.Fatalf("exhausted feed must answer next_cursor=\"\", got %q", next)
	}

	// Exactly-page-sized pieces: 5 events at limit=2 walk 2/2/1.
	cursor := ""
	total := 0
	for step := 0; step < 5; step++ {
		path := "/v1/acme/events?limit=2"
		if cursor != "" {
			path += "&cursor=" + cursor
		}
		w := do(t, h, http.MethodGet, path, "")
		if w.Code != http.StatusOK {
			t.Fatalf("walk step %d: want 200, got %d", step, w.Code)
		}
		m := decode(t, w)
		total += len(m["events"].([]any))
		next := feedStringField(t, m, "next_cursor")
		if next == "" {
			break
		}
		cursor = next
	}
	if total != 5 {
		t.Fatalf("2-per-page walk reached %d events, want 5", total)
	}
}

// TestEventsFeedCursorStaleAndMalformed covers the #85 cursor contract
// on the events face: a well-formed token that no longer (or never did)
// address anything clamps to a clean empty page, while a malformed
// token is the same 400 bad_request the resources listing answers.
func TestEventsFeedCursorStaleAndMalformed(t *testing.T) {
	h, _ := newFeedServer(t)
	for i := 0; i < 3; i++ {
		createResource(t, h, "acme", fmt.Sprintf("app-%d", i))
	}

	// Stale cursor: the ring's oldest retained event starts the
	// sequence at 1, so a cursor at sequence 1 has nothing older to
	// serve — exactly what a rolled-past cursor decodes to. Empty page,
	// no error, no cursor minted.
	w := do(t, h, http.MethodGet, "/v1/acme/events?limit=10&cursor="+state.EncodeCursor(1), "")
	if w.Code != http.StatusOK {
		t.Fatalf("stale cursor: want 200, got %d: %s", w.Code, w.Body.String())
	}
	m := decode(t, w)
	if got := len(m["events"].([]any)); got != 0 {
		t.Fatalf("stale cursor must clamp to an empty page, got %d events", got)
	}
	if next := feedStringField(t, m, "next_cursor"); next != "" {
		t.Fatalf("empty page must not mint a cursor, got %q", next)
	}

	// A cursor far above every minted sequence is the opposite clamp:
	// everything retained is older than it, so the full feed answers.
	w = do(t, h, http.MethodGet, "/v1/acme/events?limit=10&cursor="+state.EncodeCursor(1<<20), "")
	if w.Code != http.StatusOK {
		t.Fatalf("future cursor: want 200, got %d", w.Code)
	}
	if got := len(decode(t, w)["events"].([]any)); got != 3 {
		t.Fatalf("future cursor must serve the whole feed, got %d events", got)
	}

	// Malformed cursor: 400 bad_request, same mapping as resources.
	w = do(t, h, http.MethodGet, "/v1/acme/events?limit=10&cursor=%40%40bad%40%40", "")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("malformed cursor: want 400, got %d", w.Code)
	}
	if code := decode(t, w)["error"].(map[string]any)["code"]; code != CodeBadRequest {
		t.Fatalf("malformed cursor code = %v, want %s", code, CodeBadRequest)
	}
}

// TestEventsFeedFromAndCursorExclusive pins the mutual exclusion
// between the frozen #15 replay face (?from=, no next_cursor) and the
// #107 pagination face (?cursor=): sending both is a client error, not
// a silent precedence rule.
func TestEventsFeedFromAndCursorExclusive(t *testing.T) {
	h, _ := newFeedServer(t)
	createResource(t, h, "acme", "app-0")

	w := do(t, h, http.MethodGet, "/v1/acme/events?from=1&cursor="+state.EncodeCursor(1), "")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("from+cursor: want 400, got %d: %s", w.Code, w.Body.String())
	}

	// The replay face stays intact on a Replayer-less bus: from is
	// ignored exactly as documented (the request lands on the Recent
	// pagination path), the events answer is unchanged, and the new
	// envelope key is additive (empty string, no page two offered).
	w = do(t, h, http.MethodGet, "/v1/acme/events?from=1", "")
	if w.Code != http.StatusOK {
		t.Fatalf("from replay: want 200, got %d", w.Code)
	}
	m := decode(t, w)
	if got := len(m["events"].([]any)); got != 1 {
		t.Fatalf("from replay events = %d, want 1", got)
	}
	if next := feedStringField(t, m, "next_cursor"); next != "" {
		t.Fatalf("ignored-from page must not mint a cursor, got %q", next)
	}
}

// TestAuditFeedCursorWalkConsoleLoadMore walks the audit feed past its
// first page with org filtering active: offsets address the filtered
// newest-first sequence, so a full acme walk must reach every acme
// entry exactly once and never leak another org's entries.
func TestAuditFeedCursorWalkConsoleLoadMore(t *testing.T) {
	h, _ := newFeedServer(t)

	wantIDs := map[string]bool{}
	for i := 0; i < 60; i++ {
		wantIDs[createResource(t, h, "acme", fmt.Sprintf("app-%03d", i))] = true
		if i%9 == 0 {
			createResource(t, h, "globex", fmt.Sprintf("gapp-%03d", i))
		}
	}

	var walked []string
	cursor := ""
	for step := 0; ; step++ {
		if step > 5 {
			t.Fatalf("audit cursor walk did not terminate after %d pages", step)
		}
		path := "/v1/acme/audit?limit=25"
		if cursor != "" {
			path += "&cursor=" + cursor
		}
		w := do(t, h, http.MethodGet, path, "")
		if w.Code != http.StatusOK {
			t.Fatalf("audit page %d: want 200, got %d: %s", step, w.Code, w.Body.String())
		}
		m := decode(t, w)
		next := feedStringField(t, m, "next_cursor")
		entries, ok := m["entries"].([]any)
		if !ok {
			t.Fatalf("audit page %d: entries array missing: %v", step, m)
		}
		for _, e := range entries {
			id, _ := e.(map[string]any)["resource_id"].(string)
			if !wantIDs[id] {
				t.Fatalf("audit page %d leaked foreign or unknown entry %q", step, id)
			}
			walked = append(walked, id)
		}
		if next == "" {
			break
		}
		cursor = next
	}

	unique := map[string]bool{}
	for _, id := range walked {
		if unique[id] {
			t.Fatalf("audit entry %s delivered twice across the walk", id)
		}
		unique[id] = true
	}
	if len(unique) != 60 {
		t.Fatalf("walk reached %d acme audit entries, want all 60", len(unique))
	}
}

// TestAuditFeedCursorEvictionClamp pins the #85 interplay: with a tiny
// retention ring the walk still terminates over the retained window, an
// offset minted before further eviction keeps decoding, an offset past
// the window clamps to an empty page, and nothing errors.
func TestAuditFeedCursorEvictionClamp(t *testing.T) {
	h, store := newCappedFeedServer(t, 8)

	// Fill past the cap: 12 writes into an 8-slot ring evict the 4 oldest.
	for i := 0; i < 12; i++ {
		createResource(t, h, "acme", fmt.Sprintf("app-%02d", i))
	}
	if got := store.AuditEvicted(); got != 4 {
		t.Fatalf("audit ring evicted %d entries, want 4", got)
	}

	// Walk the retained window: exactly the 8 newest entries, terminating.
	seen := map[string]bool{}
	cursor := ""
	for step := 0; ; step++ {
		if step > 5 {
			t.Fatalf("audit walk over the ring did not terminate after %d pages", step)
		}
		path := "/v1/acme/audit?limit=3"
		if cursor != "" {
			path += "&cursor=" + cursor
		}
		w := do(t, h, http.MethodGet, path, "")
		if w.Code != http.StatusOK {
			t.Fatalf("audit page %d: want 200, got %d: %s", step, w.Code, w.Body.String())
		}
		m := decode(t, w)
		next := feedStringField(t, m, "next_cursor")
		for _, e := range m["entries"].([]any) {
			id, _ := e.(map[string]any)["resource_id"].(string)
			seen[id] = true
		}
		if next == "" {
			break
		}
		cursor = next
	}
	if len(seen) != 8 {
		t.Fatalf("walk over the ring reached %d entries, want the 8 retained", len(seen))
	}

	// An offset minted before more eviction keeps decoding (never
	// errors); re-walking from a mid-window offset stays a clean page.
	w := do(t, h, http.MethodGet, "/v1/acme/audit?limit=3&cursor="+state.EncodeCursor(3), "")
	if w.Code != http.StatusOK {
		t.Fatalf("cursor from before eviction: want 200, got %d: %s", w.Code, w.Body.String())
	}

	// An offset past the retained window clamps to an empty page exactly
	// like a cursor past the end of a list (#85).
	w = do(t, h, http.MethodGet, "/v1/acme/audit?limit=3&cursor="+state.EncodeCursor(50), "")
	if w.Code != http.StatusOK {
		t.Fatalf("past-window cursor: want 200, got %d: %s", w.Code, w.Body.String())
	}
	m := decode(t, w)
	if got := len(m["entries"].([]any)); got != 0 {
		t.Fatalf("past-window cursor must clamp to an empty page, got %d entries", got)
	}
	if next := feedStringField(t, m, "next_cursor"); next != "" {
		t.Fatalf("clamped page must not mint a cursor, got %q", next)
	}
}

// TestAuditFeedCursorMalformed pins the 400 mapping for a malformed
// audit cursor (bad_request, like the resources listing).
func TestAuditFeedCursorMalformed(t *testing.T) {
	h, _ := newFeedServer(t)
	createResource(t, h, "acme", "app-0")

	w := do(t, h, http.MethodGet, "/v1/acme/audit?limit=10&cursor=not-a-cursor", "")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("malformed audit cursor: want 400, got %d", w.Code)
	}
	if code := decode(t, w)["error"].(map[string]any)["code"]; code != CodeBadRequest {
		t.Fatalf("malformed audit cursor code = %v, want %s", code, CodeBadRequest)
	}
}
