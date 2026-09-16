package api

// Tests for issue #72: no-op scope PUTs — byte-identical bodies re-sent
// by the node agent's spec-throttled heartbeats — must keep the 200 +
// generation semantics but must NOT publish an EventUpdated through the
// bus. Before the fix every heartbeat flooded the events feed, the
// webhook dispatcher and ryvex_bus_events_published_total exactly as if
// the spec had changed. Genuinely-changed specs must still publish
// exactly one event, and CAS/generation/audit semantics are untouched.

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Roy-Wanyoike/Ryvex/internal/authz"
	"github.com/Roy-Wanyoike/Ryvex/internal/bus"
	"github.com/Roy-Wanyoike/Ryvex/internal/bus/natsbus"
	"github.com/Roy-Wanyoike/Ryvex/internal/metrics"
	"github.com/Roy-Wanyoike/Ryvex/internal/state"
	"github.com/Roy-Wanyoike/Ryvex/internal/webhook"
)

// nodeBody builds the node document the agent heartbeats: the full
// resource re-sent every tick with spec.last_seen refreshed at most
// once per spec-refresh interval, so consecutive bodies between
// refreshes are byte-identical. gen > 0 pins the CAS generation the
// agent echoes from its enrollment GET.
func nodeBody(gen int64, lastSeen string) string {
	b := `{"kind":"Node","org":"acme","project":"fleet","env":"prod","name":"node-1",` +
		`"labels":{"cluster":"prod-eu1","managed-by":"ryvex-agent"},` +
		`"spec":{"arch":"amd64","last_seen":"` + lastSeen + `","version":"v1.1.0"}`
	if gen > 0 {
		b += fmt.Sprintf(`,"generation":%d`, gen)
	}
	return b + "}"
}

// newNoopServer builds the handler stack with a nil reconciler — these
// tests never hit the reconcile route, and skipping the real reconciler
// removes its asynchronous status_changed events so event-count
// assertions below can be exact. The store and bus handles are handed
// back for direct assertions.
func newNoopServer(t *testing.T) (http.Handler, *state.Store, *bus.Bus) {
	t.Helper()
	store := state.NewStore()
	eventBus := bus.New()
	h := NewServer(store, eventBus, nil, ServerOptions{
		Auth:   AuthOptions{APIKeys: map[string]string{testToken: "ci"}},
		Logger: discardLogger(),
	})
	return h, store, eventBus
}

// updatedEvents returns the bus events of type "updated" recorded for a
// resource ID (the replay ring is newest first; order is not asserted).
func updatedEvents(t *testing.T, b *bus.Bus, resourceID string) []bus.Event {
	t.Helper()
	evts, err := b.Recent("", bus.RingSize)
	if err != nil {
		t.Fatalf("recent events: %v", err)
	}
	var out []bus.Event
	for _, e := range evts {
		if e.Type == bus.EventUpdated && e.ResourceID == resourceID {
			out = append(out, e)
		}
	}
	return out
}

// countAuditAction counts audit entries with the given action across
// all orgs (the test store holds no other writers).
func countAuditAction(t *testing.T, store *state.Store, action string) int {
	t.Helper()
	entries, err := store.ListAudit(state.AuditOptions{Limit: 500})
	if err != nil {
		t.Fatalf("list audit: %v", err)
	}
	n := 0
	for _, e := range entries {
		if e.Action == action {
			n++
		}
	}
	return n
}

func TestNoopScopePutSuppressesUpdatedEvent(t *testing.T) {
	h, store, eventBus := newNoopServer(t)

	// Enroll: the upsert PUT creates and publishes created — never updated.
	w := do(t, h, http.MethodPut, "/v1/acme/fleet/prod/nodes/node-1", nodeBody(0, "2026-01-01T00:00:00Z"))
	if w.Code != http.StatusCreated {
		t.Fatalf("enroll: want 201, got %d: %s", w.Code, w.Body.String())
	}
	id := decode(t, w)["id"].(string)
	if got := updatedEvents(t, eventBus, id); len(got) != 0 {
		t.Fatalf("enroll published %d updated events, want 0", len(got))
	}

	updatedMetric0 := metrics.BusEventsPublishedTotal.WithLabelValues(bus.EventUpdated).Value()
	updatedAudit0 := countAuditAction(t, store, "updated")

	// Heartbeats: byte-identical PUTs, the agent's spec-throttle contract.
	for i := 0; i < 3; i++ {
		w := do(t, h, http.MethodPut, "/v1/acme/fleet/prod/nodes/node-1", nodeBody(0, "2026-01-01T00:00:00Z"))
		if w.Code != http.StatusOK {
			t.Fatalf("heartbeat %d: want 200, got %d: %s", i, w.Code, w.Body.String())
		}
		if got := decode(t, w)["generation"].(float64); got != 1 {
			t.Fatalf("heartbeat %d: generation = %v, want unchanged 1", i, got)
		}
	}
	if got := updatedEvents(t, eventBus, id); len(got) != 0 {
		t.Fatalf("no-op heartbeats published %d updated events, want 0: %+v", len(got), got)
	}
	if got := metrics.BusEventsPublishedTotal.WithLabelValues(bus.EventUpdated).Value(); got != updatedMetric0 {
		t.Fatalf("ryvex_bus_events_published_total{updated} moved on no-op heartbeats: %v -> %v", updatedMetric0, got)
	}
	if got := countAuditAction(t, store, "updated"); got != updatedAudit0 {
		t.Fatalf("no-op heartbeats changed audit suppression semantics: %d -> %d updated entries", updatedAudit0, got)
	}

	// A real spec change (last_seen refresh) publishes exactly one event,
	// bumps the generation once and keeps the audit entry.
	w = do(t, h, http.MethodPut, "/v1/acme/fleet/prod/nodes/node-1", nodeBody(0, "2026-01-01T00:05:00Z"))
	if w.Code != http.StatusOK {
		t.Fatalf("spec refresh: want 200, got %d: %s", w.Code, w.Body.String())
	}
	if got := decode(t, w)["generation"].(float64); got != 2 {
		t.Fatalf("spec refresh: generation = %v, want 2", got)
	}
	evts := updatedEvents(t, eventBus, id)
	if len(evts) != 1 {
		t.Fatalf("spec refresh published %d updated events, want exactly 1", len(evts))
	}
	e := evts[0]
	if e.Org != "acme" || e.Kind != "Node" || e.Name != "node-1" || e.Generation != 2 || e.Actor != "ci" {
		t.Fatalf("published event fields wrong: %+v", e)
	}
	if want := bus.Subject("acme", "Node", bus.EventUpdated); e.Subject != want {
		t.Fatalf("subject = %q, want %q", e.Subject, want)
	}
	if got := countAuditAction(t, store, "updated"); got != updatedAudit0+1 {
		t.Fatalf("real change must keep exactly one updated audit entry: %d -> %d", updatedAudit0, got)
	}

	// Back to steady state: the next identical heartbeat is silent again.
	w = do(t, h, http.MethodPut, "/v1/acme/fleet/prod/nodes/node-1", nodeBody(0, "2026-01-01T00:05:00Z"))
	if w.Code != http.StatusOK {
		t.Fatalf("steady-state heartbeat: want 200, got %d", w.Code)
	}
	if got := updatedEvents(t, eventBus, id); len(got) != 1 {
		t.Fatalf("steady-state heartbeat published another event: %d total, want 1", len(got))
	}
}

func TestScopePutMetadataChangeStillPublishes(t *testing.T) {
	h, _, eventBus := newNoopServer(t)
	w := do(t, h, http.MethodPut, "/v1/acme/fleet/prod/nodes/node-1", nodeBody(0, "2026-01-01T00:00:00Z"))
	if w.Code != http.StatusCreated {
		t.Fatalf("enroll: want 201, got %d", w.Code)
	}
	id := decode(t, w)["id"].(string)

	// A labels-only change (metadata) must publish even though the spec
	// is byte-identical — the store bumps the generation for it too.
	relabel := `{"kind":"Node","org":"acme","project":"fleet","env":"prod","name":"node-1",` +
		`"labels":{"cluster":"prod-eu2","managed-by":"ryvex-agent"},` +
		`"spec":{"arch":"amd64","last_seen":"2026-01-01T00:00:00Z","version":"v1.1.0"}}`
	w = do(t, h, http.MethodPut, "/v1/acme/fleet/prod/nodes/node-1", relabel)
	if w.Code != http.StatusOK {
		t.Fatalf("relabel: want 200, got %d: %s", w.Code, w.Body.String())
	}
	if got := decode(t, w)["generation"].(float64); got != 2 {
		t.Fatalf("relabel: generation = %v, want 2", got)
	}
	if got := updatedEvents(t, eventBus, id); len(got) != 1 {
		t.Fatalf("labels-only change published %d updated events, want 1", len(got))
	}

	// Re-sending the same labels stays a no-op.
	w = do(t, h, http.MethodPut, "/v1/acme/fleet/prod/nodes/node-1", relabel)
	if w.Code != http.StatusOK {
		t.Fatalf("repeat relabel: want 200, got %d", w.Code)
	}
	if got := updatedEvents(t, eventBus, id); len(got) != 1 {
		t.Fatalf("identical relabel published another event: %d total, want 1", len(got))
	}

	// Omitting labels keeps the stored labels; with the spec unchanged
	// that is still a no-op heartbeat.
	nolabels := `{"kind":"Node","org":"acme","project":"fleet","env":"prod","name":"node-1",` +
		`"spec":{"arch":"amd64","last_seen":"2026-01-01T00:00:00Z","version":"v1.1.0"}}`
	w = do(t, h, http.MethodPut, "/v1/acme/fleet/prod/nodes/node-1", nolabels)
	if w.Code != http.StatusOK {
		t.Fatalf("label-less heartbeat: want 200, got %d", w.Code)
	}
	if got := decode(t, w)["generation"].(float64); got != 2 {
		t.Fatalf("label-less heartbeat must keep generation, got %v", got)
	}
	if got := updatedEvents(t, eventBus, id); len(got) != 1 {
		t.Fatalf("label-less no-op heartbeat published an event: %d total, want 1", len(got))
	}
}

func TestScopePutConflictPublishesNoEvent(t *testing.T) {
	h, _, eventBus := newNoopServer(t)
	w := do(t, h, http.MethodPut, "/v1/acme/fleet/prod/nodes/node-1", nodeBody(0, "2026-01-01T00:00:00Z"))
	if w.Code != http.StatusCreated {
		t.Fatalf("enroll: want 201, got %d", w.Code)
	}
	id := decode(t, w)["id"].(string)

	// Stale CAS generation conflicts exactly as before (issue #72 must
	// not relax CAS), and a conflict publishes nothing.
	w = do(t, h, http.MethodPut, "/v1/acme/fleet/prod/nodes/node-1", nodeBody(7, "2026-01-01T00:05:00Z"))
	if w.Code != http.StatusConflict {
		t.Fatalf("stale CAS: want 409, got %d: %s", w.Code, w.Body.String())
	}
	if got := updatedEvents(t, eventBus, id); len(got) != 0 {
		t.Fatalf("conflicted PUT published %d updated events, want 0", len(got))
	}

	// A current-generation CAS no-op heartbeat is accepted (200), keeps
	// the generation and stays silent.
	w = do(t, h, http.MethodPut, "/v1/acme/fleet/prod/nodes/node-1", nodeBody(1, "2026-01-01T00:00:00Z"))
	if w.Code != http.StatusOK {
		t.Fatalf("CAS no-op heartbeat: want 200, got %d: %s", w.Code, w.Body.String())
	}
	if got := decode(t, w)["generation"].(float64); got != 1 {
		t.Fatalf("CAS no-op heartbeat: generation = %v, want 1", got)
	}
	if got := updatedEvents(t, eventBus, id); len(got) != 0 {
		t.Fatalf("CAS no-op heartbeat published %d updated events, want 0", len(got))
	}
}

func TestConcurrentHeartbeatPutsSingleWinnerSingleEvent(t *testing.T) {
	h, _, eventBus := newNoopServer(t)
	w := do(t, h, http.MethodPut, "/v1/acme/fleet/prod/nodes/node-1", nodeBody(0, "2026-01-01T00:00:00Z"))
	if w.Code != http.StatusCreated {
		t.Fatalf("enroll: want 201, got %d", w.Code)
	}
	id := decode(t, w)["id"].(string)

	// Fleet-wide contention: concurrent CAS PUTs echoing the same
	// observed generation with distinct specs. Exactly one wins the CAS,
	// the losers get 409, and exactly one updated event is published —
	// the winner's pre-image snapshot is the only one the store applies
	// (run under -race).
	const fleet = 8
	var wg sync.WaitGroup
	var wins atomic.Int32
	codes := make([]int, fleet)
	for i := 0; i < fleet; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			body := fmt.Sprintf(`{"kind":"Node","org":"acme","project":"fleet","env":"prod","name":"node-1",`+
				`"spec":{"arch":"amd64","last_seen":"race-%d","version":"v1.1.0"},"generation":1}`, i)
			r := do(t, h, http.MethodPut, "/v1/acme/fleet/prod/nodes/node-1", body)
			codes[i] = r.Code
			if r.Code == http.StatusOK {
				wins.Add(1)
			}
		}(i)
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("want exactly 1 CAS winner, got %d (codes %v)", wins.Load(), codes)
	}
	for i, c := range codes {
		if c != http.StatusOK && c != http.StatusConflict {
			t.Fatalf("goroutine %d: unexpected status %d", i, c)
		}
	}
	evts := updatedEvents(t, eventBus, id)
	if len(evts) != 1 {
		t.Fatalf("contented PUTs published %d updated events, want exactly 1", len(evts))
	}
	if evts[0].Generation != 2 {
		t.Fatalf("winner event generation = %d, want 2", evts[0].Generation)
	}
}

// TestNoopHeartbeatWebhookDispatcherReceivesNothing runs the real
// webhook dispatcher against a captured sink: a Subscription matching
// only updated events for the org must receive NOTHING while the agent
// heartbeats byte-identical PUTs, and exactly one delivery when the
// spec genuinely changes.
func TestNoopHeartbeatWebhookDispatcherReceivesNothing(t *testing.T) {
	// The sink lives on 127.0.0.1, which the SSRF egress guard refuses
	// without the documented opt-in (same approach as the webhook
	// package's own TestMain).
	t.Setenv(state.EnvAllowPrivateWebhooks, "1")

	h, store, eventBus := newNoopServer(t)

	var hits atomic.Int32
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer sink.Close()

	ctx, cancel := context.WithCancel(context.Background())
	disp := webhook.NewDispatcher(store, eventBus, webhook.Options{
		Logger:         discardLogger(),
		BackoffBase:    time.Millisecond,
		RequestTimeout: 2 * time.Second,
		ServerSecret:   "noop-test-secret",
	})
	disp.Start(ctx)
	t.Cleanup(func() { cancel(); disp.Stop(2 * time.Second) })

	// Subscription matching ONLY updated events for acme, so the sink
	// count is exactly the number of updated events fanned out. The
	// memory bus delivers inline, so the subscription's own created
	// event arms the dispatcher before this PUT returns.
	sub := `{"kind":"Subscription","org":"acme","project":"fleet","env":"prod","name":"upd-hook",` +
		`"spec":{"url":"` + sink.URL + `","subjects":["ryvex.resource.acme.*.updated"],` +
		`"active":true,"max_retries":2}}`
	w := do(t, h, http.MethodPut, "/v1/acme/fleet/prod/subscriptions/upd-hook", sub)
	if w.Code != http.StatusCreated {
		t.Fatalf("subscription create: want 201, got %d: %s", w.Code, w.Body.String())
	}

	// Enroll the node: its created event must not reach the sink.
	w = do(t, h, http.MethodPut, "/v1/acme/fleet/prod/nodes/node-1", nodeBody(0, "2026-01-01T00:00:00Z"))
	if w.Code != http.StatusCreated {
		t.Fatalf("enroll: want 201, got %d", w.Code)
	}

	// Heartbeats: nothing is published, so nothing is enqueued or POSTed.
	for i := 0; i < 3; i++ {
		w := do(t, h, http.MethodPut, "/v1/acme/fleet/prod/nodes/node-1", nodeBody(0, "2026-01-01T00:00:00Z"))
		if w.Code != http.StatusOK {
			t.Fatalf("heartbeat %d: want 200, got %d", i, w.Code)
		}
	}
	time.Sleep(150 * time.Millisecond) // settle: dispatcher workers stay idle
	if got := hits.Load(); got != 0 {
		t.Fatalf("webhook dispatcher received %d deliveries for no-op heartbeats, want 0", got)
	}

	// A real change fans out exactly one delivery.
	w = do(t, h, http.MethodPut, "/v1/acme/fleet/prod/nodes/node-1", nodeBody(0, "2026-01-01T00:05:00Z"))
	if w.Code != http.StatusOK {
		t.Fatalf("spec refresh: want 200, got %d", w.Code)
	}
	waitUntil(t, "webhook delivery of the changed-spec event", 5*time.Second, func() bool {
		return hits.Load() == 1
	})

	// And the next identical heartbeat is silent again.
	w = do(t, h, http.MethodPut, "/v1/acme/fleet/prod/nodes/node-1", nodeBody(0, "2026-01-01T00:05:00Z"))
	if w.Code != http.StatusOK {
		t.Fatalf("steady-state heartbeat: want 200, got %d", w.Code)
	}
	time.Sleep(150 * time.Millisecond)
	if got := hits.Load(); got != 1 {
		t.Fatalf("webhook dispatcher received %d deliveries total, want 1", got)
	}
}

// TestNoopScopePutSuppressesUpdatedEventNATS is the backend-parity half
// of issue #72: the same heartbeat scenario must also keep the durable
// JetStream stream free of phantom updated events. Env-gated with the
// same contract as the natsbus parity suite: start a nats-server and
// export RYVEX_TEST_NATS_URL=nats://127.0.0.1:18422 to exercise it.
func TestNoopScopePutSuppressesUpdatedEventNATS(t *testing.T) {
	url := os.Getenv("RYVEX_TEST_NATS_URL")
	if url == "" {
		t.Skip("RYVEX_TEST_NATS_URL not set; skipping live NATS JetStream tests")
	}
	nb, err := natsbus.New(url, natsbus.Options{MaxAge: time.Hour, Storage: "memory"})
	if err != nil {
		t.Fatalf("natsbus.New(%s): %v", url, err)
	}
	t.Cleanup(func() { _ = nb.Close() })

	// A unique org isolates this run from anything already in the
	// durable shared stream; resource IDs differ per run anyway.
	org := fmt.Sprintf("noop%d", time.Now().UnixNano())
	store := state.NewStore()
	h := NewServer(store, nb, nil, ServerOptions{
		Auth:   AuthOptions{APIKeys: map[string]string{testToken: "ci"}},
		Logger: discardLogger(),
	})
	path := "/v1/" + org + "/fleet/prod/nodes/node-1"

	// Enroll: exactly one created event lands in the stream.
	w := do(t, h, http.MethodPut, path, nodeBody(0, "2026-01-01T00:00:00Z"))
	if w.Code != http.StatusCreated {
		t.Fatalf("enroll: want 201, got %d: %s", w.Code, w.Body.String())
	}

	// No-op heartbeats must not add a single stream message.
	for i := 0; i < 3; i++ {
		w := do(t, h, http.MethodPut, path, nodeBody(0, "2026-01-01T00:00:00Z"))
		if w.Code != http.StatusOK {
			t.Fatalf("heartbeat %d: want 200, got %d", i, w.Code)
		}
		if got := decode(t, w)["generation"].(float64); got != 1 {
			t.Fatalf("heartbeat %d: generation = %v, want 1", i, got)
		}
	}
	// The publish is acked before the handler returns, so the stream is
	// settled by the time the PUT response is read.
	evts, err := nb.Recent(org, 100)
	if err != nil {
		t.Fatalf("recent: %v", err)
	}
	if len(evts) != 1 || evts[0].Type != bus.EventCreated {
		t.Fatalf("after 3 no-op heartbeats the stream holds %d events (%v); want only created", len(evts), evts)
	}

	// A real change lands exactly one durable updated event.
	w = do(t, h, http.MethodPut, path, nodeBody(0, "2026-01-01T00:05:00Z"))
	if w.Code != http.StatusOK {
		t.Fatalf("spec refresh: want 200, got %d", w.Code)
	}
	if got := decode(t, w)["generation"].(float64); got != 2 {
		t.Fatalf("spec refresh: generation = %v, want 2", got)
	}
	evts, err = nb.Recent(org, 100)
	if err != nil {
		t.Fatalf("recent after change: %v", err)
	}
	if len(evts) != 2 {
		t.Fatalf("stream holds %d events after a real change, want 2", len(evts))
	}
	if evts[0].Type != bus.EventUpdated || evts[0].Generation != 2 {
		t.Fatalf("newest stream event = %+v, want the updated event at generation 2", evts[0])
	}
	if evts[1].Type != bus.EventCreated {
		t.Fatalf("older stream event = %+v, want the created event", evts[1])
	}
}

// newNoopRBACServer builds the handler stack with RBAC enabled and a
// nil reconciler (same exactness argument as newNoopServer: no
// asynchronous status_changed noise) so event-count assertions can be
// exact. /v1/keys is only mounted with an authorizer, and key events
// on the bus keep the authorizer cache fresh without a reconciler.
func newNoopRBACServer(t *testing.T, adminToken string) (http.Handler, *bus.Bus) {
	t.Helper()
	store := state.NewStore()
	eventBus := bus.New()
	az := authz.New(store, eventBus, authz.Options{Logger: discardLogger()})
	if err := SeedAdminKey(store, "root", adminToken, discardLogger()); err != nil {
		t.Fatalf("seed admin: %v", err)
	}
	if err := az.Refresh(); err != nil {
		t.Fatalf("authz refresh: %v", err)
	}
	h := NewServer(store, eventBus, nil, ServerOptions{
		Auth:       AuthOptions{APIKeys: map[string]string{adminToken: "root"}},
		Logger:     discardLogger(),
		Authorizer: az,
	})
	return h, eventBus
}

// TestNoopKeyPatchSuppressesUpdatedEvent pins the key-management half
// of the #72 churn class (issue #108): a no-change PATCH on a managed
// key - an empty body, or one restating the current
// roles/scopes/active - must answer 200 with the key view but must NOT
// publish an `updated` key event. A real change publishes exactly one,
// and the next identical PATCH is silent again.
func TestNoopKeyPatchSuppressesUpdatedEvent(t *testing.T) {
	admin := "ryk_noop_admin_0001"
	h, eventBus := newNoopRBACServer(t, admin)

	_, keyID := mintKey(t, h, admin, "svc-bot", "operator", "acme", "core")
	if got := updatedEvents(t, eventBus, keyID); len(got) != 0 {
		t.Fatalf("key create published %d updated events, want 0", len(got))
	}

	updatedMetric0 := metrics.BusEventsPublishedTotal.WithLabelValues(bus.EventUpdated).Value()

	// Empty PATCH: nothing addressed, nothing changed.
	w := doAuth(t, h, http.MethodPut, "/v1/keys/"+keyID, admin, `{}`)
	if w.Code != http.StatusOK {
		t.Fatalf("empty PATCH: want 200, got %d: %s", w.Code, w.Body.String())
	}
	// Restating the current values: a non-empty body with an identical
	// spec must still count as a no-change PATCH.
	w = doAuth(t, h, http.MethodPut, "/v1/keys/"+keyID, admin,
		`{"roles":["operator"],"scopes":["org/acme/project/core"],"active":true}`)
	if w.Code != http.StatusOK {
		t.Fatalf("restating PATCH: want 200, got %d: %s", w.Code, w.Body.String())
	}
	if got := decode(t, w)["active"]; got != true {
		t.Fatalf("restating PATCH must return the unchanged view, got %s", w.Body.String())
	}
	if got := updatedEvents(t, eventBus, keyID); len(got) != 0 {
		t.Fatalf("no-change key PATCHes published %d updated events, want 0: %+v", len(got), got)
	}
	if got := metrics.BusEventsPublishedTotal.WithLabelValues(bus.EventUpdated).Value(); got != updatedMetric0 {
		t.Fatalf("ryvex_bus_events_published_total{updated} moved on no-change key PATCHes: %v -> %v", updatedMetric0, got)
	}

	// A real change publishes exactly one updated event with the key's
	// coordinates (reserved namespace, APIKey kind, principal as name).
	w = doAuth(t, h, http.MethodPut, "/v1/keys/"+keyID, admin, `{"active":false}`)
	if w.Code != http.StatusOK {
		t.Fatalf("disable PATCH: want 200, got %d: %s", w.Code, w.Body.String())
	}
	evts := updatedEvents(t, eventBus, keyID)
	if len(evts) != 1 {
		t.Fatalf("real key change published %d updated events, want exactly 1", len(evts))
	}
	e := evts[0]
	if e.Org != state.ReservedOrg || e.Kind != state.KindAPIKey || e.Name != "svc-bot" || e.Actor != "root" {
		t.Fatalf("published key event fields wrong: %+v", e)
	}

	// Back to steady state: restating the new value is silent again.
	w = doAuth(t, h, http.MethodPut, "/v1/keys/"+keyID, admin, `{"active":false}`)
	if w.Code != http.StatusOK {
		t.Fatalf("steady-state PATCH: want 200, got %d: %s", w.Code, w.Body.String())
	}
	if got := updatedEvents(t, eventBus, keyID); len(got) != 1 {
		t.Fatalf("steady-state no-change PATCH published another event: %d total, want 1", len(got))
	}
}

// TestNoopHeartbeatResponseByteIdentical pins the UpdatedAt half of
// issue #108: UpdateResource must not stamp UpdatedAt on a no-op PUT,
// so the byte-identical heartbeat bodies the agent re-sends between
// spec refreshes get byte-identical responses back - the #72 heartbeat
// invariant now holds field for field, updated_at included.
func TestNoopHeartbeatResponseByteIdentical(t *testing.T) {
	h, _, _ := newNoopServer(t)
	w := do(t, h, http.MethodPut, "/v1/acme/fleet/prod/nodes/node-1", nodeBody(0, "2026-01-01T00:00:00Z"))
	if w.Code != http.StatusCreated {
		t.Fatalf("enroll: want 201, got %d", w.Code)
	}
	first := w.Body.String()
	for i := 0; i < 3; i++ {
		w = do(t, h, http.MethodPut, "/v1/acme/fleet/prod/nodes/node-1", nodeBody(0, "2026-01-01T00:00:00Z"))
		if w.Code != http.StatusOK {
			t.Fatalf("heartbeat %d: want 200, got %d: %s", i, w.Code, w.Body.String())
		}
		if w.Body.String() != first {
			t.Fatalf("no-op heartbeat %d changed the response body:\nfirst: %s\nlater: %s", i, first, w.Body.String())
		}
	}
	// updated_at must actually be present in the body, otherwise the
	// byte-equality above proves nothing.
	if !strings.Contains(first, `"updated_at"`) {
		t.Fatalf("response body carries no updated_at field: %s", first)
	}
}
