package reconcile

import (
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Roy-Wanyoike/Ryvex/internal/bus"
	"github.com/Roy-Wanyoike/Ryvex/internal/metrics"
	"github.com/Roy-Wanyoike/Ryvex/internal/state"
)

// collectEvents subscribes to every drift/status event on the bus and
// records them until cancel is called.
type eventLog struct {
	mu     sync.Mutex
	events []bus.Event
}

func (l *eventLog) subscribe(b *bus.Bus) {
	b.Subscribe("ryvex.resource.>", func(e bus.Event) {
		l.mu.Lock()
		defer l.mu.Unlock()
		l.events = append(l.events, e)
	})
}

func (l *eventLog) has(t string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, e := range l.events {
		if e.Type == t {
			return true
		}
	}
	return false
}

func (l *eventLog) drainBy(t string) []bus.Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []bus.Event
	for _, e := range l.events {
		if e.Type == t {
			out = append(out, e)
		}
	}
	l.events = nil
	return out
}

func waitDriftEvents(t *testing.T, l *eventLog, min int) []bus.Event {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if evs := l.drainBy("drift_detected"); len(evs) >= min {
			return evs
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("no drift_detected events observed")
	return nil
}

func TestDriftDetectedCorrectedThroughApply(t *testing.T) {
	store, b := mkStore(t)
	log := &eventLog{}
	log.subscribe(b)
	act := newFakeActuator()
	res := mkActuatedRes(t, store, "web", "demo:1")

	drifts0 := metricValue(t, "ryvex_reconciler_drifts_total", "Application")

	rec, cancel := startActuated(t, store, b, act, fastPolicy(3), 5*time.Millisecond)
	defer rec.Stop(2 * time.Second)
	defer cancel()

	waitPhase(t, store, res.ID, state.PhaseReady)

	// Someone edits the world behind the control plane's back.
	act.setWorld(map[string]string{"image": "demo:0.9", "runtime-injected": "noise"})

	evs := waitDriftEvents(t, log, 1)
	if len(evs) == 0 || evs[0].Kind != state.KindApplication || evs[0].ResourceID != res.ID {
		t.Fatalf("unexpected drift event: %+v", evs)
	}
	fields, _ := evs[0].Data["fields"].([]string)
	if len(fields) != 1 || fields[0] != "image" {
		t.Fatalf("expected image drift field, got %v", fields)
	}

	// The convergence loop corrects drift through Apply, not by hand.
	waitFor(t, store, res.ID, func(r *state.Resource) bool {
		return r.Status.Phase == state.PhaseReady &&
			strings.Contains(r.Status.Message, "drift corrected")
	})
	if acts := act.actions(); len(acts) != 2 || acts[1] != "update" {
		t.Fatalf("expected create then drift-correcting update, got %v", acts)
	}

	// The episode is in the audit trail.
	if !hasAuditAction(t, store, res.ID, "drift_detected") {
		t.Fatal("drift_detected audit entry missing")
	}
	// And on the metric.
	waitMetricDelta(t, "ryvex_reconciler_drifts_total", "Application", drifts0, 1)
}

func TestDriftAnnotationVisibleWhileApplyInFlight(t *testing.T) {
	store, b := mkStore(t)
	act := newFakeActuator()
	res := mkActuatedRes(t, store, "web", "demo:1")

	rec, cancel := startActuated(t, store, b, act, fastPolicy(3), 5*time.Millisecond)
	defer rec.Stop(2 * time.Second)
	defer cancel()

	waitPhase(t, store, res.ID, state.PhaseReady)

	// Block the next (drift-correcting) apply so the annotation phase
	// is observable.
	gate := make(chan struct{})
	act.setGate(gate)
	act.setWorld(map[string]string{"image": "demo:0.9"})

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		r, err := store.GetResource(res.ID)
		if err == nil && r.Status.Phase == state.PhaseReady &&
			strings.HasPrefix(r.Status.Message, "Drifted: ") &&
			strings.Contains(r.Status.Message, "image") {
			// Found the annotation; release the apply.
			close(gate)
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("Drifted annotation never visible; last: %+v", r.Status)
		}
		time.Sleep(5 * time.Millisecond)
	}
	waitFor(t, store, res.ID, func(r *state.Resource) bool {
		return r.Status.Phase == state.PhaseReady &&
			strings.Contains(r.Status.Message, "drift corrected")
	})
}

func TestDriftMissingObjectRecreates(t *testing.T) {
	store, b := mkStore(t)
	act := newFakeActuator()
	res := mkActuatedRes(t, store, "web", "demo:1")

	rec, cancel := startActuated(t, store, b, act, fastPolicy(3), 5*time.Millisecond)
	defer rec.Stop(2 * time.Second)
	defer cancel()

	waitPhase(t, store, res.ID, state.PhaseReady)

	// The external object vanished entirely.
	act.setWorld(nil)

	// The drift pass must re-create through Apply.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if act.applyCount() >= 2 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if acts := act.actions(); len(acts) != 2 || acts[1] != "create" {
		t.Fatalf("expected a re-creating create, got %v", acts)
	}
	waitPhase(t, store, res.ID, state.PhaseReady)
	got, _ := store.GetResource(res.ID)
	if !strings.Contains(got.Status.Message, "converged to desired spec") {
		t.Fatalf("unexpected message: %q", got.Status.Message)
	}
	if !hasAuditAction(t, store, res.ID, "drift_detected") {
		t.Fatal("missing-object drift must be audited too")
	}
}

func TestDriftInspectErrorDoesNotFlap(t *testing.T) {
	store, b := mkStore(t)
	log := &eventLog{}
	log.subscribe(b)
	act := newFakeActuator()
	res := mkActuatedRes(t, store, "web", "demo:1")

	rec, cancel := startActuated(t, store, b, act, fastPolicy(3), 5*time.Millisecond)
	defer rec.Stop(2 * time.Second)
	defer cancel()

	waitPhase(t, store, res.ID, state.PhaseReady)
	before, _ := store.GetResource(res.ID)

	// The provider goes dark: drift detection is advisory and must not
	// flap a Ready resource into Degraded or invent drift events.
	act.setInspectErr(nilSafeUnavailable())

	deadline := time.Now().Add(300 * time.Millisecond)
	for time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	after, _ := store.GetResource(res.ID)
	if after.Status.Phase != state.PhaseReady || after.Status.Message != before.Status.Message {
		t.Fatalf("inspect outage flapped the resource: %+v", after.Status)
	}
	if log.has("drift_detected") {
		t.Fatal("inspect outage must not publish drift events")
	}
}

func TestDriftAnnotationClearedOnReconverge(t *testing.T) {
	store, b := mkStore(t)
	act := newFakeActuator()
	res := mkActuatedRes(t, store, "web", "demo:1")

	rec, cancel := startActuated(t, store, b, act, fastPolicy(3), 5*time.Millisecond)
	defer rec.Stop(2 * time.Second)
	defer cancel()

	waitPhase(t, store, res.ID, state.PhaseReady)

	// Simulate a stale annotation (e.g. written before a restart, and
	// the world has since converged on its own).
	if err := store.UpdateStatus(res.ID, state.PhaseReady, "Drifted: image",
		state.WriteOptions{Actor: "test", Reason: "seed stale annotation"}); err != nil {
		t.Fatalf("seed annotation: %v", err)
	}

	waitFor(t, store, res.ID, func(r *state.Resource) bool {
		return r.Status.Phase == state.PhaseReady &&
			strings.Contains(r.Status.Message, "drift resolved")
	})
	if !hasAuditAction(t, store, res.ID, "drift_resolved") {
		t.Fatal("drift_resolved audit entry missing")
	}
	// Steady state afterwards: no more message churn.
	stable, _ := store.GetResource(res.ID)
	time.Sleep(80 * time.Millisecond)
	steady, _ := store.GetResource(res.ID)
	if steady.Status.Message != stable.Status.Message || steady.Status.UpdatedAt != stable.Status.UpdatedAt {
		t.Fatalf("converged resource keeps churning status: %+v vs %+v", stable.Status, steady.Status)
	}
}

// ---- helpers shared by the drift tests ----

func nilSafeUnavailable() error { return unavailableErr{} }

type unavailableErr struct{}

func (unavailableErr) Error() string { return "dial unix: connect: connection refused" }

func hasAuditAction(t *testing.T, s *state.Store, resourceID, action string) bool {
	t.Helper()
	entries, err := s.ListAudit(state.AuditOptions{Limit: 500})
	if err != nil {
		t.Fatalf("ListAudit: %v", err)
	}
	for _, e := range entries {
		if e.ResourceID == resourceID && e.Action == action {
			return true
		}
	}
	return false
}

// metricValue reads one labeled sample of a counter from the default
// registry's exposition output (0 when the series was never written).
func metricValue(t *testing.T, name, kindLabel string) float64 {
	t.Helper()
	out := string(metrics.Default.Gather())
	for _, line := range strings.Split(out, "\n") {
		if !strings.HasPrefix(line, name+"{") || !strings.Contains(line, `kind="`+kindLabel+`"`) {
			continue
		}
		idx := strings.LastIndex(line, "} ")
		if idx < 0 {
			continue
		}
		v, err := strconv.ParseFloat(strings.TrimSpace(line[idx+2:]), 64)
		if err == nil {
			return v
		}
	}
	return 0
}

func waitMetricDelta(t *testing.T, name, kindLabel string, before, delta float64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if metricValue(t, name, kindLabel) >= before+delta {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("metric %s{kind=%q} never advanced from %v", name, kindLabel, before)
}
