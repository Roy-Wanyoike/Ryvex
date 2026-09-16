package reconcile

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Roy-Wanyoike/Ryvex/internal/bus"
	"github.com/Roy-Wanyoike/Ryvex/internal/metrics"
	"github.com/Roy-Wanyoike/Ryvex/internal/provider"
	"github.com/Roy-Wanyoike/Ryvex/internal/state"
)

// fakeActuator is a scriptable Application actuator used to drive the
// reconciler through every phase transition without any real
// infrastructure. Its external world is a field map: Apply writes it,
// Inspect reads it — drift is just an edit of that map.
type fakeActuator struct {
	mu   sync.Mutex
	caps provider.Caps

	// world holds the normalized observed fields; nil map = object missing.
	world map[string]string
	// inspectErr, when set, is returned by every Inspect.
	inspectErr error
	// failClass, when non-nil, classifies the error returned by the
	// first failRemaining applies; applyErr overrides everything.
	failClass     provider.Class
	failErr       error
	failRemaining int
	// applyErr, when set, fails EVERY apply with it (classified).
	applyErr error
	// gate, when non-nil, blocks each Apply until closed.
	gate chan struct{}

	applied []provider.Action
}

func newFakeActuator() *fakeActuator {
	return &fakeActuator{caps: provider.Caps{DriftDetection: true, Name: "fake"}}
}

func (f *fakeActuator) Kind() string { return state.KindApplication }

func (f *fakeActuator) Capabilities() provider.Caps {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.caps
}

// DesiredFields maps image (required) and env (optional map) — the
// same field contract the docker provider implements.
func (f *fakeActuator) DesiredFields(spec map[string]any) (map[string]string, error) {
	out := map[string]string{}
	img, _ := spec["image"].(string)
	if img == "" {
		return nil, fmt.Errorf("spec.image is required")
	}
	out["image"] = img
	if env, ok := spec["env"].(map[string]any); ok {
		out["env"] = canonicalEnvForTest(env)
	}
	return out, nil
}

func canonicalEnvForTest(env map[string]any) string {
	pairs := make([]string, 0, len(env))
	for k, v := range env {
		pairs = append(pairs, fmt.Sprintf("%s=%v", k, v))
	}
	sort.Strings(pairs)
	return strings.Join(pairs, ",")
}

func (f *fakeActuator) Plan(current, desired *state.Resource) (provider.Plan, error) {
	want, err := f.DesiredFields(desired.Spec)
	if err != nil {
		return provider.Plan{}, provider.E(provider.Permanent, "plan", err)
	}
	p := provider.Plan{Kind: desired.Kind, Action: provider.ActionCreate, Desired: desired}
	for k, v := range want {
		p.Changes = append(p.Changes, provider.Change{Field: k, To: v})
	}
	sort.Slice(p.Changes, func(i, j int) bool { return p.Changes[i].Field < p.Changes[j].Field })
	if current == nil {
		return p, nil // create
	}
	have, herr := f.DesiredFields(current.Spec)
	if herr != nil {
		have = map[string]string{} // unusable current: force a full update
	}
	drift := provider.CompareFields(want, have)
	if len(drift) == 0 {
		p.Action = provider.ActionNoop
		p.Changes = nil
		return p, nil
	}
	p.Action = provider.ActionUpdate
	p.Changes = nil
	for _, k := range drift {
		p.Changes = append(p.Changes, provider.Change{Field: k, From: have[k], To: want[k]})
	}
	return p, nil
}

func (f *fakeActuator) Apply(_ context.Context, plan provider.Plan) (provider.Result, error) {
	f.mu.Lock()
	gate := f.gate
	applyErr := f.applyErr
	if applyErr == nil && f.failRemaining > 0 {
		f.failRemaining--
		applyErr = provider.E(f.failClass, "apply", f.failErr)
	}
	f.mu.Unlock()

	if gate != nil {
		<-gate // block until the test opens the gate
	}
	// Record the ATTEMPT (not the outcome) so budget assertions can
	// count failed applies too.
	f.mu.Lock()
	f.applied = append(f.applied, plan.Action)
	f.mu.Unlock()

	if applyErr != nil {
		return provider.Result{}, applyErr
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if plan.Action == provider.ActionNoop {
		return provider.Result{Action: plan.Action, Message: "nothing to do"}, nil
	}
	f.world = map[string]string{}
	if want, err := f.DesiredFields(plan.Desired.Spec); err == nil {
		f.world = want
	}
	return provider.Result{Action: plan.Action, ExternalID: "fake-" + plan.Desired.Name, Message: "fake object converged"}, nil
}

func (f *fakeActuator) Inspect(_ context.Context, _ provider.Ref) (provider.Observed, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.inspectErr != nil {
		return provider.Observed{}, f.inspectErr
	}
	if f.world == nil {
		return provider.Observed{Exists: false}, nil
	}
	fields := make(map[string]string, len(f.world))
	for k, v := range f.world {
		fields[k] = v
	}
	// A provider-side key the controller never declared: drift
	// comparison must ignore it (out-of-band addition).
	fields["runtime-injected"] = "noise"
	return provider.Observed{Exists: true, ExternalID: "fake-obj", State: "running", Ready: true, Fields: fields}, nil
}

func (f *fakeActuator) applyCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.applied)
}

func (f *fakeActuator) actions() []provider.Action {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]provider.Action(nil), f.applied...)
}

func (f *fakeActuator) setWorld(w map[string]string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if w == nil {
		f.world = nil
		return
	}
	cp := make(map[string]string, len(w))
	for k, v := range w {
		cp[k] = v
	}
	f.world = cp
}

func (f *fakeActuator) setInspectErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.inspectErr = err
}

func (f *fakeActuator) setApplyErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.applyErr = err
}

func (f *fakeActuator) failFirst(n int, class provider.Class, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failRemaining = n
	f.failClass = class
	f.failErr = err
}

func (f *fakeActuator) setGate(g chan struct{}) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gate = g
}

// startActuated runs a reconciler wired to act with the given retry
// policy and drift cadence. All delays are tiny: the tests drive real
// scan/trigger/backoff cycles, just fast.
func startActuated(t *testing.T, store *state.Store, b *bus.Bus, act *fakeActuator, policy RetryPolicy, drift time.Duration) (*Reconciler, context.CancelFunc) {
	t.Helper()
	rec := New(store, b, Options{
		Interval:      5 * time.Millisecond,
		Concurrency:   2,
		Logger:        slog.Default(),
		Actuators:     []provider.Actuator{act},
		DriftInterval: drift,
		RetryDefaults: &policy,
	})
	ctx, cancel := context.WithCancel(context.Background())
	rec.Start(ctx)
	return rec, cancel
}

func fastPolicy(maxAttempts int) RetryPolicy {
	return RetryPolicy{MaxAttempts: maxAttempts, BaseDelay: time.Millisecond, MaxDelay: 5 * time.Millisecond}
}

// waitFor polls until cond passes, dumping status on timeout.
func waitFor(t *testing.T, s *state.Store, id string, cond func(*state.Resource) bool) *state.Resource {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if r, err := s.GetResource(id); err == nil && cond(r) {
			return r
		}
		time.Sleep(5 * time.Millisecond)
	}
	r, _ := s.GetResource(id)
	t.Fatalf("condition never held; status: %+v", r.Status)
	return nil
}

// statusWatch observes one resource's status_changed events on the
// bus. Some phases are transient: under heavy parallel load (-race,
// full suite, concurrent packages) a phase's store window — here the
// retry backoff, ~1ms under the fast policy — can close and turn
// terminal before a store poll wakes up, so the poll never sees it
// (issue #130). The bus invokes handlers synchronously inside the
// reconciler's Publish, so a watcher subscribed before Start captures
// every stamp regardless of the test goroutine's scheduling.
type statusWatch struct {
	mu     sync.Mutex
	phases []string
	msgs   map[string]string
}

// watchStatus subscribes to res's status_changed events. Call it
// BEFORE the reconciler starts: subscriptions only see later events.
func watchStatus(b *bus.Bus, store *state.Store, res *state.Resource) *statusWatch {
	w := &statusWatch{msgs: map[string]string{}}
	b.Subscribe(bus.Subject(res.Org, res.Kind, bus.EventStatusChanged), func(e bus.Event) {
		if e.Type != bus.EventStatusChanged || e.ResourceID != res.ID {
			return
		}
		// Runs inline inside the reconciler's Publish, immediately after
		// the status write and while that pass still holds the
		// per-resource single-actor claim — no other writer can
		// interleave, so the read reflects exactly the stamp this event
		// announces.
		if r, err := store.GetResource(res.ID); err == nil {
			w.mu.Lock()
			w.phases = append(w.phases, e.Phase)
			w.msgs[e.Phase] = r.Status.Message
			w.mu.Unlock()
		}
	})
	return w
}

// waitSeen polls (bounded) until the watched stream shows phase.
func (w *statusWatch) waitSeen(t *testing.T, phase string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		w.mu.Lock()
		saw := false
		for _, p := range w.phases {
			if p == phase {
				saw = true
			}
		}
		seen := append([]string(nil), w.phases...)
		w.mu.Unlock()
		if saw {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("status stream never showed %s; saw %v", phase, seen)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// messageAt returns the status message captured when phase was last
// stamped.
func (w *statusWatch) messageAt(phase string) string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.msgs[phase]
}

func mkActuatedRes(t *testing.T, store *state.Store, name, image string) *state.Resource {
	t.Helper()
	res := mkRes(state.KindApplication, name)
	res.Spec = map[string]any{"image": image}
	r, err := store.CreateResource(res, state.WriteOptions{Actor: "test"})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	return r
}

func TestActuatedConvergesViaCreate(t *testing.T) {
	store, b := mkStore(t)
	act := newFakeActuator()
	res := mkActuatedRes(t, store, "web", "demo:1")

	rec, cancel := startActuated(t, store, b, act, fastPolicy(3), time.Hour)
	defer rec.Stop(2 * time.Second)
	defer cancel()

	waitPhase(t, store, res.ID, state.PhaseReady)
	got, _ := store.GetResource(res.ID)
	if got.Status.ObservedGen != got.Generation {
		t.Fatalf("observed generation not stamped: %+v", got.Status)
	}
	if !strings.Contains(got.Status.Message, "actuated by fake") ||
		!strings.Contains(got.Status.Message, "fake-"+res.Name) {
		t.Fatalf("unexpected actuation message: %q", got.Status.Message)
	}
	if acts := act.actions(); len(acts) != 1 || acts[0] != provider.ActionCreate {
		t.Fatalf("expected exactly one create, got %v", acts)
	}
}

func TestActuatedGenerationBumpReapplies(t *testing.T) {
	store, b := mkStore(t)
	act := newFakeActuator()
	res := mkActuatedRes(t, store, "web", "demo:1")

	rec, cancel := startActuated(t, store, b, act, fastPolicy(3), time.Hour)
	defer rec.Stop(2 * time.Second)
	defer cancel()

	waitPhase(t, store, res.ID, state.PhaseReady)

	// A spec change bumps the generation; the actuator must observe
	// the stale external state and plan an update.
	if _, err := store.UpdateResource(res.ID, func(r *state.Resource) error {
		r.Spec = map[string]any{"image": "demo:2"}
		return nil
	}, state.UpdateOptions{WriteOptions: state.WriteOptions{Actor: "test"}}); err != nil {
		t.Fatalf("spec update: %v", err)
	}

	waitFor(t, store, res.ID, func(r *state.Resource) bool {
		return r.Generation == 2 && r.Status.ObservedGen == 2 && r.Status.Phase == state.PhaseReady
	})
	if acts := act.actions(); len(acts) != 2 || acts[0] != provider.ActionCreate || acts[1] != provider.ActionUpdate {
		t.Fatalf("expected create then update, got %v", acts)
	}
}

func TestTransientRetriesThenReady(t *testing.T) {
	store, b := mkStore(t)
	act := newFakeActuator()
	res := mkActuatedRes(t, store, "web", "demo:1")
	act.failFirst(2, provider.Transient, errors.New("engine hiccup"))

	// Degraded lasts only one backoff window per attempt (~1ms under
	// the fast policy); under heavy parallel load a store poll can sleep
	// straight through every window, so observe the transitions on the
	// synchronous event stream instead of racing the store (issue
	// #130). Subscribed before Start, so nothing is missed.
	watch := watchStatus(b, store, res)

	rec, cancel := startActuated(t, store, b, act, fastPolicy(4), time.Hour)
	defer rec.Stop(2 * time.Second)
	defer cancel()

	// Degraded is observable between attempts...
	watch.waitSeen(t, state.PhaseDegraded)
	// ...and the resource still converges once the provider recovers.
	waitPhase(t, store, res.ID, state.PhaseReady)
	if n := act.applyCount(); n != 3 {
		t.Fatalf("expected 3 applies (2 failures + success), got %d", n)
	}
	got, _ := store.GetResource(res.ID)
	if !strings.Contains(got.Status.Message, "converged to desired spec") {
		t.Fatalf("recovered resource should carry the converged message, got %q", got.Status.Message)
	}
}

func TestRetryBudgetExhaustedToFailed(t *testing.T) {
	store, b := mkStore(t)
	act := newFakeActuator()
	act.mu.Lock()
	act.caps = provider.Caps{Name: "fake"} // no drift detection: isolates the worker path
	act.mu.Unlock()
	res := mkActuatedRes(t, store, "web", "demo:1")

	act.setApplyErr(provider.E(provider.Transient, "apply:create", errors.New("engine on fire")))

	rec, cancel := startActuated(t, store, b, act, fastPolicy(2), time.Hour)
	defer rec.Stop(2 * time.Second)
	defer cancel()

	waitPhase(t, store, res.ID, state.PhaseFailed)
	got, _ := store.GetResource(res.ID)
	if !strings.Contains(got.Status.Message, "after 2 attempts") ||
		!strings.Contains(got.Status.Message, "transient") {
		t.Fatalf("unexpected failure message: %q", got.Status.Message)
	}

	// Failed is terminal for the generation: no further applies while
	// scans keep running.
	n := act.applyCount()
	deadline := time.Now().Add(300 * time.Millisecond)
	for time.Now().Before(deadline) {
		if c := act.applyCount(); c != n {
			t.Fatalf("failed resource re-applied: %d -> %d", n, c)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestPermanentFailsImmediatelyNoRetry(t *testing.T) {
	store, b := mkStore(t)
	act := newFakeActuator()
	res := mkActuatedRes(t, store, "web", "demo:1")

	act.setApplyErr(provider.E(provider.Permanent, "apply:create", errors.New("unsupported field")))

	rec, cancel := startActuated(t, store, b, act, fastPolicy(5), time.Hour)
	defer rec.Stop(2 * time.Second)
	defer cancel()

	waitPhase(t, store, res.ID, state.PhaseFailed)
	got, _ := store.GetResource(res.ID)
	if !strings.Contains(got.Status.Message, "permanently") {
		t.Fatalf("unexpected message: %q", got.Status.Message)
	}
	if n := act.applyCount(); n != 1 {
		t.Fatalf("permanent failure must not retry, got %d applies", n)
	}

	// A fresh generation re-opens convergence from Failed.
	act.setApplyErr(nil)
	if _, err := store.UpdateResource(res.ID, func(r *state.Resource) error {
		r.Spec = map[string]any{"image": "demo:2"}
		return nil
	}, state.UpdateOptions{WriteOptions: state.WriteOptions{Actor: "test"}}); err != nil {
		t.Fatalf("spec update: %v", err)
	}
	waitPhase(t, store, res.ID, state.PhaseReady)
}

func TestUnavailableGoesDegradedThenFailed(t *testing.T) {
	store, b := mkStore(t)
	act := newFakeActuator()
	res := mkActuatedRes(t, store, "web", "demo:1")

	act.setApplyErr(provider.E(provider.Unavailable, "apply:create",
		errors.New("dial unix /var/run/docker.sock: connect: no such file or directory")))

	// Degraded lasts exactly one backoff window (~1ms under the fast
	// policy); under heavy parallel load the budget-exhausting second
	// attempt can stamp Failed — terminal for the generation — before
	// this test's store poll wakes up, so the window never reopens and
	// a store poll times out. That is the #130 flake. Watch the
	// synchronous status event stream for the Degraded stamp instead,
	// then assert the terminal phase in the store as before.
	watch := watchStatus(b, store, res)

	rec, cancel := startActuated(t, store, b, act, fastPolicy(2), time.Hour)
	defer rec.Stop(2 * time.Second)
	defer cancel()

	watch.waitSeen(t, state.PhaseDegraded)
	if msg := watch.messageAt(state.PhaseDegraded); !strings.Contains(msg, "unavailable") {
		t.Fatalf("unexpected degraded message: %q", msg)
	}
	waitPhase(t, store, res.ID, state.PhaseFailed)
}

func TestNoopOnLabelOnlyGenerationBump(t *testing.T) {
	store, b := mkStore(t)
	act := newFakeActuator()
	res := mkActuatedRes(t, store, "web", "demo:1")

	rec, cancel := startActuated(t, store, b, act, fastPolicy(3), time.Hour)
	defer rec.Stop(2 * time.Second)
	defer cancel()

	waitPhase(t, store, res.ID, state.PhaseReady)

	// Label-only change: actuated fields did not move, so the plan is
	// a noop and the resource still re-stamps Ready.
	if _, err := store.UpdateResource(res.ID, func(r *state.Resource) error {
		r.Labels = map[string]string{"team": "payments"}
		return nil
	}, state.UpdateOptions{WriteOptions: state.WriteOptions{Actor: "test"}}); err != nil {
		t.Fatalf("label update: %v", err)
	}

	waitFor(t, store, res.ID, func(r *state.Resource) bool {
		return r.Generation == 2 && r.Status.ObservedGen == 2 &&
			strings.Contains(r.Status.Message, "no changes")
	})
	if acts := act.actions(); len(acts) != 1 {
		t.Fatalf("label bump must not re-apply, got %v", acts)
	}
}

func TestActuationMetricsCounted(t *testing.T) {
	store, b := mkStore(t)
	act := newFakeActuator()
	_ = mkActuatedRes(t, store, "web", "demo:1")

	rec, cancel := startActuated(t, store, b, act, fastPolicy(3), time.Hour)
	defer rec.Stop(2 * time.Second)
	defer cancel()

	// The counter increments just after the Ready stamp; poll to dodge
	// that ordering race. The registry is process-global, so assert the
	// SERIES exists (value semantics are covered by the transition
	// tests that read the store directly).
	deadline := time.Now().Add(5 * time.Second)
	for {
		if strings.Contains(string(metrics.Default.Gather()),
			`ryvex_reconciler_actuations_total{kind="Application",outcome="create"} `) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("actuation counter missing:\n%s", metrics.Default.Gather())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestNewDefaultsDriftInterval pins the default drift cadence (issue
// #80): an unset DriftInterval must be normalized in New BEFORE the
// options are captured on the reconciler — driftLoop builds its ticker
// from the captured copy, and a zero value would panic at Start.
func TestNewDefaultsDriftInterval(t *testing.T) {
	store, b := mkStore(t)
	act := newFakeActuator()
	rec := New(store, b, Options{Actuators: []provider.Actuator{act}, Logger: slog.Default()})
	if rec.opts.DriftInterval != 60*time.Second {
		t.Fatalf("DriftInterval = %v, want the 60s default", rec.opts.DriftInterval)
	}
}
