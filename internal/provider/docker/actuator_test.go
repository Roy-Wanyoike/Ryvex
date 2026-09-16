//go:build docker

package docker

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/Roy-Wanyoike/Ryvex/internal/provider"
	"github.com/Roy-Wanyoike/Ryvex/internal/state"
)

func testResource() *state.Resource {
	return &state.Resource{
		ID:   "r-1",
		Kind: state.KindApplication,
		Org:  "acme", Project: "core", Env: "prod", Name: "web",
		Spec: map[string]any{"image": "demo:1", "env": map[string]any{"A": "1", "B": "2"}},
	}
}

func TestShortID(t *testing.T) {
	if got := shortID("deadbeefdeadbeef"); got != "deadbeefdead" {
		t.Fatalf("shortID = %q", got)
	}
	if got := shortID("abc"); got != "abc" {
		t.Fatalf("shortID = %q", got)
	}
}

func TestActuatorCapabilities(t *testing.T) {
	a := NewActuator(nil)
	caps := a.Capabilities()
	if !caps.DriftDetection || caps.Name != "docker" {
		t.Fatalf("unexpected caps: %+v", caps)
	}
	if a.Kind() != state.KindApplication {
		t.Fatalf("Kind = %q, want Application", a.Kind())
	}
}

func TestActuatorApplyCreateFlow(t *testing.T) {
	socket, e := newFakeEngine(t)
	a := NewActuator(NewClient(socket))
	res := testResource()

	plan, err := a.Plan(nil, res) // external object absent → create
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if plan.Action != provider.ActionCreate {
		t.Fatalf("action = %q, want create", plan.Action)
	}
	got, err := a.Apply(context.Background(), plan)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if got.Action != provider.ActionCreate || got.ExternalID == "" {
		t.Fatalf("unexpected result: %+v", got)
	}
	if !strings.Contains(got.Message, "running") {
		t.Fatalf("message should say the container runs: %q", got.Message)
	}
	if calls := e.snapshotCalls(); len(calls) != 2 || !strings.HasPrefix(calls[0], "create:ryvex-acme-core-prod-web") || calls[1] != "start" {
		t.Fatalf("unexpected call sequence: %v", calls)
	}

	// The create body carried the managed env (sorted) and labels.
	e.mu.Lock()
	cfg := e.cfg
	e.mu.Unlock()
	if cfg.Image != "demo:1" || !reflect.DeepEqual(cfg.Env, []string{"A=1", "B=2"}) {
		t.Fatalf("create body wrong: %+v", cfg)
	}
	if cfg.Labels["ryvex.managed"] != "true" || cfg.Labels["ryvex.resource.id"] != res.ID {
		t.Fatalf("provenance labels missing: %+v", cfg.Labels)
	}
}

func TestActuatorCreateAfterCrashAdoptsExisting(t *testing.T) {
	socket, e := newFakeEngine(t)
	a := NewActuator(NewClient(socket))

	// A container with the managed name already exists (e.g. the daemon
	// crashed between create and the Ready stamp): create replays must
	// be idempotent — adopt and start, never fail.
	e.mu.Lock()
	e.ctr = &Container{Id: "already-here", State: &ContainerState{Status: "created"}}
	e.mu.Unlock()

	plan, err := a.Plan(nil, testResource())
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	got, err := a.Apply(context.Background(), plan)
	if err != nil {
		t.Fatalf("apply after crash: %v", err)
	}
	if got.ExternalID != "already-here" {
		t.Fatalf("adopted external id = %q, want already-here", got.ExternalID)
	}
	calls := e.snapshotCalls()
	if len(calls) != 3 || !strings.HasPrefix(calls[0], "create:") || calls[1] != "inspect" || calls[2] != "start" {
		t.Fatalf("unexpected call sequence: %v", calls)
	}
}

func TestActuatorUpdateRecreatesContainer(t *testing.T) {
	socket, e := newFakeEngine(t)
	a := NewActuator(NewClient(socket))
	res := testResource()

	// The world runs an older image.
	e.mu.Lock()
	e.ctr = &Container{
		Id:     "old-container-id-0001",
		Name:   "/ryvex-acme-core-prod-web",
		Config: &ContainerConfig{Image: "demo:0", Env: []string{"A=1", "B=2"}},
		State:  &ContainerState{Status: "running", Running: true},
	}
	e.mu.Unlock()

	obs, err := a.Inspect(context.Background(), provider.RefFor(res))
	if err != nil || !obs.Exists {
		t.Fatalf("inspect: (%+v, %v, %v)", obs, obs.Exists, err)
	}
	current := res.DeepCopy()
	current.Spec = provider.FieldsToSpec(obs.Fields)
	plan, err := a.Plan(current, res)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if plan.Action != provider.ActionUpdate {
		t.Fatalf("action = %q, want update", plan.Action)
	}
	got, err := a.Apply(context.Background(), plan)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if got.Action != provider.ActionUpdate || got.ExternalID == "old-container-id-0001" {
		t.Fatalf("unexpected result: %+v", got)
	}
	// The test's own Inspect plus the recreate's Inspect, then
	// stop → remove → create → start, in that order.
	want := []string{"inspect", "inspect", "stop", "remove", "create:ryvex-acme-core-prod-web", "start"}
	if calls := e.snapshotCalls(); !reflect.DeepEqual(calls, want) {
		t.Fatalf("call sequence = %v, want %v", calls, want)
	}
}

// TestActuatorEnvInjectionDoesNotFlap pins the property that keeps the
// drift pass honest against real engines: Docker merges image-defined
// variables (PATH and friends) into Config.Env, so observed env always
// carries extras the spec never declared. Per-variable env fields make
// those extras plain ignored keys — a converged container must plan a
// noop, not an eternal recreate loop.
func TestActuatorEnvInjectionDoesNotFlap(t *testing.T) {
	socket, e := newFakeEngine(t)
	a := NewActuator(NewClient(socket))
	res := testResource()

	e.mu.Lock()
	e.ctr = &Container{
		Id:     "live",
		Config: &ContainerConfig{Image: "demo:1", Env: []string{"PATH=/usr/local/sbin:/usr/bin", "A=1", "B=2", "HOSTNAME=4f0d1c"}},
		State:  &ContainerState{Status: "running", Running: true},
	}
	e.mu.Unlock()

	obs, err := a.Inspect(context.Background(), provider.RefFor(res))
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	if obs.Fields["env.PATH"] != "/usr/local/sbin:/usr/bin" || obs.Fields["env.A"] != "1" {
		t.Fatalf("unexpected observed fields: %v", obs.Fields)
	}
	current := res.DeepCopy()
	current.Spec = provider.FieldsToSpec(obs.Fields)
	plan, err := a.Plan(current, res)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if plan.Action != provider.ActionNoop {
		t.Fatalf("engine-injected env caused drift: %+v", plan.Changes)
	}
}

func TestActuatorInspectAbsence(t *testing.T) {
	socket, _ := newFakeEngine(t)
	a := NewActuator(NewClient(socket))
	obs, err := a.Inspect(context.Background(), provider.RefFor(testResource()))
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	if obs.Exists {
		t.Fatalf("expected absence, got %+v", obs)
	}
}

func TestActuatorApplyRejectsPlanWithoutDesired(t *testing.T) {
	socket, _ := newFakeEngine(t)
	a := NewActuator(NewClient(socket))
	_, err := a.Apply(context.Background(), provider.Plan{Action: provider.ActionCreate})
	if err == nil || provider.ClassOf(err) != provider.Permanent {
		t.Fatalf("plan without desired must be a permanent input error, got %v", err)
	}
}

func TestActuatorFieldMapperIdempotent(t *testing.T) {
	a := NewActuator(nil)
	mapper := provider.FieldMapper(a) // drift capability declared via Caps
	first, err := mapper.DesiredFields(testResource().Spec)
	if err != nil {
		t.Fatalf("first mapping: %v", err)
	}
	second, err := mapper.DesiredFields(provider.FieldsToSpec(first))
	if err != nil {
		t.Fatalf("round-trip mapping: %v", err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("not idempotent: %v vs %v", first, second)
	}
}
