package docker

import (
	"errors"
	"reflect"
	"testing"

	"github.com/Roy-Wanyoike/Ryvex/internal/provider"
	"github.com/Roy-Wanyoike/Ryvex/internal/state"
)

func TestContainerNameDerivesScope(t *testing.T) {
	ref := provider.Ref{Org: "acme", Project: "core", Env: "prod", Name: "web"}
	if got, want := ContainerName(ref), "ryvex-acme-core-prod-web"; got != want {
		t.Fatalf("ContainerName = %q, want %q", got, want)
	}
}

func TestDesiredFieldsSpecForms(t *testing.T) {
	cases := []struct {
		name string
		spec map[string]any
		want map[string]string
	}{
		{"image only", map[string]any{"image": "demo:1"}, map[string]string{"image": "demo:1"}},
		{
			"env as object",
			map[string]any{"image": "demo:1", "env": map[string]any{"B": "2", "A": "1"}},
			map[string]string{"image": "demo:1", "env.A": "1", "env.B": "2"},
		},
		{
			"env as list",
			map[string]any{"image": "demo:1", "env": []any{"B=2", "A=1"}},
			map[string]string{"image": "demo:1", "env.A": "1", "env.B": "2"},
		},
		{
			"env as packed string",
			map[string]any{"image": "demo:1", "env": "A=1,B=2"},
			map[string]string{"image": "demo:1", "env.A": "1", "env.B": "2"},
		},
		{
			"flat per-variable keys",
			map[string]any{"image": "demo:1", "env.A": "1", "env.PATH": "/usr/bin"},
			map[string]string{"image": "demo:1", "env.A": "1", "env.PATH": "/usr/bin"},
		},
		{
			"flat keys win over an env block",
			map[string]any{"image": "demo:1", "env": map[string]any{"A": "1"}, "env.A": "9"},
			map[string]string{"image": "demo:1", "env.A": "9"},
		},
		{"empty env object dropped", map[string]any{"image": "demo:1", "env": map[string]any{}}, map[string]string{"image": "demo:1"}},
		{"nil env dropped", map[string]any{"image": "demo:1", "env": nil}, map[string]string{"image": "demo:1"}},
		{"image trimmed", map[string]any{"image": "  demo:1  "}, map[string]string{"image": "demo:1"}},
	}
	for _, c := range cases {
		got, err := DesiredFields(c.spec)
		if err != nil {
			t.Errorf("%s: DesiredFields: %v", c.name, err)
			continue
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: DesiredFields = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestDesiredFieldsRejectsBadSpecs(t *testing.T) {
	cases := []struct {
		name string
		spec map[string]any
	}{
		{"missing image", map[string]any{"env": map[string]any{"A": "1"}}},
		{"blank image", map[string]any{"image": "   "}},
		{"non-string image", map[string]any{"image": 7}},
		{"env value not string", map[string]any{"image": "i", "env": map[string]any{"A": 1}}},
		{"env empty key", map[string]any{"image": "i", "env": map[string]any{"": "v"}}},
		{"env list entry without =", map[string]any{"image": "i", "env": []any{"A"}}},
		{"env list non-string entry", map[string]any{"image": "i", "env": []any{7}}},
		{"env packed entry without =", map[string]any{"image": "i", "env": "A"}},
		{"env packed comma value", map[string]any{"image": "i", "env": "A=x,y"}},
		{"env wrong type", map[string]any{"image": "i", "env": 42}},
		{"flat key without name", map[string]any{"image": "i", "env.": "v"}},
		{"flat key non-string", map[string]any{"image": "i", "env.A": 7}},
	}
	for _, c := range cases {
		if _, err := DesiredFields(c.spec); err == nil {
			t.Errorf("%s: DesiredFields accepted a bad spec", c.name)
		}
	}
}

func TestDesiredFieldsIdempotentOverOwnOutput(t *testing.T) {
	// The property the reconciler's drift re-apply relies on: mapping a
	// spec rebuilt from normalized fields yields the same fields. Both
	// input shapes must round-trip.
	for _, spec := range []map[string]any{
		{"image": "demo:1", "env": map[string]any{"B": "2", "A": "1"}},
		{"image": "demo:1", "env.A": "1", "env.B": "2"},
	} {
		first, err := DesiredFields(spec)
		if err != nil {
			t.Fatalf("first mapping (%v): %v", spec, err)
		}
		second, err := DesiredFields(provider.FieldsToSpec(first))
		if err != nil {
			t.Fatalf("mapping over rebuilt spec: %v", err)
		}
		if !reflect.DeepEqual(first, second) {
			t.Fatalf("not idempotent: %v vs %v", first, second)
		}
	}
}

func TestEnvListToFieldsSkipsMalformed(t *testing.T) {
	got := EnvListToFields([]string{"B=2", "PATH=/usr/bin:/bin", "malformed", "=bad"})
	want := map[string]string{"env.B": "2", "env.PATH": "/usr/bin:/bin"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("EnvListToFields = %v, want %v", got, want)
	}
}

func TestPlanContainersActions(t *testing.T) {
	desired := &state.Resource{
		Kind: state.KindApplication, Org: "acme", Project: "core", Env: "prod", Name: "web",
		Spec: map[string]any{"image": "demo:2", "env": map[string]any{"A": "1"}},
	}

	// current == nil → create with the full desired field set.
	plan, err := PlanContainers(nil, desired)
	if err != nil {
		t.Fatalf("create plan: %v", err)
	}
	if plan.Action != provider.ActionCreate || plan.Kind != state.KindApplication || plan.Desired != desired {
		t.Fatalf("unexpected create plan: %+v", plan)
	}
	wantChanges := []provider.Change{{Field: "env.A", To: "1"}, {Field: "image", To: "demo:2"}}
	if !reflect.DeepEqual(plan.Changes, wantChanges) {
		t.Fatalf("create changes = %+v, want %+v", plan.Changes, wantChanges)
	}

	// Converged current → noop.
	current := desired.DeepCopy()
	current.Spec = map[string]any{"image": "demo:2", "env": "A=1"}
	plan, err = PlanContainers(current, desired)
	if err != nil {
		t.Fatalf("noop plan: %v", err)
	}
	if plan.Action != provider.ActionNoop || plan.Changes != nil {
		t.Fatalf("expected noop without changes, got %+v", plan)
	}

	// Actuated-field change → update carrying From/To.
	current.Spec = map[string]any{"image": "demo:1", "env": "A=1"}
	plan, err = PlanContainers(current, desired)
	if err != nil {
		t.Fatalf("update plan: %v", err)
	}
	if plan.Action != provider.ActionUpdate {
		t.Fatalf("expected update, got %q", plan.Action)
	}
	want := []provider.Change{{Field: "image", From: "demo:1", To: "demo:2"}}
	if !reflect.DeepEqual(plan.Changes, want) {
		t.Fatalf("update changes = %+v, want %+v", plan.Changes, want)
	}

	// A new env variable is a field-accurate update, not a full rewrite.
	withB := &state.Resource{Kind: state.KindApplication, Org: "acme", Project: "core", Env: "prod", Name: "web",
		Spec: map[string]any{"image": "demo:2", "env": map[string]any{"A": "1", "B": "2"}}}
	current.Spec = map[string]any{"image": "demo:2", "env.A": "1"}
	plan, err = PlanContainers(current, withB)
	if err != nil {
		t.Fatalf("env-add plan: %v", err)
	}
	if plan.Action != provider.ActionUpdate {
		t.Fatalf("expected update, got %q", plan.Action)
	}
	want = []provider.Change{{Field: "env.B", From: "", To: "2"}}
	if !reflect.DeepEqual(plan.Changes, want) {
		t.Fatalf("env-add changes = %+v, want %+v", plan.Changes, want)
	}

	// An undeclared variable observed on the object (the Engine injects
	// PATH and friends) is out-of-band: not drift, no rewrite.
	current.Spec = map[string]any{"image": "demo:2", "env.A": "1", "env.PATH": "/usr/bin"}
	plan, err = PlanContainers(current, desired)
	if err != nil {
		t.Fatalf("injection plan: %v", err)
	}
	if plan.Action != provider.ActionNoop {
		t.Fatalf("engine-injected env caused drift: %+v", plan.Changes)
	}

	// Unusable current spec forces a full update rather than lying.
	current.Spec = map[string]any{"env": "A=1"} // image missing → unreadable current
	plan, err = PlanContainers(current, desired)
	if err != nil {
		t.Fatalf("full-update plan: %v", err)
	}
	if plan.Action != provider.ActionUpdate || len(plan.Changes) != 2 {
		t.Fatalf("expected full update over an unusable current, got %+v", plan)
	}

	// A bad desired spec classifies Permanent: retrying is lying.
	if _, err := PlanContainers(nil, &state.Resource{Kind: state.KindApplication, Spec: map[string]any{}}); err == nil {
		t.Fatal("plan accepted a spec without image")
	} else if got := provider.ClassOf(err); got != provider.Permanent {
		t.Fatalf("plan error class = %v, want permanent", got)
	}
}

func TestClassifyStatus(t *testing.T) {
	cases := []struct {
		code int
		want provider.Class
	}{
		{200, provider.Transient}, // unreachable via statusError, but safe default
		{400, provider.Permanent},
		{404, provider.Permanent}, // callers treat 404 as absence; never routed here
		{409, provider.Transient}, // create races resolve on retry
		{429, provider.Transient}, // throttle
		{500, provider.Transient},
		{503, provider.Transient},
	}
	for _, c := range cases {
		if got := ClassifyStatus(c.code); got != c.want {
			t.Errorf("ClassifyStatus(%d) = %v, want %v", c.code, got, c.want)
		}
	}
}

func TestErrConflictSentinelIsIsAble(t *testing.T) {
	err := errors.New("unrelated")
	if errors.Is(err, ErrConflict) {
		t.Fatal("unrelated error must not match ErrConflict")
	}
}
