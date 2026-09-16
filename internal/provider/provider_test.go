package provider

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/Roy-Wanyoike/Ryvex/internal/state"
)

func TestRefForCarriesScope(t *testing.T) {
	res := &state.Resource{
		ID: "r-abc", Kind: state.KindApplication,
		Org: "acme", Project: "core", Env: "prod", Name: "checkout",
	}
	ref := RefFor(res)
	if ref.ResourceID != "r-abc" || ref.Org != "acme" || ref.Project != "core" ||
		ref.Env != "prod" || ref.Kind != state.KindApplication || ref.Name != "checkout" {
		t.Fatalf("unexpected ref: %+v", ref)
	}
	if got, want := ref.Key(), "acme/core/prod/Application/checkout"; got != want {
		t.Fatalf("Key() = %q, want %q", got, want)
	}
}

func TestClassOf(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want Class
	}{
		{"nil defaults to transient", nil, Transient},
		{"plain error defaults to transient", errors.New("boom"), Transient},
		{"classified transient", E(Transient, "apply", errors.New("503")), Transient},
		{"classified permanent", E(Permanent, "plan", errors.New("bad spec")), Permanent},
		{"classified unavailable", E(Unavailable, "inspect", errors.New("dial unix: no such file")), Unavailable},
		{"wrapped classified error", fmt.Errorf("outer: %w", E(Permanent, "apply", errors.New("x"))), Permanent},
	}
	for _, c := range cases {
		if got := ClassOf(c.err); got != c.want {
			t.Errorf("%s: ClassOf = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestErrorStringAndUnwrap(t *testing.T) {
	sentinel := errors.New("socket gone")
	err := E(Unavailable, "inspect", sentinel)
	if got, want := err.Error(), "unavailable provider error at inspect: socket gone"; got != want {
		t.Fatalf("Error() = %q, want %q", got, want)
	}
	if !errors.Is(err, sentinel) {
		t.Fatal("errors.Is lost the wrap chain")
	}
	opless := E(Permanent, "", errors.New("bad"))
	if got, want := opless.Error(), "permanent provider error: bad"; got != want {
		t.Fatalf("Error() = %q, want %q", got, want)
	}
	if E(Transient, "op", nil) != nil {
		t.Fatal("E with nil error must return nil")
	}
}

func TestClassString(t *testing.T) {
	if Transient.String() != "transient" || Permanent.String() != "permanent" || Unavailable.String() != "unavailable" {
		t.Fatal("class strings drifted from the taxonomy labels")
	}
}

func TestCompareFields(t *testing.T) {
	cases := []struct {
		name string
		want map[string]string
		got  map[string]string
		exp  []string
	}{
		{"converged", map[string]string{"image": "a:1"}, map[string]string{"image": "a:1"}, nil},
		{"value drift", map[string]string{"image": "a:1"}, map[string]string{"image": "a:2"}, []string{"image"}},
		{"missing key is drift", map[string]string{"image": "a:1", "env": "A=1"}, map[string]string{"image": "a:1"}, []string{"env"}},
		{"extra observed keys ignored", map[string]string{"image": "a:1"}, map[string]string{"image": "a:1", "PATH": "/usr/bin"}, nil},
		{"multiple sorted", map[string]string{"env": "A=1", "image": "a:1"}, map[string]string{"env": "B=2", "image": "z"}, []string{"env", "image"}},
		{"empty want", nil, map[string]string{"image": "a:1"}, nil},
	}
	for _, c := range cases {
		got := CompareFields(c.want, c.got)
		if !reflect.DeepEqual(got, c.exp) {
			t.Errorf("%s: CompareFields = %v, want %v", c.name, got, c.exp)
		}
	}
}

func TestFieldsToSpecRoundTrip(t *testing.T) {
	fields := map[string]string{"image": "a:1", "env": "A=1,B=2"}
	spec := FieldsToSpec(fields)
	if spec["image"] != "a:1" || spec["env"] != "A=1,B=2" {
		t.Fatalf("unexpected spec: %+v", spec)
	}
}

// registryFake is a minimal actuator used to exercise the Registry.
type registryFake struct{ kind string }

func (f registryFake) Kind() string { return f.kind }
func (f registryFake) Plan(_, desired *state.Resource) (Plan, error) {
	return Plan{}, nil
}
func (f registryFake) Apply(_ context.Context, _ Plan) (Result, error) {
	return Result{}, nil
}
func (f registryFake) Inspect(_ context.Context, _ Ref) (Observed, error) {
	return Observed{}, nil
}
func (f registryFake) Capabilities() Caps { return Caps{Name: "fake"} }

func TestRegistryRegisterLookupKinds(t *testing.T) {
	rg := NewRegistry()
	if rg.Len() != 0 {
		t.Fatal("fresh registry not empty")
	}
	if err := rg.Register(registryFake{kind: state.KindApplication}); err != nil {
		t.Fatalf("register: %v", err)
	}
	if err := rg.Register(registryFake{kind: state.KindCache}); err != nil {
		t.Fatalf("register: %v", err)
	}
	// Duplicates are rejected.
	if err := rg.Register(registryFake{kind: state.KindApplication}); err == nil {
		t.Fatal("duplicate registration accepted")
	}
	// Nil and empty-kind actuators are rejected.
	if err := rg.Register(nil); err == nil {
		t.Fatal("nil actuator accepted")
	}
	if err := rg.Register(registryFake{kind: ""}); err == nil {
		t.Fatal("empty kind accepted")
	}

	a, ok := rg.Lookup(state.KindApplication)
	if !ok || a.Kind() != state.KindApplication {
		t.Fatalf("Lookup(Application) = %v, %v", a, ok)
	}
	if _, ok := rg.Lookup(state.KindSecret); ok {
		t.Fatal("Lookup returned an actuator for an unregistered kind")
	}
	if got, want := rg.Kinds(), []string{"Application", "Cache"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Kinds() = %v, want %v", got, want)
	}
	if rg.Len() != 2 {
		t.Fatalf("Len() = %d, want 2", rg.Len())
	}
}
