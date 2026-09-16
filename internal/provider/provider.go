// Package provider defines the Ryvex actuator SPI (issue #80): the
// contract between the reconciler and the code that actually touches
// infrastructure. An Actuator is one resource kind's hands — plan,
// apply, inspect, capabilities — while the reconciler keeps every
// piece of control-plane policy: phases, retry/backoff, drift
// comparison, audit, events and metrics.
//
// The design is deliberately thin (see docs/adr/0002-provider-spi.md):
// Plan is a pure function over two resource snapshots, Apply must be
// idempotent, Inspect reports normalized external state, and failures
// are classified (Transient / Permanent / Unavailable) so the
// reconciler can decide what they mean for phase transitions and
// retries. The taxonomy mirrors the agent's Outcome classes
// (agent/ryvex-agent/src/client.rs).
package provider

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/Roy-Wanyoike/Ryvex/internal/state"
)

// Ref identifies the concrete external object an actuator manages on
// behalf of a resource. It carries the resource's scope (org/project/
// env) and identity so providers can derive deterministic external
// names (e.g. the docker provider's "ryvex-{org}-{project}-{env}-
// {name}" container naming) without reaching back into the store.
type Ref struct {
	ResourceID string
	Org        string
	Project    string
	Env        string
	Kind       string
	Name       string
}

// RefFor derives the actuator reference from a stored resource.
func RefFor(r *state.Resource) Ref {
	return Ref{
		ResourceID: r.ID,
		Org:        r.Org,
		Project:    r.Project,
		Env:        r.Env,
		Kind:       r.Kind,
		Name:       r.Name,
	}
}

// Key returns the resource's logical key — the stable, human-readable
// address used for logs and per-resource bookkeeping.
func (ref Ref) Key() string {
	return strings.Join([]string{ref.Org, ref.Project, ref.Env, ref.Kind, ref.Name}, "/")
}

// Action is the operation a Plan prescribes for one Apply.
type Action string

const (
	ActionNoop   Action = "noop"   // external state already matches; nothing to do
	ActionCreate Action = "create" // external object absent (or existence unknown)
	ActionUpdate Action = "update" // external object present but diverges
)

// Change is one field-level difference between current and desired
// state, in the actuator's normalized field vocabulary (the same keys
// Observed.Fields and FieldMapper.DesiredFields use).
type Change struct {
	Field string
	From  string
	To    string
}

// Plan is the pure output of Actuator.Plan: what one Apply must do.
// Desired is the snapshot Apply consumes; Apply must never mutate it.
type Plan struct {
	Kind    string
	Action  Action
	Changes []Change // field diffs; for ActionCreate it is the full desired set (From "")

	Desired *state.Resource
}

// Result reports the outcome of one Apply.
type Result struct {
	Action     Action
	ExternalID string // provider-native handle (e.g. docker container ID)
	Message    string // short, log-safe human summary (no secret material)
}

// Observed is the normalized view of external state Inspect returns.
// Fields keys align with FieldMapper.DesiredFields so the reconciler
// can diff desired vs observed generically (provider.CompareFields).
type Observed struct {
	Exists     bool
	ExternalID string
	State      string            // provider-native lifecycle state ("running", "exited", ...)
	Ready      bool              // the provider's own readiness verdict
	Fields     map[string]string // normalized drift fields; may carry extra provider-side keys
}

// Caps advertises optional actuator capabilities.
type Caps struct {
	// DriftDetection reports that Inspect returns Fields comparable
	// with FieldMapper.DesiredFields, so the reconciler runs drift
	// passes for this actuator's kind. Actuators without it converge
	// but are never drift-checked.
	DriftDetection bool

	// Name is a short provider identifier used in status messages,
	// audit reasons and logs ("docker", "fake"). Optional but
	// strongly recommended.
	Name string
}

// Actuator is the provider SPI: one implementation per actuated
// resource kind. Implementations must be safe for concurrent use (the
// reconciler's worker pool and drift pass share one instance) and must
// keep Plan free of side effects.
type Actuator interface {
	// Kind is the resource kind this actuator drives (state.KindApplication, ...).
	Kind() string
	// Plan derives the operation from two snapshots. current == nil
	// means the external object does not exist (or the caller wants a
	// fresh create plan); otherwise the actuator diffs the two specs
	// through its own field mapping. A Plan error is a controller
	// input error (e.g. invalid spec) and must classify as Permanent.
	Plan(current, desired *state.Resource) (Plan, error)
	// Apply executes a Plan exactly once-ward: it must be idempotent
	// because retries replay the same plan (a create after a crash
	// must tolerate the object already existing).
	Apply(ctx context.Context, plan Plan) (Result, error)
	// Inspect reads external state. Absence (404-style) is not an
	// error: return Observed{Exists: false}, nil.
	Inspect(ctx context.Context, ref Ref) (Observed, error)
	// Capabilities declares what the reconciler may assume.
	Capabilities() Caps
}

// FieldMapper is the optional capability behind drift detection: the
// actuator can translate a desired spec into the same normalized
// field keys its Inspect reports. Actuators that implement it (and
// declare Caps.DriftDetection) get periodic drift comparison; those
// that do not are converged-only.
type FieldMapper interface {
	// DesiredFields maps a desired spec to normalized fields. It must
	// be idempotent over its own output: DesiredFields over a spec
	// rebuilt via FieldsToSpec(DesiredFields(s)) equals DesiredFields(s).
	DesiredFields(spec map[string]any) (map[string]string, error)
}

// ---- error taxonomy ----

// Class buckets every actuator failure into one of three outcomes,
// mirroring the agent's Outcome classes (agent/ryvex-agent client.rs):
// Transient / Rejected(Permanent) / Missing-transport(Unavailable).
type Class int

const (
	// Transient: the provider answered but the operation may succeed
	// on retry (5xx, throttles, transient conflicts). Retried with
	// backoff; phase Degraded between attempts.
	Transient Class = iota
	// Permanent: a deterministic rejection (invalid spec, unsupported
	// field). Retrying is lying. Fails immediately.
	Permanent
	// Unavailable: the provider or its transport is unreachable (dial
	// errors, socket gone). Same mechanics as Transient, but the class
	// is surfaced because the fix is operational, not in the spec.
	Unavailable
)

// String renders the class for logs, messages and metric labels.
func (c Class) String() string {
	switch c {
	case Permanent:
		return "permanent"
	case Unavailable:
		return "unavailable"
	default:
		return "transient"
	}
}

// Error is the canonical actuator failure: a classified wrapper that
// preserves the underlying error for errors.Is / errors.As.
type Error struct {
	Class Class
	Op    string // operation site, e.g. "inspect", "apply:create"
	Err   error
}

// E wraps err with a class and operation site. A nil err returns nil
// so call sites can write `return provider.E(..., err)` unconditionally.
func E(class Class, op string, err error) *Error {
	if err == nil {
		return nil
	}
	return &Error{Class: class, Op: op, Err: err}
}

func (e *Error) Error() string {
	if e.Op == "" {
		return fmt.Sprintf("%s provider error: %v", e.Class, e.Err)
	}
	return fmt.Sprintf("%s provider error at %s: %v", e.Class, e.Op, e.Err)
}

// Unwrap preserves the wrap chain.
func (e *Error) Unwrap() error { return e.Err }

// ClassOf reports the failure class of err. *Error passes its class
// through; anything else defaults to Transient — retry-then-fail is
// the safe default for unknown errors because the retry budget still
// bounds the loop and the status message records the assumption.
func ClassOf(err error) Class {
	var e *Error
	if errors.As(err, &e) {
		return e.Class
	}
	return Transient
}

// ---- generic field helpers ----

// CompareFields diffs desired (want) against observed (got) field maps
// and returns the sorted names of fields that drift. Only keys present
// in want are compared: provider-side additions (e.g. a container
// runtime injecting PATH into env) are out-of-band and never reported;
// a declared key missing from got IS drift, as is any value mismatch.
func CompareFields(want, got map[string]string) []string {
	keys := make([]string, 0, len(want))
	for k := range want {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var drift []string
	for _, k := range keys {
		v, ok := got[k]
		if !ok || v != want[k] {
			drift = append(drift, k)
		}
	}
	return drift
}

// FieldsToSpec rebuilds a spec-shaped map from normalized fields so
// Actuator.Plan can diff real external state: the reconciler
// synthesizes the "current" resource for a drift re-apply by copying
// Observed.Fields into a spec via this helper. Field keys become spec
// keys verbatim (both sides of the mapping agree on names).
func FieldsToSpec(fields map[string]string) map[string]any {
	spec := make(map[string]any, len(fields))
	for k, v := range fields {
		spec[k] = v
	}
	return spec
}

// ---- registry ----

// Registry maps resource kinds to actuators. The reconciler holds one
// registry built from Options.Actuators; providers register one
// Actuator per kind.
type Registry struct {
	mu     sync.RWMutex
	byKind map[string]Actuator
}

// NewRegistry returns an empty actuator registry.
func NewRegistry() *Registry {
	return &Registry{byKind: map[string]Actuator{}}
}

// Register adds an actuator for its kind. Registering two actuators
// for the same kind is a wiring bug and is rejected.
func (rg *Registry) Register(a Actuator) error {
	if a == nil {
		return errors.New("provider: nil actuator")
	}
	if a.Kind() == "" {
		return errors.New("provider: actuator with empty kind")
	}
	rg.mu.Lock()
	defer rg.mu.Unlock()
	if _, dup := rg.byKind[a.Kind()]; dup {
		return fmt.Errorf("provider: actuator for kind %q already registered", a.Kind())
	}
	rg.byKind[a.Kind()] = a
	return nil
}

// Lookup returns the actuator for kind, if any.
func (rg *Registry) Lookup(kind string) (Actuator, bool) {
	rg.mu.RLock()
	defer rg.mu.RUnlock()
	a, ok := rg.byKind[kind]
	return a, ok
}

// Kinds returns the registered kinds, sorted for deterministic scans
// and test output.
func (rg *Registry) Kinds() []string {
	rg.mu.RLock()
	defer rg.mu.RUnlock()
	kinds := make([]string, 0, len(rg.byKind))
	for k := range rg.byKind {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	return kinds
}

// Len is the registered actuator count.
func (rg *Registry) Len() int {
	rg.mu.RLock()
	defer rg.mu.RUnlock()
	return len(rg.byKind)
}
