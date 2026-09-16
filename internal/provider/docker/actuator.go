//go:build docker

package docker

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/Roy-Wanyoike/Ryvex/internal/provider"
	"github.com/Roy-Wanyoike/Ryvex/internal/state"
)

// Actuator drives Application resources against a Docker Engine
// (issue #80): one managed container per Application, named after the
// resource's logical scope (ContainerName). Built only with
// `-tags docker`; enabled at runtime with
// `--enable-docker-actuator --docker-socket <path>`.
//
// Concurrency: one Actuator instance is shared by the reconciler's
// worker pool and drift pass, but the reconciler's per-resource
// single-flight claim guarantees the same resource is never actuated
// concurrently; the underlying Client is an http.Client (safe).
type Actuator struct {
	client *Client
}

// NewActuator wires the actuator to an Engine client.
func NewActuator(c *Client) *Actuator { return &Actuator{client: c} }

// Kind is the resource kind this actuator drives.
func (a *Actuator) Kind() string { return state.KindApplication }

// Capabilities: drift detection is supported (Inspect returns fields
// comparable via DesiredFields), and "docker" labels every message.
func (a *Actuator) Capabilities() provider.Caps {
	return provider.Caps{DriftDetection: true, Name: "docker"}
}

// Plan delegates to the pure, tag-free plan computation.
func (a *Actuator) Plan(current, desired *state.Resource) (provider.Plan, error) {
	return PlanContainers(current, desired)
}

// DesiredFields implements provider.FieldMapper (drift capability).
func (a *Actuator) DesiredFields(spec map[string]any) (map[string]string, error) {
	return DesiredFields(spec)
}

// Inspect reads the managed container's state. Absence (404) maps to
// Observed{Exists:false} per the SPI contract. Observed env is mapped
// to per-variable fields (env.<KEY>), so Engine/image-injected
// variables (PATH and friends) stay in Fields as extra keys — drift
// comparison only considers keys the desired spec declares, so
// image-level additions never flap.
func (a *Actuator) Inspect(ctx context.Context, ref provider.Ref) (provider.Observed, error) {
	ctr, exists, err := a.client.InspectContainer(ctx, ContainerName(ref))
	if err != nil {
		return provider.Observed{}, err
	}
	if !exists {
		return provider.Observed{Exists: false}, nil
	}
	fields := map[string]string{}
	if ctr.Config != nil {
		if img := strings.TrimSpace(ctr.Config.Image); img != "" {
			fields[FieldImage] = img
		}
		for k, v := range EnvListToFields(ctr.Config.Env) {
			fields[k] = v
		}
	}
	ready := ctr.State != nil && ctr.State.Running && !ctr.State.Dead
	var st string
	if ctr.State != nil {
		st = ctr.State.Status
	}
	return provider.Observed{
		Exists:     true,
		ExternalID: ctr.Id,
		State:      st,
		Ready:      ready,
		Fields:     fields,
	}, nil
}

// Apply executes a Plan:
//
//   - create: ensure (create-if-absent + start) — idempotent for
//     create-after-crash replays (a 409 falls back to adopting and
//     starting the existing object);
//   - update: recreate (stop → remove → create → start), the honest
//     primitive for immutable container configs;
//   - noop:   nothing.
func (a *Actuator) Apply(ctx context.Context, plan provider.Plan) (provider.Result, error) {
	if plan.Desired == nil {
		return provider.Result{}, provider.E(provider.Permanent, "apply", fmt.Errorf("plan has no desired resource"))
	}
	name := ContainerName(provider.RefFor(plan.Desired))
	switch plan.Action {
	case provider.ActionCreate:
		return a.ensure(ctx, name, plan)
	case provider.ActionUpdate:
		return a.recreate(ctx, name, plan)
	case provider.ActionNoop:
		return provider.Result{Action: provider.ActionNoop, Message: "no changes"}, nil
	default:
		return provider.Result{}, provider.E(provider.Permanent, "apply", fmt.Errorf("unsupported plan action %q", plan.Action))
	}
}

// stopTimeoutSecs is the graceful stop window before the engine SIGKILLs.
const stopTimeoutSecs = 10

func (a *Actuator) ensure(ctx context.Context, name string, plan provider.Plan) (provider.Result, error) {
	cfg, err := containerConfig(plan)
	if err != nil {
		return provider.Result{}, err
	}
	id, err := a.client.CreateContainer(ctx, name, cfg)
	if err != nil {
		if !isConflict(err) {
			return provider.Result{}, err
		}
		// Create-after-crash: adopt the existing object and start it.
		// The drift pass owns config correction.
		ctr, exists, ierr := a.client.InspectContainer(ctx, name)
		if ierr != nil {
			return provider.Result{}, ierr
		}
		if !exists {
			// The object vanished between the 409 and the inspect:
			// surface the original conflict as Transient; the retry
			// replays a clean create.
			return provider.Result{}, err
		}
		id = ctr.Id
	}
	if err := a.client.StartContainer(ctx, id); err != nil {
		return provider.Result{}, err
	}
	return provider.Result{
		Action:     provider.ActionCreate,
		ExternalID: id,
		Message:    "container " + shortID(id) + " running",
	}, nil
}

func (a *Actuator) recreate(ctx context.Context, name string, plan provider.Plan) (provider.Result, error) {
	cfg, err := containerConfig(plan)
	if err != nil {
		return provider.Result{}, err
	}
	ctr, exists, err := a.client.InspectContainer(ctx, name)
	if err != nil {
		return provider.Result{}, err
	}
	if exists {
		if err := a.client.StopContainer(ctx, ctr.Id, stopTimeoutSecs); err != nil {
			return provider.Result{}, err
		}
		if err := a.client.RemoveContainer(ctx, ctr.Id); err != nil {
			return provider.Result{}, err
		}
	}
	id, err := a.client.CreateContainer(ctx, name, cfg)
	if err != nil {
		return provider.Result{}, err
	}
	if err := a.client.StartContainer(ctx, id); err != nil {
		return provider.Result{}, err
	}
	return provider.Result{
		Action:     provider.ActionUpdate,
		ExternalID: id,
		Message:    "container recreated " + shortID(id),
	}, nil
}

// containerConfig builds the Engine config from the plan's desired
// spec. Spec errors classify Permanent (they would fail every retry).
// Env variables are reassembled from their per-key fields into a
// sorted list so the same spec always produces a byte-identical
// create body.
func containerConfig(plan provider.Plan) (ContainerConfig, error) {
	want, err := DesiredFields(plan.Desired.Spec)
	if err != nil {
		return ContainerConfig{}, provider.E(provider.Permanent, "apply", err)
	}
	cfg := ContainerConfig{
		Image:  want[FieldImage],
		Labels: managedLabels(plan.Desired),
	}
	for k, v := range want {
		if key, ok := strings.CutPrefix(k, FieldEnvPrefix); ok {
			cfg.Env = append(cfg.Env, key+"="+v)
		}
	}
	sort.Strings(cfg.Env)
	return cfg, nil
}

// managedLabels stamp provenance onto the container so operators can
// see which resource owns it (and scripts can find managed objects).
func managedLabels(r *state.Resource) map[string]string {
	return map[string]string{
		"ryvex.managed":     "true",
		"ryvex.resource":    r.LogicalKey(),
		"ryvex.resource.id": r.ID,
	}
}

// isConflict reports whether err wraps the sentinel create conflict.
func isConflict(err error) bool { return errors.Is(err, ErrConflict) }

// shortID renders the engine's conventional 12-char short form.
func shortID(id string) string {
	if len(id) <= 12 {
		return id
	}
	return id[:12]
}
