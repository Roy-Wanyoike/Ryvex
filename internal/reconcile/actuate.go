package reconcile

import (
	"context"
	"fmt"
	"strings"

	"github.com/Roy-Wanyoike/Ryvex/internal/metrics"
	"github.com/Roy-Wanyoike/Ryvex/internal/provider"
	"github.com/Roy-Wanyoike/Ryvex/internal/state"
)

// actorName is the audit/bus attribution for every actuation-driven
// mutation, matching the "reconciler" actor the status path uses.
const actorName = "reconciler"

// registerActuators builds the kind→actuator registry from options.
// A duplicate kind is a wiring bug: it is logged and skipped so one
// bad entry cannot take the daemon down (the first registration wins).
func (r *Reconciler) registerActuators(acts []provider.Actuator) {
	for _, a := range acts {
		if a == nil {
			continue
		}
		if err := r.actuators.Register(a); err != nil {
			r.log.Error("actuator registration skipped", "err", err)
		}
	}
}

// policyFor resolves the retry policy for a kind: the per-kind
// override first, then the caller-supplied default, then the built-in
// default. All inputs are sanitized at the boundary.
func (r *Reconciler) policyFor(kind string) RetryPolicy {
	if p, ok := r.opts.RetryPolicies[kind]; ok {
		return p.sanitized()
	}
	if r.opts.RetryDefaults != nil {
		return (*r.opts.RetryDefaults).sanitized()
	}
	return DefaultRetryPolicy()
}

// tryClaim takes the per-resource actuation lock. The drift pass and
// the worker pool share it so exactly one goroutine ever actuates a
// resource at a time — the in-process single-actor guarantee
// (docs/adr/0002-provider-spi.md). A losing caller simply skips; the
// scan or the next drift pass re-runs it.
func (r *Reconciler) tryClaim(id string) bool {
	r.actMu.Lock()
	defer r.actMu.Unlock()
	if r.actuating == nil {
		r.actuating = map[string]struct{}{}
	}
	if _, busy := r.actuating[id]; busy {
		return false
	}
	r.actuating[id] = struct{}{}
	return true
}

func (r *Reconciler) release(id string) {
	r.actMu.Lock()
	defer r.actMu.Unlock()
	delete(r.actuating, id)
}

// reconcileActuated drives one resource of an actuated kind. Guards:
//
//   - Failed is terminal for the current generation (a spec change
//     re-opens convergence via the ObservedGen < Generation trigger);
//   - Ready with the generation observed is steady state, owned by the
//     drift pass;
//   - Degraded honors the backoff schedule before re-attempting.
func (r *Reconciler) reconcileActuated(res *state.Resource, cause string) {
	if !r.tryClaim(res.ID) {
		return
	}
	defer r.release(res.ID)

	act, ok := r.actuators.Lookup(res.Kind)
	if !ok {
		return
	}

	if res.Status.Phase == state.PhaseFailed && res.Status.ObservedGen >= res.Generation {
		return // terminal until the spec generation moves
	}
	if res.Status.Phase == state.PhaseReady && res.Status.ObservedGen >= res.Generation {
		return // steady state; the drift pass owns it
	}
	if res.Status.Phase == state.PhaseDegraded && !r.attempts.due(res.ID, res.Generation) {
		return // inside the backoff window
	}
	r.attempts.begin(res.ID, res.Generation) // fresh generation ⇒ fresh budget

	if res.Status.Phase == state.PhasePending {
		actor := state.WriteOptions{Actor: actorName, Reason: cause}
		if err := r.store.UpdateStatus(res.ID, state.PhaseProvisioning, "provisioning underlying infrastructure", actor); err != nil {
			r.log.Error("provisioning stamp failed", "id", res.ID, "err", err)
			return
		}
		r.emit(res, state.PhaseProvisioning)
		res.Status.Phase = state.PhaseProvisioning
	}

	obs, err := act.Inspect(r.actCtx(), provider.RefFor(res))
	if err != nil {
		r.actuationFailed(res, act, err, cause)
		return
	}
	r.runActuation(r.actCtx(), res, act, obs, cause)
}

// actCtx is the context actuator calls run under: the daemon's base
// context once Start has been called (so shutdown cancels in-flight
// Applies), Background before that (defensive for direct use).
func (r *Reconciler) actCtx() context.Context {
	if r.baseCtx != nil {
		return r.baseCtx
	}
	return context.Background()
}

// planFor builds the Plan for one actuation pass:
//
//   - external object missing            ⇒ Plan(nil, desired) → create;
//   - object present, FieldMapper fluent ⇒ Plan(pseudo-current from
//     Observed.Fields, desired) → update/noop by real field diff (this
//     also covers a fresh generation: actuated-field changes diff as
//     update, label-only bumps collapse to noop);
//   - object present, no FieldMapper     ⇒ on a fresh generation re-run
//     the create plan (Apply must be idempotent), otherwise nothing to do.
func (r *Reconciler) planFor(act provider.Actuator, res *state.Resource, obs provider.Observed) (provider.Plan, error) {
	if !obs.Exists {
		return act.Plan(nil, res)
	}
	if _, ok := act.(provider.FieldMapper); ok {
		current := res.DeepCopy()
		current.Spec = provider.FieldsToSpec(obs.Fields)
		return act.Plan(current, res)
	}
	if res.Status.ObservedGen < res.Generation {
		return act.Plan(nil, res)
	}
	return provider.Plan{Kind: res.Kind, Action: provider.ActionNoop, Desired: res}, nil
}

// runActuation plans and applies, then records the outcome on the
// resource status. Kept separate from reconcileActuated so the drift
// pass can drive the exact same path with its own Inspect result.
func (r *Reconciler) runActuation(ctx context.Context, res *state.Resource, act provider.Actuator, obs provider.Observed, cause string) {
	plan, err := r.planFor(act, res, obs)
	if err != nil {
		r.actuationFailed(res, act, err, cause)
		return
	}

	if plan.Action == provider.ActionNoop {
		r.actuationSettled(res, act, plan, provider.Result{Action: provider.ActionNoop}, cause)
		return
	}

	result, err := act.Apply(ctx, plan)
	if err != nil {
		r.actuationFailed(res, act, err, cause)
		return
	}
	r.actuationSettled(res, act, plan, result, cause)
}

// actuationSettled stamps the success/noop outcome: Ready with an
// actuation-aware message, a status event, and the actuation metric.
func (r *Reconciler) actuationSettled(res *state.Resource, act provider.Actuator, plan provider.Plan, result provider.Result, cause string) {
	name := providerName(act)
	actor := state.WriteOptions{Actor: actorName, Reason: cause}
	var msg string
	switch {
	case plan.Action == provider.ActionNoop:
		msg = fmt.Sprintf("converged to desired spec (actuated by %s: no changes)", name)
	case cause == driftCause && plan.Action == provider.ActionUpdate:
		msg = fmt.Sprintf("drift corrected: re-applied desired spec (actuated by %s, %s)", name, externalRef(result))
	default:
		msg = fmt.Sprintf("converged to desired spec (actuated by %s, %s)", name, externalRef(result))
	}
	if err := r.store.UpdateStatus(res.ID, state.PhaseReady, clampMessage(msg), actor); err != nil {
		r.log.Error("ready stamp failed", "id", res.ID, "err", err)
	}
	r.emit(res, state.PhaseReady)
	r.attempts.clear(res.ID)
	metrics.ReconcilerActuationsTotal.WithLabelValues(res.Kind, string(plan.Action)).Inc()
	r.log.Info("actuation applied", "kind", res.Kind, "name", res.Name,
		"action", plan.Action, "provider", name, "external_id", result.ExternalID, "cause", cause)
}

// actuationFailed records one failed attempt under the per-kind retry
// policy: Permanent fails immediately; retryable classes go Degraded
// with exponential backoff and Failed once the budget is exhausted.
func (r *Reconciler) actuationFailed(res *state.Resource, act provider.Actuator, err error, cause string) {
	class := provider.ClassOf(err)
	n := r.attempts.record(res.ID, res.Generation)
	policy := r.policyFor(res.Kind)
	actor := state.WriteOptions{Actor: actorName, Reason: cause}
	metrics.ReconcilerActuationsTotal.WithLabelValues(res.Kind, "failed").Inc()

	// A cancelled context means the daemon is shutting down: skip the
	// status churn (the scan re-drives the resource on next boot).
	if ctxErr := r.actCtx().Err(); ctxErr != nil {
		r.log.Warn("actuation aborted by shutdown", "id", res.ID, "err", err)
		return
	}

	var msg string
	switch {
	case class == provider.Permanent:
		msg = fmt.Sprintf("actuation failed permanently (attempt %d, %s): %v", n, class, err)
		if err := r.store.UpdateStatus(res.ID, state.PhaseFailed, clampMessage(msg), actor); err != nil {
			r.log.Error("failed stamp error", "id", res.ID, "err", err)
		}
		r.emit(res, state.PhaseFailed)
		r.attempts.clear(res.ID)
	case n >= policy.MaxAttempts:
		msg = fmt.Sprintf("actuation failed after %d attempts (%s): %v", n, class, err)
		if err := r.store.UpdateStatus(res.ID, state.PhaseFailed, clampMessage(msg), actor); err != nil {
			r.log.Error("failed stamp error", "id", res.ID, "err", err)
		}
		r.emit(res, state.PhaseFailed)
		r.attempts.clear(res.ID)
	default:
		delay := Backoff(policy, n)
		r.attempts.schedule(res.ID, res.Generation, delay)
		msg = fmt.Sprintf("actuation degraded, retry %d/%d in %v (%s): %v", n, policy.MaxAttempts, delay, class, err)
		if err := r.store.UpdateStatus(res.ID, state.PhaseDegraded, clampMessage(msg), actor); err != nil {
			r.log.Error("degraded stamp error", "id", res.ID, "err", err)
		}
		r.emit(res, state.PhaseDegraded)
	}
	r.log.Error("actuation failed", "kind", res.Kind, "name", res.Name,
		"provider", providerName(act), "class", class.String(), "attempt", n, "cause", cause, "err", err)
}

// providerName is the Caps.Name fallback for actuators that skip it.
func providerName(act provider.Actuator) string {
	if c := act.Capabilities(); c.Name != "" {
		return c.Name
	}
	return "provider"
}

// externalRef renders the actuator's handle for status messages.
func externalRef(result provider.Result) string {
	if result.ExternalID != "" {
		return "external id " + result.ExternalID
	}
	if result.Message != "" {
		return result.Message
	}
	return "no external id"
}

// driftCause marks actuations driven by the drift pass; it selects
// the "drift corrected" success message.
const driftCause = "drift"

// clampMessage keeps status messages inside a comfortable display
// size: a hostile provider error string must not bloat every list
// response. (Errors are classified upstream; this is cosmetics.)
func clampMessage(msg string) string {
	const max = 512
	if len(msg) <= max {
		return msg
	}
	return strings.TrimSuffix(msg[:max], " ") + "…"
}
