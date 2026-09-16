package reconcile

import (
	"context"
	"strings"
	"time"

	"github.com/Roy-Wanyoike/Ryvex/internal/bus"
	"github.com/Roy-Wanyoike/Ryvex/internal/metrics"
	"github.com/Roy-Wanyoike/Ryvex/internal/provider"
	"github.com/Roy-Wanyoike/Ryvex/internal/state"
)

// Drift detection (issue #80, docs/adr/0002-provider-spi.md):
//
// A dedicated pass runs on its own interval over every actuated kind
// that declares Caps.DriftDetection and implements FieldMapper. For
// each Ready resource it Inspects the external world and compares the
// desired fields against the observed ones. Drift never mutates
// anything directly: it is surfaced as a status annotation (phase
// stays Ready), an audit entry, a bus event and a metric — then
// corrected through the same Plan→Apply path as ordinary convergence.

const (
	// driftPrefix marks the status annotation a drifted-but-Ready
	// resource carries until the re-apply corrects it (or a later pass
	// observes convergence and clears it).
	driftPrefix = "Drifted: "

	// eventDriftDetected is the bus event type. The bus package's type
	// constants are frozen (parallel-owned package), so the drift
	// event is declared here; Subject() renders it as
	// ryvex.resource.{org}.{kind}.drift_detected.
	eventDriftDetected = "drift_detected"

	// auditDriftDetected is the audit action for a drift observation.
	// UpdateStatus already writes "status_changed" audit entries; this
	// distinct action makes drift episodes directly filterable.
	auditDriftDetected = "drift_detected"

	// driftClearReason annotates the audit reason of a clearing write.
	driftClearReason = "drift resolved on re-inspect"
)

// driftLoop ticks the drift pass. Started only when at least one
// actuator is registered, so status-only deployments keep today's
// exact goroutine and ticker footprint.
func (r *Reconciler) driftLoop(ctx context.Context) {
	t := time.NewTicker(r.opts.DriftInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.driftPass(ctx)
		}
	}
}

// driftPass inspects every converged resource of every drift-capable
// kind. Resources still converging (or Failed / Degraded) are left to
// the worker path; drift is only meaningful from a steady state.
func (r *Reconciler) driftPass(ctx context.Context) {
	for _, kind := range r.actuators.Kinds() {
		act, ok := r.actuators.Lookup(kind)
		if !ok || !act.Capabilities().DriftDetection {
			continue
		}
		mapper, ok := act.(provider.FieldMapper)
		if !ok {
			continue
		}
		r.driftKind(ctx, act, mapper)
		if ctx.Err() != nil {
			return
		}
	}
}

// driftKind walks one actuator's kind with the store's paged listing
// (same pagination discipline as scan: follow cursors to exhaustion
// and bound the walk defensively).
func (r *Reconciler) driftKind(ctx context.Context, act provider.Actuator, mapper provider.FieldMapper) {
	seen := make(map[string]struct{}, 64)
	cursor := ""
	for page := 0; page < maxScanPages; page++ {
		resources, next, err := r.store.ListResources(state.ListOptions{Kind: act.Kind(), Limit: scanPageLimit, Cursor: cursor})
		if err != nil {
			r.log.Error("drift listing failed", "kind", act.Kind(), "err", err)
			return
		}
		for _, res := range resources {
			if res.Status.Phase != state.PhaseReady || res.Status.ObservedGen < res.Generation {
				continue // the worker path owns non-converged resources
			}
			if !r.tryClaim(res.ID) {
				continue // mid-actuation; next pass will look again
			}
			r.checkDrift(ctx, act, mapper, res)
			r.release(res.ID)
			if ctx.Err() != nil {
				return
			}
		}
		if next == "" {
			return
		}
		if _, stuck := seen[next]; stuck {
			r.log.Warn("drift pagination stuck; deferring the rest to the next pass", "kind", act.Kind())
			return
		}
		seen[next] = struct{}{}
		cursor = next
	}
}

// checkDrift compares one resource's desired fields with observed
// external state and drives the annotate → re-Apply → verify loop.
func (r *Reconciler) checkDrift(ctx context.Context, act provider.Actuator, mapper provider.FieldMapper, res *state.Resource) {
	obs, err := act.Inspect(ctx, provider.RefFor(res))
	if err != nil {
		// Advisory only: a down provider must not flap a Ready
		// resource into Degraded — that would invent drift out of an
		// outage. The next pass re-inspects; real actuation failures
		// surface through the worker path's retry book.
		r.log.Warn("drift inspect failed; resource left untouched",
			"kind", res.Kind, "name", res.Name,
			"class", provider.ClassOf(err).String(), "err", err)
		return
	}

	want, err := mapper.DesiredFields(res.Spec)
	if err != nil {
		// The spec stopped being representable (edited by hand?);
		// surface it like any other controller input error would be:
		// through the worker path, which classifies Plan errors.
		r.log.Error("drift desired-fields failed; deferring to converge path",
			"kind", res.Kind, "name", res.Name, "err", err)
		r.Trigger(res.ID)
		return
	}

	var drift []string
	if !obs.Exists {
		drift = []string{"external object missing"}
	} else {
		drift = provider.CompareFields(want, obs.Fields)
	}

	if len(drift) == 0 {
		r.clearDriftAnnotation(res, act)
		return
	}
	r.reportDrift(ctx, act, res, obs, drift)
}

// reportDrift annotates the resource (phase stays Ready — the external
// object still runs; it just diverges), records the episode in the
// audit log and on the bus, then re-applies through the actuator.
func (r *Reconciler) reportDrift(ctx context.Context, act provider.Actuator, res *state.Resource, obs provider.Observed, drift []string) {
	driftStr := strings.Join(drift, ", ")
	r.log.Warn("drift detected", "kind", res.Kind, "name", res.Name, "fields", driftStr)
	metrics.ReconcilerDriftsTotal.WithLabelValues(res.Kind).Inc()

	actor := state.WriteOptions{Actor: actorName, Reason: "drift detected"}
	if err := r.store.UpdateStatus(res.ID, state.PhaseReady, driftPrefix+driftStr, actor); err != nil {
		r.log.Error("drift annotation failed", "id", res.ID, "err", err)
	}
	_, _ = r.store.AppendAudit(state.AuditEntry{
		Actor:      actorName,
		Action:     auditDriftDetected,
		ResourceID: res.ID,
		Kind:       res.Kind,
		LogicalKey: res.LogicalKey(),
		Generation: res.Generation,
		Reason:     driftStr,
	})
	r.bus.Publish(bus.Event{
		Type:       eventDriftDetected,
		Org:        res.Org,
		Project:    res.Project,
		Env:        res.Env,
		Kind:       res.Kind,
		Name:       res.Name,
		ResourceID: res.ID,
		Generation: res.Generation,
		Phase:      res.Status.Phase,
		Actor:      actorName,
		Data:       map[string]any{"fields": drift},
	})

	// Convergence loop: drift detected → re-Apply → verify on the next
	// pass. Same Inspect → Plan → Apply → retry semantics as the
	// worker path, so drift fixes consume the same budget and can land
	// a misbehaving resource in Degraded/Failed honestly.
	r.attempts.begin(res.ID, res.Generation)
	r.runActuation(ctx, res, act, obs, driftCause)
}

// clearDriftAnnotation resets a stale "Drifted:" message once external
// state matches the desired spec again. Write-on-transition only: a
// converged resource is left byte-identical pass after pass.
func (r *Reconciler) clearDriftAnnotation(res *state.Resource, act provider.Actuator) {
	if !strings.HasPrefix(res.Status.Message, driftPrefix) {
		return
	}
	actor := state.WriteOptions{Actor: actorName, Reason: driftClearReason}
	msg := "drift resolved: converged to desired spec (actuated by " + providerName(act) + ")"
	if err := r.store.UpdateStatus(res.ID, state.PhaseReady, msg, actor); err != nil {
		r.log.Error("drift clear failed", "id", res.ID, "err", err)
	}
	_, _ = r.store.AppendAudit(state.AuditEntry{
		Actor:      actorName,
		Action:     "drift_resolved",
		ResourceID: res.ID,
		Kind:       res.Kind,
		LogicalKey: res.LogicalKey(),
		Generation: res.Generation,
		Reason:     driftClearReason,
	})
	r.log.Info("drift resolved", "kind", res.Kind, "name", res.Name)
}
