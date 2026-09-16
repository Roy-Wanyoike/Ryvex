// Package reconcile drives declarative resources toward their desired
// state. In this reference implementation the reconciler progresses
// each resource through Pending -> Provisioning -> Ready, stamping the
// observed generation and emitting status events on the bus.
package reconcile

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/Roy-Wanyoike/Ryvex/internal/bus"
	"github.com/Roy-Wanyoike/Ryvex/internal/metrics"
	"github.com/Roy-Wanyoike/Ryvex/internal/provider"
	"github.com/Roy-Wanyoike/Ryvex/internal/state"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// Options configures the reconciler loop.
type Options struct {
	Interval    time.Duration // scan cadence
	Concurrency int           // worker count
	Scopes      [][2]string   // namespaces the platform controls, e.g. {"org","project"}
	Namespaces  []string      // env namespaces considered in-scope
	Logger      *slog.Logger

	// --- provider SPI (issue #80, docs/adr/0002-provider-spi.md) ---

	// Actuators drive kinds that touch real infrastructure. Kinds
	// without an actuator keep the exact status-only convergence flow
	// (and messages) they have always had.
	Actuators []provider.Actuator

	// DriftInterval is the cadence of the drift-detection pass for
	// actuated kinds that declare Caps.DriftDetection. Zero selects
	// the default (60s). The pass is only started when at least one
	// drift-capable actuator is registered.
	DriftInterval time.Duration

	// RetryDefaults overrides the built-in retry policy for every
	// actuated kind without a specific entry (nil = DefaultRetryPolicy).
	RetryDefaults *RetryPolicy

	// RetryPolicies overrides the retry policy per resource kind.
	RetryPolicies map[string]RetryPolicy

	// TracerProvider, when non-nil, enables reconcile spans (issue
	// #83): one "reconcile.scan" span per scan cycle and one
	// "reconcile.resource" span per resource reconcile, both rooted
	// at the daemon context passed to Start (background work has no
	// request parent). nil keeps the global default provider — the
	// no-op — so tracing stays zero-cost unless the daemon wires the
	// SDK provider (it does when --otlp-endpoint is set).
	TracerProvider trace.TracerProvider
}

// Reconciler scans the store on a fixed interval and progresses
// resource phases. It is safe for concurrent use.
type Reconciler struct {
	store state.Backend
	bus   bus.BusI
	opts  Options
	log   *slog.Logger

	triggers chan trigger
	stopOnce sync.Once
	done     chan struct{}

	// --- provider SPI state (issue #80) ---
	actuators *provider.Registry

	// attempts is the in-memory per-resource retry book (generation,
	// attempt count, next-due time). A daemon restart restarts the
	// episode; durable retry bookkeeping is the ADR-0001 workflow
	// engine's territory.
	attempts *attemptBook

	// actuating/actMu form the per-resource single-flight claim shared
	// by the worker pool and the drift pass: the in-process half of
	// the single-actor guarantee (one daemon, one store).
	actMu     sync.Mutex
	actuating map[string]struct{}

	// baseCtx is the daemon context captured by Start; actuator calls
	// run under it so shutdown cancels in-flight Applies.
	baseCtx context.Context

	// tracer mints the reconcile spans (issue #83). It resolves from
	// opts.TracerProvider (or the global no-op default) at New time.
	tracer trace.Tracer
}

// New constructs a reconciler. Call Start to begin the loop.
func New(store state.Backend, b bus.BusI, opts Options) *Reconciler {
	if opts.Interval <= 0 {
		opts.Interval = 30 * time.Second
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = 2
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.DriftInterval <= 0 {
		opts.DriftInterval = 60 * time.Second
	}
	if opts.TracerProvider == nil {
		opts.TracerProvider = otel.GetTracerProvider() // global default: no-op (issue #83)
	}
	r := &Reconciler{
		store:     store,
		bus:       b,
		opts:      opts,
		log:       opts.Logger.With("component", "reconciler"),
		triggers:  make(chan trigger, 128),
		done:      make(chan struct{}),
		actuators: provider.NewRegistry(),
		attempts:  newAttemptBook(),
		actuating: map[string]struct{}{},
		tracer:    opts.TracerProvider.Tracer("github.com/Roy-Wanyoike/Ryvex/internal/reconcile"),
	}
	r.registerActuators(opts.Actuators)
	return r
}

// Start launches the scan loop and worker pool; it returns
// immediately. Cancel ctx (or call Stop) to shut down.
//
// Shutdown protocol (issue #28): the triggers channel is NEVER closed
// — closing it raced with in-flight Trigger() sends (data race /
// panic: close of closed channel). Workers exit via ctx.Done instead
// and the buffered channel is simply abandoned at shutdown.
func (r *Reconciler) Start(ctx context.Context) {
	r.baseCtx = ctx
	go r.loop(ctx)
	for i := 0; i < r.opts.Concurrency; i++ {
		go r.worker(ctx, i)
	}
	// The drift pass only exists when something can actuate; status-
	// only deployments keep the exact footprint they had before #80.
	if r.actuators.Len() > 0 {
		go r.driftLoop(ctx)
	}
	go func() {
		<-ctx.Done()
		close(r.done)
	}()
}

// Stop waits for graceful shutdown with a timeout.
func (r *Reconciler) Stop(timeout time.Duration) {
	select {
	case <-r.done:
	case <-time.After(timeout):
		r.log.Warn("reconciler stop timed out")
	}
}

// trigger is one queued reconcile request. sc, when valid, is the
// originating scan's span context (issue #83): the resource span then
// nests under the "reconcile.scan" span instead of rooting at the
// daemon context. Triggered-from-the-API requests carry no span
// context (Trigger keeps its ctx-free signature) and root at the
// daemon context.
type trigger struct {
	id string
	sc trace.SpanContext
}

// Trigger asks for an out-of-band reconcile of one resource by ID.
func (r *Reconciler) Trigger(id string) {
	r.send(trigger{id: id})
}

// send queues a reconcile request, dropping it (with a warning) when
// the bounded queue is full; recover keeps shutdown sends benign.
func (r *Reconciler) send(t trigger) {
	defer func() { _ = recover() }() // sending on closed channel during shutdown is benign
	select {
	case r.triggers <- t:
	default:
		r.log.Warn("trigger queue full, resource will be picked up on next scan", "id", t.id)
	}
}

// spanCtx returns the context reconcile spans attach to: the daemon
// context captured by Start (scans and reconciles are background work
// with no request parent, so spans root there — issue #83), or
// Background when called before Start (tests).
func (r *Reconciler) spanCtx() context.Context {
	if r.baseCtx != nil {
		return r.baseCtx
	}
	return context.Background()
}

func (r *Reconciler) loop(ctx context.Context) {
	t := time.NewTicker(r.opts.Interval)
	defer t.Stop()
	r.scan()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.scan()
		}
	}
}

func (r *Reconciler) worker(ctx context.Context, n int) {
	for {
		select {
		case <-ctx.Done():
			return
		case id, ok := <-r.triggers:
			if !ok {
				return
			}
			r.reconcileOne(id.id, "triggered", id.sc)
		}
	}
}

// scanPageLimit pins the page size to the store's hard clamp: both the
// reference memory store and pgstore silently reduce any Limit > 200
// to 50, so requesting more would not reduce round trips.
const scanPageLimit = 200

// maxScanPages is a hard bound on one scan's page walk. The primary
// guard against a pathological backend is the seen-cursor set below
// (mirroring the TS SDK listAll pattern); this bound is defense in
// depth against a backend that keeps minting fresh, never-repeating
// cursors. At 200 resources per page it allows two million resources
// per scan before deferring the rest to the next interval.
const maxScanPages = 10000

// scan queues every resource that has not fully converged yet:
// pending/provisioning phases, or a spec generation the status has
// not observed. The list is paged with the backend's next cursor
// until exhaustion (issue #37): the store clamps Limit to 200, so a
// single page silently capped the scan at the first 200 resources and
// anything beyond sat Pending forever. It also refreshes the
// ryvex_resources snapshot gauge and records the scan counter, scan
// duration and queue depth (issue #17).
func (r *Reconciler) scan() {
	start := time.Now()
	// Issue #83: one span per scan cycle, rooted at the daemon
	// context. It carries the pages-walked and triggers-queued counts
	// and is marked incomplete when the walk bails early.
	pages, triggered := 0, 0
	_, span := r.tracer.Start(r.spanCtx(), "reconcile.scan",
		trace.WithAttributes(attribute.Int("ryvex.reconcile.page_size", scanPageLimit)))
	defer func() {
		span.SetAttributes(
			attribute.Int("ryvex.reconcile.pages", pages),
			attribute.Int("ryvex.reconcile.triggered", triggered),
		)
		span.End()
		metrics.ReconcilerScansTotal.Inc()
		metrics.ReconcilerScanSeconds.Observe(time.Since(start).Seconds())
		metrics.ReconcilerQueueDepth.Set(float64(len(r.triggers)))
	}()

	// Refresh the ryvex_resources gauge from a lightweight store
	// snapshot so the gauge tracks kind/phase inventory without any
	// per-mutation bookkeeping. A failed snapshot is logged (issue
	// #71) and leaves the previous gauge values untouched.
	if _, err := metrics.ReconcileMetrics(r.store); err != nil {
		r.log.Error("resource metrics snapshot failed", "err", err)
	}

	// Walk every page, following the cursor chain until it is
	// exhausted (""). Guarded like the TS SDK listAll: a cursor we
	// have already followed means the backend is stuck, and the page
	// bound caps a walk that would otherwise never end. Behavior for
	// stores with <=200 resources is unchanged (a single page, next
	// cursor empty).
	seen := make(map[string]struct{}, 64)
	cursor := ""
	for ; pages < maxScanPages; pages++ {
		resources, next, err := r.store.ListResources(state.ListOptions{Limit: scanPageLimit, Cursor: cursor})
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, "scan failed")
			span.SetAttributes(attribute.Bool("ryvex.reconcile.scan_incomplete", true))
			r.log.Error("scan failed", "err", err)
			return
		}
		for _, res := range resources {
			if res.Status.ObservedGen < res.Generation ||
				res.Status.Phase == state.PhasePending ||
				res.Status.Phase == state.PhaseProvisioning {
				// The scan span stays open while its triggers are
				// queued (it closes after the walk), so resource
				// spans nest under it via the queued span context
				// (issue #83) even though workers run concurrently.
				r.send(trigger{id: res.ID, sc: span.SpanContext()})
				triggered++
				continue
			}
			// Actuated kinds in Degraded re-enter the retry schedule once
			// their backoff window has elapsed (issue #80); the per-resource
			// gate drops triggers that arrive early. Failed resources are
			// terminal for their generation and are never re-queued here.
			if res.Status.Phase == state.PhaseDegraded {
				if _, actuated := r.actuators.Lookup(res.Kind); actuated && r.attempts.due(res.ID, res.Generation) {
					r.send(trigger{id: res.ID, sc: span.SpanContext()})
					triggered++
				}
			}
		}
		if next == "" {
			return
		}
		if _, stuck := seen[next]; stuck {
			span.SetAttributes(attribute.Bool("ryvex.reconcile.scan_incomplete", true))
			r.log.Warn("scan pagination stuck: backend returned a repeated cursor; deferring the rest to the next scan",
				"pages", pages+1)
			return
		}
		seen[next] = struct{}{}
		cursor = next
	}
	span.SetAttributes(attribute.Bool("ryvex.reconcile.scan_incomplete", true))
	r.log.Warn("scan hit the page bound; remaining resources are deferred to the next scan",
		"pages", maxScanPages, "page_size", scanPageLimit)
}

func (r *Reconciler) reconcileOne(id, cause string, parent trace.SpanContext) {
	start := time.Now()
	defer func() { metrics.ReconcilerConvergeSeconds.Observe(time.Since(start).Seconds()) }()

	// Issue #83: one span per resource reconcile. It nests under the
	// originating scan span when queued by a scan (parent), and roots
	// at the daemon context otherwise (API-triggered, drift). It
	// carries the cause (scan/triggered/drift), the resource identity
	// and the phase the pass drove it to.
	base := r.spanCtx()
	if parent.IsValid() {
		base = trace.ContextWithSpanContext(base, parent)
	}
	_, span := r.tracer.Start(base, "reconcile.resource",
		trace.WithAttributes(
			attribute.String("ryvex.resource.id", id),
			attribute.String("ryvex.reconcile.cause", cause),
		))
	defer span.End()

	res, err := r.store.GetResource(id)
	if err != nil {
		return // deleted between scan and reconcile
	}
	span.SetAttributes(
		attribute.String("ryvex.resource.kind", res.Kind),
		attribute.Int64("ryvex.resource.generation", res.Generation),
		attribute.String("ryvex.resource.phase", res.Status.Phase),
	)

	// Actuated kinds take the provider path (issue #80): the actuator
	// owns Plan/Apply, and the guards inside decide whether this pass
	// should run at all. Everything below is the untouched status-only
	// flow for kinds without an actuator.
	if _, actuated := r.actuators.Lookup(res.Kind); actuated {
		r.reconcileActuated(res, cause)
		return
	}

	if res.Status.ObservedGen >= res.Generation &&
		res.Status.Phase != state.PhasePending &&
		res.Status.Phase != state.PhaseProvisioning {
		return // already converged
	}

	actor := state.WriteOptions{Actor: "reconciler", Reason: cause}
	switch res.Status.Phase {
	case state.PhasePending:
		_ = r.store.UpdateStatus(id, state.PhaseProvisioning, "provisioning underlying infrastructure", actor)
		span.SetAttributes(attribute.String("ryvex.reconcile.phase_to", state.PhaseProvisioning))
		r.emit(res, state.PhaseProvisioning)
	case state.PhaseProvisioning:
		phase, msg := r.evaluate(res)
		_ = r.store.UpdateStatus(id, phase, msg, actor)
		span.SetAttributes(attribute.String("ryvex.reconcile.phase_to", phase))
		r.emit(res, phase)
	default:
		_ = r.store.UpdateStatus(id, state.PhaseReady, "observed generation "+itoa(res.Generation), actor)
		span.SetAttributes(attribute.String("ryvex.reconcile.phase_to", state.PhaseReady))
		r.emit(res, state.PhaseReady)
	}
}

// evaluate decides the next phase for a provisioning resource. The
// reference policy converges everything to Ready; kinds like Secret
// converge immediately. Replace this hook with real controllers.
func (r *Reconciler) evaluate(res *state.Resource) (string, string) {
	if strings.EqualFold(res.Kind, state.KindSecret) {
		return state.PhaseReady, "secret sealed and mounted"
	}
	return state.PhaseReady, "converged to desired spec"
}

func (r *Reconciler) emit(res *state.Resource, phase string) {
	r.bus.Publish(bus.Event{
		Type:       bus.EventStatusChanged,
		Org:        res.Org,
		Project:    res.Project,
		Env:        res.Env,
		Kind:       res.Kind,
		Name:       res.Name,
		ResourceID: res.ID,
		Phase:      phase,
		Actor:      "reconciler",
	})
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
