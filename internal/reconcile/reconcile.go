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
	"github.com/Roy-Wanyoike/Ryvex/internal/state"
)

// Options configures the reconciler loop.
type Options struct {
	Interval    time.Duration // scan cadence
	Concurrency int           // worker count
	Scopes      [][2]string   // namespaces the platform controls, e.g. {"org","project"}
	Namespaces  []string      // env namespaces considered in-scope
	Logger      *slog.Logger
}

// Reconciler scans the store on a fixed interval and progresses
// resource phases. It is safe for concurrent use.
type Reconciler struct {
	store state.Backend
	bus   bus.BusI
	opts  Options
	log   *slog.Logger

	triggers chan string
	stopOnce sync.Once
	done     chan struct{}
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
	return &Reconciler{
		store:    store,
		bus:      b,
		opts:     opts,
		log:      opts.Logger.With("component", "reconciler"),
		triggers: make(chan string, 128),
		done:     make(chan struct{}),
	}
}

// Start launches the scan loop and worker pool; it returns
// immediately. Cancel ctx (or call Stop) to shut down.
//
// Shutdown protocol (issue #28): the triggers channel is NEVER closed
// — closing it raced with in-flight Trigger() sends (data race /
// panic: close of closed channel). Workers exit via ctx.Done instead
// and the buffered channel is simply abandoned at shutdown.
func (r *Reconciler) Start(ctx context.Context) {
	go r.loop(ctx)
	for i := 0; i < r.opts.Concurrency; i++ {
		go r.worker(ctx, i)
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

// Trigger asks for an out-of-band reconcile of one resource by ID.
func (r *Reconciler) Trigger(id string) {
	defer func() { _ = recover() }() // sending on closed channel during shutdown is benign
	select {
	case r.triggers <- id:
	default:
		r.log.Warn("trigger queue full, resource will be picked up on next scan", "id", id)
	}
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
			r.reconcileOne(id, "triggered")
		}
	}
}

// scan queues every resource that has not fully converged yet:
// pending/provisioning phases, or a spec generation the status has
// not observed. It also refreshes the ryvex_resources snapshot gauge
// and records the scan counter, scan duration and queue depth
// (issue #17).
func (r *Reconciler) scan() {
	start := time.Now()
	defer func() {
		metrics.ReconcilerScansTotal.Inc()
		metrics.ReconcilerScanSeconds.Observe(time.Since(start).Seconds())
		metrics.ReconcilerQueueDepth.Set(float64(len(r.triggers)))
	}()

	// Refresh the ryvex_resources gauge from a lightweight store
	// snapshot so the gauge tracks kind/phase inventory without any
	// per-mutation bookkeeping.
	metrics.ReconcileMetrics(r.store)

	resources, _, err := r.store.ListResources(state.ListOptions{Limit: 200})
	if err != nil {
		r.log.Error("scan failed", "err", err)
		return
	}
	for _, res := range resources {
		if res.Status.ObservedGen < res.Generation ||
			res.Status.Phase == state.PhasePending ||
			res.Status.Phase == state.PhaseProvisioning {
			r.Trigger(res.ID)
		}
	}
}

func (r *Reconciler) reconcileOne(id, cause string) {
	start := time.Now()
	defer func() { metrics.ReconcilerConvergeSeconds.Observe(time.Since(start).Seconds()) }()

	res, err := r.store.GetResource(id)
	if err != nil {
		return // deleted between scan and reconcile
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
		r.emit(res, state.PhaseProvisioning)
	case state.PhaseProvisioning:
		phase, msg := r.evaluate(res)
		_ = r.store.UpdateStatus(id, phase, msg, actor)
		r.emit(res, phase)
	default:
		_ = r.store.UpdateStatus(id, state.PhaseReady, "observed generation "+itoa(res.Generation), actor)
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
