package metrics

import (
	"net/http"
	"sync"
)

// Default is the process-wide registry the Ryvex control plane
// instruments. Instruments are registered once at package init and
// only updated afterwards; the registry does no background work and
// only renders output when a scrape calls Gather.
var Default = NewRegistry()

// Predefined control-plane instruments (issue #17).
var (
	// HTTPRequestsTotal counts HTTP requests by normalized route
	// bucket, method and response status code.
	HTTPRequestsTotal = Default.NewCounterVec(
		"ryvex_http_requests_total",
		"HTTP requests handled by the control plane, by normalized route, method and status.",
		"route", "method", "status",
	)

	// HTTPRequestDuration times HTTP requests by route and method.
	HTTPRequestDuration = Default.NewHistogramVec(
		"ryvex_http_request_duration_seconds",
		"HTTP request duration in seconds, by normalized route and method.",
		[]float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5},
		"route", "method",
	)

	// Resources tracks how many resources sit in each kind/phase
	// pair. It is a periodic snapshot: the reconciler refreshes it
	// from a store scan (see ReconcileMetrics), so it lags mutations
	// by at most one scan interval.
	Resources = Default.NewGaugeVec(
		"ryvex_resources",
		"Resources tracked in the store, by kind and lifecycle phase (refreshed on each reconciler scan).",
		"kind", "phase",
	)

	// ReconcilerScansTotal counts reconciler store scans.
	ReconcilerScansTotal = Default.NewCounter(
		"ryvex_reconciler_scans_total",
		"Reconciler scans performed.",
	)

	// ReconcilerScanSeconds times whole reconciler scans.
	ReconcilerScanSeconds = Default.NewHistogram(
		"ryvex_reconciler_scan_seconds",
		"Duration of reconciler scans in seconds.",
		[]float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1},
	)

	// ReconcilerConvergeSeconds times single-resource reconcile
	// passes (one observation per reconcileOne call).
	ReconcilerConvergeSeconds = Default.NewHistogram(
		"ryvex_reconciler_converge_seconds",
		"Duration of single-resource reconcile passes in seconds.",
		[]float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5},
	)

	// ReconcilerQueueDepth samples the trigger queue length after
	// each scan; sustained growth means the reconciler cannot keep up.
	ReconcilerQueueDepth = Default.NewGauge(
		"ryvex_reconciler_queue_depth",
		"Reconcile triggers waiting in the queue, sampled after each scan.",
	)

	// BusEventsPublishedTotal counts events published to the bus by
	// event type (created/updated/deleted/status_changed).
	BusEventsPublishedTotal = Default.NewCounterVec(
		"ryvex_bus_events_published_total",
		"Events published to the bus, by event type.",
		"type",
	)

	// BusEventsDeliveredTotal counts handler invocations: one
	// increment per event handed to a subscriber.
	BusEventsDeliveredTotal = Default.NewCounter(
		"ryvex_bus_events_delivered_total",
		"Event deliveries to subscriber handlers (one increment per handler invocation).",
	)
)

// Handler serves the default registry; mount it at /metrics.
func Handler() http.Handler { return Default.Handler() }

// ResourceCounter is the minimal read view of the resource store the
// metrics snapshot needs. *state.Store satisfies it; the tiny
// interface keeps this package free of internal imports.
type ResourceCounter interface {
	CountByKindPhase() map[string]map[string]int64
}

// ReconcileMetrics refreshes the ryvex_resources gauge from a store
// snapshot. The reconciler calls it once per scan. Pairs that
// disappear from the snapshot are zeroed (not deleted), so resource
// deletions are reflected without churning series. It returns the
// number of live kind/phase pairs in the snapshot.
func ReconcileMetrics(rc ResourceCounter) int {
	snap := rc.CountByKindPhase()

	resourcesMu.Lock()
	defer resourcesMu.Unlock()

	for key := range lastResourceSnapshot {
		if _, ok := snap[key[0]][key[1]]; !ok {
			Resources.WithLabelValues(key[0], key[1]).Set(0)
		}
	}
	live := 0
	for kind, phases := range snap {
		for phase, n := range phases {
			Resources.WithLabelValues(kind, phase).Set(float64(n))
			if lastResourceSnapshot == nil {
				lastResourceSnapshot = make(map[[2]string]struct{})
			}
			lastResourceSnapshot[[2]string{kind, phase}] = struct{}{}
			live++
		}
	}
	return live
}

var (
	resourcesMu          sync.Mutex
	lastResourceSnapshot map[[2]string]struct{}
)
