package reconcile

import (
	"context"
	"log/slog"
	"regexp"
	"testing"
	"time"

	"github.com/Roy-Wanyoike/Ryvex/internal/metrics"
	"github.com/Roy-Wanyoike/Ryvex/internal/state"
)

// TestMetricsRecordedOnScan verifies the issue #17 instruments on the
// default registry: the scan counter advances on each tick, the
// converge histogram observes the resource pass, the queue-depth
// gauge carries a sample after a scan, and the ryvex_resources
// snapshot gauge reflects the store inventory.
func TestMetricsRecordedOnScan(t *testing.T) {
	store, b := mkStore(t)
	res, err := store.CreateResource(mkRes(state.KindApplication, "metrics-demo"), state.WriteOptions{Actor: "test"})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	scans0 := metrics.ReconcilerScansTotal.Value()
	conv0 := metrics.ReconcilerConvergeSeconds.Count()
	scanDur0 := metrics.ReconcilerScanSeconds.Count()

	rec := New(store, b, Options{Interval: 15 * time.Millisecond, Concurrency: 2, Logger: slog.Default()})
	ctx, cancel := context.WithCancel(context.Background())
	rec.Start(ctx)
	defer rec.Stop(2 * time.Second)
	defer cancel()

	waitPhase(t, store, res.ID, state.PhaseReady)

	// Wait for the initial scan plus at least one ticker scan.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && metrics.ReconcilerScansTotal.Value() < scans0+2 {
		time.Sleep(5 * time.Millisecond)
	}
	if got := metrics.ReconcilerScansTotal.Value(); got < scans0+2 {
		t.Fatalf("scan counter did not advance: got %v, want >= %v", got, scans0+2)
	}
	if got := metrics.ReconcilerScanSeconds.Count(); got <= scanDur0 {
		t.Fatalf("scan duration histogram not observed: count %v <= %v", got, scanDur0)
	}
	if got := metrics.ReconcilerConvergeSeconds.Count(); got <= conv0 {
		t.Fatalf("converge histogram not observed: count %v <= %v", got, conv0)
	}

	out := string(metrics.Default.Gather())

	// Queue-depth gauge carries at least one sample line (not just the
	// HELP/TYPE header).
	qdRe := regexp.MustCompile(`(?m)^ryvex_reconciler_queue_depth(\{[^}]*\})? [-+0-9.eE]+`)
	if !qdRe.MatchString(out) {
		t.Fatalf("queue depth gauge has no sample line:\n%s", out)
	}

	// Resources snapshot gauge reflects the store: an Application
	// series exists (phase may be Pending..Ready depending on scan
	// timing, so only assert the kind dimension).
	resRe := regexp.MustCompile(`(?m)^ryvex_resources\{kind="Application",phase="[A-Za-z]+"\} [0-9]+`)
	if !resRe.MatchString(out) {
		t.Fatalf("resources gauge has no Application sample:\n%s", out)
	}
}
