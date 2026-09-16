package reconcile

// Tracing tests (issue #83): a scan cycle emits one "reconcile.scan"
// span and each resource reconcile one "reconcile.resource" span,
// rooted at the context Start was called with.

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/Roy-Wanyoike/Ryvex/internal/state"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func findSpan(exp *tracetest.InMemoryExporter, name string) *tracetest.SpanStub {
	spans := exp.GetSpans()
	for i := range spans {
		if spans[i].Name == name {
			return &spans[i]
		}
	}
	return nil
}

func spanAttr(s *tracetest.SpanStub, key string) string {
	for _, kv := range s.Attributes {
		if string(kv.Key) == key {
			return kv.Value.AsString()
		}
	}
	return ""
}

func TestScanAndReconcileSpans(t *testing.T) {
	exp := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exp))
	defer func() { _ = tp.Shutdown(context.Background()) }()

	store, b := mkStore(t)
	res, err := store.CreateResource(mkRes("Application", "traced"), state.WriteOptions{Actor: "test"})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	rec := New(store, b, Options{
		Interval:       20 * time.Millisecond, // repeated scans drive Pending -> Provisioning -> Ready
		Concurrency:    2,
		Logger:         discardLogger(),
		TracerProvider: tp,
	})
	ctx, cancel := context.WithCancel(context.Background())
	rec.Start(ctx)
	defer rec.Stop(2 * time.Second)
	defer cancel()

	waitPhase(t, store, res.ID, state.PhaseReady)

	// The resource span that drove the resource to Ready must exist and
	// must nest under the scan span that queued its trigger (issue #83
	// span tree: reconcile.scan -> reconcile.resource).
	var ready *tracetest.SpanStub
	var parentScan *tracetest.SpanStub
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		spans := exp.GetSpans()
		for i := range spans {
			s := &spans[i]
			if s.Name == "reconcile.resource" && spanAttr(s, "ryvex.resource.id") == res.ID &&
				spanAttr(s, "ryvex.reconcile.phase_to") == state.PhaseReady {
				ready = s
			}
			if s.Name == "reconcile.scan" && ready != nil && s.SpanContext.SpanID() == ready.Parent.SpanID() {
				parentScan = s
			}
		}
		if ready != nil && parentScan != nil {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if ready == nil {
		t.Fatal("reconcile.resource span with phase_to=ready missing")
	}
	if parentScan == nil {
		t.Fatal("reconcile.resource span does not nest under a reconcile.scan span")
	}

	// Cause attribute and trace coherence.
	if got := spanAttr(ready, "ryvex.reconcile.cause"); got != "triggered" {
		t.Errorf("reconcile.resource cause = %q, want %q", got, "triggered")
	}
	if ready.SpanContext.TraceID() != parentScan.SpanContext.TraceID() {
		t.Errorf("resource span trace %s != scan span trace %s",
			ready.SpanContext.TraceID(), parentScan.SpanContext.TraceID())
	}

	// The scan span reports the triggers it queued.
	triggered := int64(0)
	for _, kv := range parentScan.Attributes {
		if string(kv.Key) == "ryvex.reconcile.triggered" {
			triggered = kv.Value.AsInt64()
		}
	}
	if triggered < 1 {
		t.Errorf("reconcile.scan triggered attr = %d, want >= 1", triggered)
	}
}
