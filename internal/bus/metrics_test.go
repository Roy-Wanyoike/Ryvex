package bus

import (
	"sync/atomic"
	"testing"

	"github.com/Roy-Wanyoike/Ryvex/internal/metrics"
)

func TestMetricsPublishedAndDelivered(t *testing.T) {
	// Default-registry counters are shared across the package's tests,
	// so assert on deltas around the publishes below.
	pubCreated0 := metrics.BusEventsPublishedTotal.WithLabelValues(EventCreated).Value()
	pubUpdated0 := metrics.BusEventsPublishedTotal.WithLabelValues(EventUpdated).Value()
	del0 := metrics.BusEventsDeliveredTotal.Value()

	b := New()
	var hits atomic.Int64
	sub := b.Subscribe("ryvex.resource.metrics.*.created", func(Event) { hits.Add(1) })

	b.Publish(Event{Org: "metrics", Kind: "Application", Type: EventCreated})
	b.Publish(Event{Org: "metrics", Kind: "Application", Type: EventCreated})
	b.Publish(Event{Org: "metrics", Kind: "Application", Type: EventUpdated})

	if hits.Load() != 2 {
		t.Fatalf("handler hits = %d, want 2", hits.Load())
	}
	if got := metrics.BusEventsPublishedTotal.WithLabelValues(EventCreated).Value() - pubCreated0; got != 2 {
		t.Fatalf("published{created} delta = %v, want 2", got)
	}
	if got := metrics.BusEventsPublishedTotal.WithLabelValues(EventUpdated).Value() - pubUpdated0; got != 1 {
		t.Fatalf("published{updated} delta = %v, want 1", got)
	}
	if got := metrics.BusEventsDeliveredTotal.Value() - del0; got != 2 {
		t.Fatalf("delivered delta = %v, want 2 (one per handler invocation)", got)
	}
	sub.Cancel()

	// Publishing with no subscribers counts the publish but no delivery.
	pubDeleted0 := metrics.BusEventsPublishedTotal.WithLabelValues(EventDeleted).Value()
	del1 := metrics.BusEventsDeliveredTotal.Value()
	b.Publish(Event{Org: "metrics", Kind: "Bucket", Type: EventDeleted})
	if got := metrics.BusEventsPublishedTotal.WithLabelValues(EventDeleted).Value() - pubDeleted0; got != 1 {
		t.Fatalf("published{deleted} delta = %v, want 1", got)
	}
	if got := metrics.BusEventsDeliveredTotal.Value() - del1; got != 0 {
		t.Fatalf("delivered delta without subscribers = %v, want 0", got)
	}

	// An event without an explicit type is counted under "unknown" so
	// the metric's cardinality stays bounded.
	unk0 := metrics.BusEventsPublishedTotal.WithLabelValues("unknown").Value()
	b.Publish(Event{Org: "metrics", Kind: "Secret"})
	if got := metrics.BusEventsPublishedTotal.WithLabelValues("unknown").Value() - unk0; got != 1 {
		t.Fatalf("published{unknown} delta = %v, want 1", got)
	}
}
