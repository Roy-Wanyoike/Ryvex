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

// TestCancelStopsDeliveredMetric pins the delivered-counter half of
// issue #69: after a subscription is canceled, matching publishes must
// not move ryvex_bus_events_delivered_total at all — not even for the
// zombie entry the pre-fix wrong-element delete left behind (its nil
// handler was invoked, recovered at runHandler, but still counted as a
// delivery). A surviving subscriber on the same pattern proves the
// counter tracks exactly its live deliveries.
func TestCancelStopsDeliveredMetric(t *testing.T) {
	b := New()
	var survivor atomic.Int64
	b.Subscribe("ryvex.resource.cancelmetric.>", func(Event) { survivor.Add(1) })
	zombie := b.Subscribe("ryvex.resource.cancelmetric.>", func(Event) {})

	b.Publish(Event{Org: "cancelmetric", Kind: "Node", Type: EventDeleted})
	if survivor.Load() != 1 {
		t.Fatalf("precondition failed: survivor got %d deliveries", survivor.Load())
	}

	del0 := metrics.BusEventsDeliveredTotal.Value()
	zombie.Cancel()

	b.Publish(Event{Org: "cancelmetric", Kind: "Node", Type: EventDeleted})
	b.Publish(Event{Org: "cancelmetric", Kind: "Node", Type: EventDeleted})
	if survivor.Load() != 3 {
		t.Fatalf("survivor stopped receiving after the other sub was canceled: %d, want 3", survivor.Load())
	}
	if got := metrics.BusEventsDeliveredTotal.Value() - del0; got != 2 {
		t.Fatalf("delivered delta after cancel = %v, want 2 (only the survivor counts)", got)
	}
}

// TestCancelResubscribeChurn exercises subscribe/publish/cancel churn
// on one pattern and asserts no growth: every round delivers exactly
// once to a live handler, canceled rounds deliver nothing, the
// delivered counter advances only for live deliveries, and the bus
// ends with zero registered patterns (goroutine-free — the memory bus
// has no background workers, so map state is the full leak surface).
func TestCancelResubscribeChurn(t *testing.T) {
	b := New()
	pattern := "ryvex.resource.churn.>"
	const rounds = 200
	del0 := metrics.BusEventsDeliveredTotal.Value()

	for i := 0; i < rounds; i++ {
		var hits atomic.Int64
		sub := b.Subscribe(pattern, func(Event) { hits.Add(1) })
		b.Publish(Event{Org: "churn", Kind: "Node", Type: EventUpdated})
		if hits.Load() != 1 {
			t.Fatalf("round %d: %d deliveries to live subscription, want 1", i, hits.Load())
		}
		sub.Cancel()
		// Post-cancel publish: must be fully silent (no handler hit and
		// no delivered-counter movement, checked in aggregate below).
		b.Publish(Event{Org: "churn", Kind: "Node", Type: EventUpdated})
		if len(b.subs) != 0 {
			t.Fatalf("round %d: canceled pattern still registered (leak)", i)
		}
	}

	if got := metrics.BusEventsDeliveredTotal.Value() - del0; got != rounds {
		t.Fatalf("delivered delta over %d churn rounds = %v, want %d (canceled subscriptions must not count)", rounds, got, rounds)
	}
	if len(b.subs) != 0 {
		t.Fatalf("churn left %d registered patterns", len(b.subs))
	}
}
