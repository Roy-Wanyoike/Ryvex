package bus

import (
	"sync/atomic"
	"testing"
)

func TestSubjectFormat(t *testing.T) {
	got := Subject("acme", "Deployment", EventCreated)
	want := "ryvex.resource.acme.deployment.created"
	if got != want {
		t.Fatalf("subject = %q, want %q", got, want)
	}
}

func TestPubSubSingleSegmentWildcard(t *testing.T) {
	b := New()
	var hits atomic.Int64
	b.Subscribe("ryvex.resource.acme.*.created", func(Event) { hits.Add(1) })

	b.Publish(Event{Org: "acme", Kind: "Application", Type: EventCreated})
	b.Publish(Event{Org: "acme", Kind: "Bucket", Type: EventCreated})
	b.Publish(Event{Org: "acme", Kind: "Application", Type: EventDeleted}) // wrong type
	b.Publish(Event{Org: "globex", Kind: "Application", Type: EventCreated})

	if hits.Load() != 2 {
		t.Fatalf("want 2 deliveries, got %d", hits.Load())
	}
}

func TestPubSubTailWildcard(t *testing.T) {
	b := New()
	var hits atomic.Int64
	b.Subscribe("ryvex.resource.>", func(Event) { hits.Add(1) })

	b.Publish(Event{Org: "acme", Kind: "Node", Type: EventUpdated})
	b.Publish(Event{Org: "globex", Kind: "Secret", Type: EventStatusChanged})
	if hits.Load() != 2 {
		t.Fatalf("tail wildcard should match everything under namespace, got %d", hits.Load())
	}
}

func TestSubscriptionCancel(t *testing.T) {
	b := New()
	var hits atomic.Int64
	sub := b.Subscribe("ryvex.resource.acme.>", func(Event) { hits.Add(1) })
	b.Publish(Event{Org: "acme", Kind: "Node", Type: EventDeleted})
	sub.Cancel()
	b.Publish(Event{Org: "acme", Kind: "Node", Type: EventDeleted})
	if hits.Load() != 1 {
		t.Fatalf("cancel failed: %d deliveries", hits.Load())
	}
}

func TestHandlerPanicContained(t *testing.T) {
	b := New()
	var good atomic.Int64
	b.Subscribe("ryvex.resource.a.>", func(Event) { panic("subscriber bug") })
	b.Subscribe("ryvex.resource.a.>", func(Event) { good.Add(1) })
	b.Publish(Event{Org: "a", Kind: "Node", Type: EventCreated})
	if good.Load() != 1 {
		t.Fatalf("panic in one subscriber must not block others")
	}
}

func TestRecentRing(t *testing.T) {
	b := New()
	for i := 0; i < RingSize+50; i++ {
		b.Publish(Event{Org: "acme", Kind: "Node", Type: EventUpdated})
	}
	evts, _ := b.Recent("acme", 10)
	if len(evts) != 10 {
		t.Fatalf("want 10 events, got %d", len(evts))
	}
	if len(b.ring) > RingSize {
		t.Fatalf("ring overflowed: %d", len(b.ring))
	}
	none, _ := b.Recent("globex", 10)
	if len(none) != 0 {
		t.Fatalf("org filter failed: %d", len(none))
	}
}
