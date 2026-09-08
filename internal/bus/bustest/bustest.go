// Package bustest holds the backend-parity suite for Ryvex event
// buses (issue #15). Every bus backend that satisfies bus.BusI must
// pass the same behavioral scenarios: the in-memory bus runs them
// always (see internal/bus), the JetStream bus runs them against a
// live nats-server when RYVEX_TEST_NATS_URL is set (see
// internal/bus/natsbus). If the two backends ever drift, the suite
// fails and natsbus gets fixed — not the suite.
//
// Delivery timing: the in-memory bus dispatches synchronously inside
// Publish; the NATS backend delivers asynchronously. The suite is
// therefore written against eventual delivery (bounded polling), so
// a single scenario set exercises both backends unmodified.
package bustest

import (
	"fmt"
	"testing"
	"time"

	"github.com/Roy-Wanyoike/Ryvex/internal/bus"
)

// Bus is the minimal surface the parity suite drives. It mirrors the
// consumer-facing slice of bus.BusI; both *bus.Bus and
// *natsbus.Bus satisfy it.
type Bus interface {
	Publish(e bus.Event)
	Subscribe(pattern string, h bus.Handler) bus.Sub
	Recent(org string, limit int) ([]bus.Event, error)
}

// Factory builds a fresh, empty bus for one subtest. The returned
// cleanup func is invoked via defer.
type Factory func(t *testing.T) (Bus, func())

// SuiteOptions toggles backend-specific scenarios.
type SuiteOptions struct {
	// RingCap runs the 1126-event capacity scenario: after 1126
	// publishes, at most RingSize (1024) events remain queryable.
	// Only meaningful for the ring-shaped in-memory bus — JetStream
	// retention is time-based, not ring-based — so natsbus leaves it
	// off and its limit semantics are covered by the recent tests.
	RingCap bool
}

// deliveryTimeout bounds eventual-delivery waits. Generous enough for
// a CI nats-server on localhost; memory backends never wait.
const deliveryTimeout = 5 * time.Second

// quietAfter is how long a "no more deliveries" assertion observes
// the bus before concluding silence (cancel / non-matching cases).
const quietAfter = 400 * time.Millisecond

// waitFor polls until cond is true or the deadline passes.
func waitFor(cond func() bool) bool {
	deadline := time.Now().Add(deliveryTimeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return cond()
}

// settle sleeps long enough for an async backend to have delivered
// everything published before it (used to observe *absence*).
func settle() { time.Sleep(quietAfter) }

// counter is a thread-safe delivery hit counter.
type counter struct {
	ch chan struct{}
}

func newCounter() *counter {
	return &counter{ch: make(chan struct{}, 4096)}
}

func (c *counter) hit(bus.Event) {
	select {
	case c.ch <- struct{}{}:
	default:
	}
}

func (c *counter) n() int { return len(c.ch) }

// markerName gives each published event a queryable identity.
func markerName(i int) string { return fmt.Sprintf("m%04d", i) }

// publishMarkers publishes n events alternating org acme/globex with
// distinct names, all kind Deployment type created.
func publishMarkers(b Bus, n int) {
	for i := 0; i < n; i++ {
		org := "acme"
		if i%2 == 1 {
			org = "globex"
		}
		b.Publish(bus.Event{
			Org:  org,
			Kind: "Deployment",
			Type: bus.EventCreated,
			Name: markerName(i),
		})
	}
}

// RunSuite executes the full parity scenario set against a freshly
// constructed bus backend. newBus must return an empty bus; the
// returned cleanup func is deferred by every subtest. Each subtest
// gets its own bus instance.
func RunSuite(t *testing.T, name string, newBus Factory, opts SuiteOptions) {
	t.Helper()

	t.Run(name+"/subject_format_and_exact_match", func(t *testing.T) {
		b, done := newBus(t)
		defer done()
		hits := newCounter()
		b.Subscribe("ryvex.resource.acme.deployment.created", hits.hit)

		// Implicit subject construction from org/kind/type must yield
		// the canonical subject.
		b.Publish(bus.Event{Org: "acme", Kind: "Deployment", Type: bus.EventCreated})
		if !waitFor(func() bool { return hits.n() == 1 }) {
			t.Fatalf("canonical subject not delivered: hits=%d", hits.n())
		}

		b.Publish(bus.Event{Org: "globex", Kind: "Deployment", Type: bus.EventCreated})
		b.Publish(bus.Event{Org: "acme", Kind: "Bucket", Type: bus.EventCreated})
		b.Publish(bus.Event{Org: "acme", Kind: "Deployment", Type: bus.EventDeleted})
		settle()
		if hits.n() != 1 {
			t.Fatalf("non-matching publishes leaked: hits=%d, want 1", hits.n())
		}
	})

	t.Run(name+"/wildcard_single_segment", func(t *testing.T) {
		b, done := newBus(t)
		defer done()
		hits := newCounter()
		b.Subscribe("ryvex.resource.acme.*.created", hits.hit)

		b.Publish(bus.Event{Org: "acme", Kind: "Application", Type: bus.EventCreated})
		b.Publish(bus.Event{Org: "acme", Kind: "Bucket", Type: bus.EventCreated})
		b.Publish(bus.Event{Org: "acme", Kind: "Application", Type: bus.EventDeleted})   // wrong type
		b.Publish(bus.Event{Org: "globex", Kind: "Application", Type: bus.EventCreated}) // wrong org
		if !waitFor(func() bool { return hits.n() == 2 }) {
			t.Fatalf("want 2 deliveries, got %d", hits.n())
		}
		settle()
		if hits.n() != 2 {
			t.Fatalf("wildcard over-matched: hits=%d, want 2", hits.n())
		}
	})

	t.Run(name+"/wildcard_tail", func(t *testing.T) {
		b, done := newBus(t)
		defer done()
		hits := newCounter()
		b.Subscribe("ryvex.resource.>", hits.hit)

		b.Publish(bus.Event{Org: "acme", Kind: "Node", Type: bus.EventUpdated})
		b.Publish(bus.Event{Org: "globex", Kind: "Secret", Type: bus.EventStatusChanged})
		if !waitFor(func() bool { return hits.n() == 2 }) {
			t.Fatalf("tail wildcard should match everything under the namespace, got %d", hits.n())
		}
	})

	t.Run(name+"/cancel_stops_delivery", func(t *testing.T) {
		b, done := newBus(t)
		defer done()
		hits := newCounter()
		sub := b.Subscribe("ryvex.resource.acme.>", hits.hit)
		if sub == nil {
			t.Fatal("Subscribe returned nil subscription")
		}

		b.Publish(bus.Event{Org: "acme", Kind: "Node", Type: bus.EventDeleted})
		if !waitFor(func() bool { return hits.n() == 1 }) {
			t.Fatalf("initial delivery missing: hits=%d", hits.n())
		}

		sub.Cancel()
		b.Publish(bus.Event{Org: "acme", Kind: "Node", Type: bus.EventDeleted})
		settle()
		if hits.n() != 1 {
			t.Fatalf("cancel failed: %d deliveries, want 1", hits.n())
		}
	})

	t.Run(name+"/panic_containment", func(t *testing.T) {
		b, done := newBus(t)
		defer done()
		good := newCounter()
		b.Subscribe("ryvex.resource.a.>", func(bus.Event) { panic("subscriber bug") })
		b.Subscribe("ryvex.resource.a.>", good.hit)

		b.Publish(bus.Event{Org: "a", Kind: "Node", Type: bus.EventCreated})
		if !waitFor(func() bool { return good.n() == 1 }) {
			t.Fatalf("panic in one subscriber blocked or starved the other: hits=%d", good.n())
		}
	})

	t.Run(name+"/recent_newest_first_limit_org", func(t *testing.T) {
		b, done := newBus(t)
		defer done()
		// 10 events: acme m0 m2 m4 m6 m8, globex m1 m3 m5 m7 m9.
		publishMarkers(b, 10)

		acme, err := b.Recent("acme", 3)
		if err != nil {
			t.Fatalf("Recent(acme,3): %v", err)
		}
		if len(acme) != 3 {
			t.Fatalf("Recent(acme,3) len=%d, want 3", len(acme))
		}
		// Newest first: the last three acme publishes are m8, m6, m4.
		for i, want := range []string{"m0008", "m0006", "m0004"} {
			if acme[i].Name != want {
				t.Fatalf("Recent(acme,3)[%d].Name=%q, want %q (order must be newest first)", i, acme[i].Name, want)
			}
			if acme[i].Org != "acme" {
				t.Fatalf("org filter leaked: got org=%q", acme[i].Org)
			}
		}

		// limit <= 0 falls back to the default (100): all five acme events.
		all, err := b.Recent("acme", 0)
		if err != nil {
			t.Fatalf("Recent(acme,0): %v", err)
		}
		if len(all) != 5 || all[0].Name != "m0008" || all[4].Name != "m0000" {
			t.Fatalf("Recent(acme,0) = %d events, first=%q last=%q; want 5, m0008, m0000", len(all), all[0].Name, all[4].Name)
		}

		globex, err := b.Recent("globex", 10)
		if err != nil {
			t.Fatalf("Recent(globex,10): %v", err)
		}
		if len(globex) != 5 || globex[0].Name != "m0009" {
			t.Fatalf("Recent(globex,10) = %d events, newest=%q; want 5, m0009", len(globex), globex[0].Name)
		}

		none, err := b.Recent("initech", 10)
		if err != nil {
			t.Fatalf("Recent(initech,10): %v", err)
		}
		if len(none) != 0 {
			t.Fatalf("unknown org should return nothing, got %d", len(none))
		}

		mixed, err := b.Recent("", 4)
		if err != nil {
			t.Fatalf("Recent(\"\",4): %v", err)
		}
		if len(mixed) != 4 {
			t.Fatalf("Recent(\"\",4) len=%d, want 4", len(mixed))
		}
		for i, want := range []string{"m0009", "m0008", "m0007", "m0006"} {
			if mixed[i].Name != want {
				t.Fatalf("Recent(\"\",4)[%d].Name=%q, want %q (global newest first)", i, mixed[i].Name, want)
			}
		}
	})

	t.Run(name+"/recent_empty", func(t *testing.T) {
		b, done := newBus(t)
		defer done()
		evts, err := b.Recent("acme", 10)
		if err != nil {
			t.Fatalf("Recent on empty bus: %v", err)
		}
		if len(evts) != 0 {
			t.Fatalf("empty bus returned %d events", len(evts))
		}
	})

	if opts.RingCap {
		t.Run(name+"/ring_cap", func(t *testing.T) {
			b, done := newBus(t)
			defer done()
			// 1126 publishes (ring 1024) must drop the oldest 102.
			publishMarkers(b, 1126)
			evts, err := b.Recent("", 1024)
			if err != nil {
				t.Fatalf("Recent: %v", err)
			}
			if len(evts) != 1024 {
				t.Fatalf("want exactly 1024 retained events, got %d", len(evts))
			}
			// Newest first: first is m1125 (last publish overall),
			// oldest retained event is m0102.
			if evts[0].Name != markerName(1125) || evts[len(evts)-1].Name != markerName(102) {
				t.Fatalf("ring cap dropped wrong events: newest=%q oldest=%q, want %q/%q",
					evts[0].Name, evts[len(evts)-1].Name, markerName(1125), markerName(102))
			}
		})
	}
}
