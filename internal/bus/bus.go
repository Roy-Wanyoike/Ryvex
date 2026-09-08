// Package bus implements the Ryvex in-process event bus. Every state
// mutation is published with a NATS-style subject so downstream
// components (reconciler, webhooks, console streams) can subscribe to
// exactly the slice of the world they care about.
package bus

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/Roy-Wanyoike/Ryvex/internal/metrics"
)

// SubjectNamespace is the root of every Ryvex event subject.
const SubjectNamespace = "ryvex.resource"

// Event types emitted by the control plane.
const (
	EventCreated       = "created"
	EventUpdated       = "updated"
	EventDeleted       = "deleted"
	EventStatusChanged = "status_changed"
)

// Event is a single occurrence on the bus.
type Event struct {
	ID         string         `json:"id"`
	Time       time.Time      `json:"time"`
	Type       string         `json:"type"` // created | updated | deleted | status_changed
	Subject    string         `json:"subject"`
	Org        string         `json:"org"`
	Project    string         `json:"project"`
	Env        string         `json:"env"`
	Kind       string         `json:"kind"`
	Name       string         `json:"name"`
	ResourceID string         `json:"resource_id"`
	Generation int64          `json:"generation"`
	Phase      string         `json:"phase,omitempty"`
	Actor      string         `json:"actor,omitempty"`
	Data       map[string]any `json:"data,omitempty"`
}

// Subject builds the canonical subject for an event:
// ryvex.resource.{org}.{kind}.{type}
func Subject(org, kind, eventType string) string {
	return strings.Join([]string{SubjectNamespace, org, strings.ToLower(kind), eventType}, ".")
}

// Handler processes events synchronously inside Publish.
type Handler func(Event)

// Sub is a live bus subscription handle; Cancel removes it so no
// further events are delivered. *Bus.Subscription and
// *natsbus.Subscription both satisfy it.
type Sub interface {
	Cancel()
}

// BusI is the minimal event-bus surface control-plane components
// depend on. The in-memory *Bus and the durable *natsbus.Bus
// (JetStream, issue #15) both satisfy it, so callers (API handlers,
// reconciler, webhook dispatcher, daemon wiring) stay backend-agnostic.
type BusI interface {
	// Publish fans an event out to matching subscribers.
	Publish(e Event)
	// Recent returns up to limit recent events for org (empty = all
	// orgs), newest first.
	Recent(org string, limit int) ([]Event, error)
	// Subscribe registers a handler for a subject pattern
	// ("*" = one segment, trailing ">" = tail). Subscriptions created
	// after a Publish see only later events; use Recent/RecentFrom for
	// history.
	Subscribe(pattern string, h Handler) Sub
}

// Replayer is the optional capability of a bus that can replay by
// stream sequence (issue #15). The in-memory bus does not implement
// it; *natsbus.Bus does. Callers detect it with a type assertion.
type Replayer interface {
	// RecentFrom returns up to limit events for org with stream
	// sequence greater than from, newest first, plus the highest
	// sequence observed so callers can resume with from=last_seq.
	RecentFrom(org string, limit int, from uint64) ([]Event, uint64, error)
}

// Subscription ties a handler to a subject pattern.
type Subscription struct {
	ID      string
	Pattern string
	handler Handler
	bus     *Bus
}

// Cancel removes the subscription from the bus.
func (s *Subscription) Cancel() {
	if s.bus == nil {
		return
	}
	s.bus.mu.Lock()
	defer s.bus.mu.Unlock()
	subs := s.bus.subs[s.Pattern]
	for i, x := range subs {
		if x.ID == s.ID {
			s.bus.subs[s.Pattern] = append(subs[:i], subs[:i+1]...)
			break
		}
	}
	if len(s.bus.subs[s.Pattern]) == 0 {
		delete(s.bus.subs, s.Pattern)
	}
	s.bus = nil
	s.handler = nil
}

// Bus is a synchronous pub/sub with a bounded replay ring per query.
type Bus struct {
	mu   sync.RWMutex
	subs map[string][]*Subscription
	ring []Event // newest last, capped
	next uint64
}

// RingSize is how many recent events are retained for replay.
const RingSize = 1024

// New creates an empty bus.
func New() *Bus {
	return &Bus{subs: map[string][]*Subscription{}}
}

// Subscribe registers a handler for a subject pattern. Patterns use
// "*" to match exactly one segment, e.g.
//
//	ryvex.resource.acme.*.created
//
// The declared return type is the bus.Sub interface so *Bus and
// *natsbus.Bus share the bus.BusI surface (issue #15); the returned
// value is always this bus's *Subscription.
func (b *Bus) Subscribe(pattern string, h Handler) Sub {
	if h == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.next++
	sub := &Subscription{
		ID:      fmt.Sprintf("sub-%d", b.next),
		Pattern: pattern,
		handler: h,
		bus:     b,
	}
	b.subs[pattern] = append(b.subs[pattern], sub)
	return sub
}

// Publish fans an event out to all matching subscribers and records
// it in the replay ring. Handler panics are contained. Publishes and
// deliveries are counted on the ryvex_bus_events_* metrics
// (issue #17); the counters are mutex-guarded and independent of the
// bus lock, so instrumentation adds no contention.
func (b *Bus) Publish(e Event) {
	if e.Subject == "" {
		e.Subject = Subject(e.Org, e.Kind, e.Type)
	}
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	metrics.BusEventsPublishedTotal.WithLabelValues(eventTypeLabel(e.Type)).Inc()

	b.mu.Lock()
	b.next++
	e.ID = fmt.Sprintf("evt-%d", b.next)
	b.ring = append(b.ring, e)
	if len(b.ring) > RingSize {
		b.ring = b.ring[len(b.ring)-RingSize:]
	}
	// Copy matching handlers under the lock so Cancel races are safe.
	var handlers []Handler
	for pattern, subs := range b.subs {
		if match(pattern, e.Subject) {
			for _, s := range subs {
				handlers = append(handlers, s.handler)
			}
		}
	}
	b.mu.Unlock()

	for _, h := range handlers {
		metrics.BusEventsDeliveredTotal.Inc()
		runHandler(h, e)
	}
}

// eventTypeLabel keeps the published-events metric cardinality
// bounded even when an event is published without an explicit type.
func eventTypeLabel(t string) string {
	if t == "" {
		return "unknown"
	}
	return t
}

func runHandler(h Handler, e Event) {
	defer func() { _ = recover() }() // subscriber bugs must not kill the control plane
	h(e)
}

// Match reports whether subject satisfies pattern. Both are
// dot-separated; "*" matches exactly one segment and a trailing ">"
// matches one or more remaining segments (NATS-style).
//
// Exported so components that filter events without a bus
// subscription (e.g. the webhook dispatcher) reuse the exact same
// grammar as Subscribe/Publish.
func Match(pattern, subject string) bool {
	pt := strings.Split(pattern, ".")
	st := strings.Split(subject, ".")
	for i := 0; i < len(pt); i++ {
		if pt[i] == ">" {
			return i < len(st) // ">" consumes at least one segment
		}
		if i >= len(st) {
			return false
		}
		if pt[i] != "*" && pt[i] != st[i] {
			return false
		}
	}
	return len(pt) == len(st)
}

// match is the internal alias kept for readability at the Publish
// call site; it delegates to the exported Match.
func match(pattern, subject string) bool {
	return Match(pattern, subject)
}

// Recent returns up to limit most recent events, newest first,
// optionally filtered by org. limit <= 0 falls back to 100. The
// error is always nil; it exists so the in-memory bus and the
// JetStream bus (issue #15) share the BusI signature.
func (b *Bus) Recent(org string, limit int) ([]Event, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if limit <= 0 || limit > RingSize {
		limit = 100
	}
	out := make([]Event, 0, limit)
	for i := len(b.ring) - 1; i >= 0 && len(out) < limit; i-- {
		e := b.ring[i]
		if org == "" || e.Org == org {
			out = append(out, e)
		}
	}
	return out, nil
}
