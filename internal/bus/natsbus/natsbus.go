// Package natsbus implements a durable Ryvex event bus on NATS
// JetStream (issue #15). It satisfies bus.BusI with the same
// constructor-level surface as the in-memory bus (internal/bus),
// reusing that package's Event type and Subject grammar 1:1:
//
//	stream  RYVEX      on  ryvex.resource.>
//	stream  RYVEX_DLQ  on  ryvex.dlq.>
//
// Publishes are acknowledged by the server before Publish/PublishErr
// returns (at-least-once, persisted into the stream); failed
// publishes return an error from PublishErr and increment
// ryvex_bus_publish_failures_total (issue #81). Subscriptions come in
// two flavors: plain Subscribe remains a core-NATS live delivery of
// new events (no replay — parity with the memory bus), while
// SubscribeDurable attaches a named, restart-idempotent JetStream
// pull consumer that delivers at-least-once with explicit acks,
// retries failed handlers (bus.ErrEventRetry) and dead-letters
// exhausted or poison events into RYVEX_DLQ with failure headers.
// Recent/RecentFrom replay history from the stream with a bounded
// 5000-message scan for safety.
package natsbus

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/Roy-Wanyoike/Ryvex/internal/bus"
	"github.com/Roy-Wanyoike/Ryvex/internal/metrics"
)

// StreamName is the JetStream stream carrying all Ryvex events.
const StreamName = "RYVEX"

// DLQStreamName is the JetStream stream that retains dead-lettered
// events (issue #81): events whose handler failed permanently (bus
// .ErrEventPoison) or exhausted the consumer's MaxDeliver budget.
// The original payload is republished verbatim on the DLQ subject so
// operators can inspect and re-drive it; failure metadata travels in
// the DLQHeader* headers.
const DLQStreamName = "RYVEX_DLQ"

// DLQSubjectPrefix is the subject namespace of the RYVEX_DLQ stream:
// dead-lettered messages are published on
// "ryvex.dlq.<RYVEX-stream-sequence>" so subjects are unique per
// dead-lettered event. It deliberately does not overlap the main
// stream's "ryvex.resource.>" filter.
const DLQSubjectPrefix = "ryvex.dlq"

// Headers attached to every dead-lettered message.
const (
	DLQHeaderReason    = "X-Ryvex-DLQ-Reason"     // poison | max_deliver
	DLQHeaderCause     = "X-Ryvex-DLQ-Cause"      // handler error text
	DLQHeaderStreamSeq = "X-Ryvex-DLQ-Stream-Seq" // RYVEX sequence of the original
	DLQHeaderConsumer  = "X-Ryvex-DLQ-Consumer"   // durable consumer that gave up
)

// Dead-letter reasons (the DLQHeaderReason header and the
// ryvex_bus_dlq_total metric label).
const (
	DLQReasonPoison     = "poison"      // permanent handler failure / undecodable payload
	DLQReasonMaxDeliver = "max_deliver" // retry budget exhausted
)

// ScanCap bounds how many stream messages a single Recent/RecentFrom
// call will examine, so a huge stream can never stall the API.
const ScanCap = 5000

// fetchBatch is the per-round-trip pull size during stream scans.
const fetchBatch = 256

const (
	defaultMaxAge     = 24 * time.Hour
	defaultDLQMaxAge  = 7 * 24 * time.Hour
	defaultMaxDeliver = 5
	defaultAckWait    = 30 * time.Second
	defaultLimit      = 100
	publishTimeout    = 5 * time.Second
	jsTimeout         = 5 * time.Second
	connectTimeout    = 5 * time.Second
	// scanWait bounds each pull round-trip during Recent/RecentFrom
	// scans; the final (empty) fetch of a drained stream costs this
	// much, which keeps a scan bounded while publishing stays fast.
	scanWait = 200 * time.Millisecond

	// Durable-consumer fetch loop tuning (issue #81): batches of 64
	// with a 1s wait keep the dispatcher latency low without hammering
	// the server when idle; a failed (non-timeout) fetch backs off
	// before the next attempt.
	durableBatchSize = 64
	durableFetchWait = time.Second
	durableErrorWait = 2 * time.Second
)

// Options configures the JetStream bus.
type Options struct {
	// MaxAge is the stream retention window (default 24h). Applied
	// when the stream is first created, and reconciled onto an existing
	// RYVEX stream when it differs (issue #81: config updates on
	// version change — the first daemon no longer freezes the config
	// forever).
	MaxAge time.Duration

	// Storage selects JetStream storage: "" or "file" (default, makes
	// events survive nats-server restarts) or "memory".
	Storage string

	// MaxDeliver caps how many times a durable consumer delivers one
	// message before dead-lettering it (default 5: one initial
	// delivery + 4 retries).
	MaxDeliver int

	// AckWait is the server-side ack timeout for durable consumers
	// (default 30s): a delivered message that is neither acked, nacked
	// nor terminated is redelivered once it elapses.
	AckWait time.Duration

	// DLQMaxAge is the retention window of the RYVEX_DLQ stream
	// (default 7 days), giving operators a week to inspect and re-drive
	// dead-lettered events.
	DLQMaxAge time.Duration

	// Logger receives operational warnings (publish failures, inert
	// subscriptions). Nil falls back to slog.Default.
	Logger *slog.Logger
}

// Bus is the JetStream-backed event bus. Construct with New; satisfy
// bus.BusI, bus.Replayer, bus.HealthChecker, bus.Publisher and
// bus.DurableSubscriber.
type Bus struct {
	nc  *nats.Conn
	js  nats.JetStreamContext
	log *slog.Logger

	maxDeliver int           // durable-consumer delivery budget
	ackWait    time.Duration // durable-consumer ack timeout
	dlqMaxAge  time.Duration // RYVEX_DLQ retention

	seq       atomic.Uint64 // local event-ID sequencing (parity with memory bus)
	closeOnce sync.Once
}

var (
	_ bus.BusI              = (*Bus)(nil)
	_ bus.Replayer          = (*Bus)(nil)
	_ bus.HealthChecker     = (*Bus)(nil)
	_ bus.Publisher         = (*Bus)(nil)
	_ bus.DurableSubscriber = (*Bus)(nil)
)

// Package-level instruments (issue #81), declared next to their only
// writer and registered on the shared dependency-free
// internal/metrics registry — the same pattern as the predefined
// instruments there.
var (
	// busPublishFailuresTotal counts publish attempts that failed to
	// reach JetStream persistence (marshal error, disconnect, server
	// rejection). Mid-outage publishes surface here and to the caller
	// via PublishErr instead of being silently dropped.
	busPublishFailuresTotal = metrics.Default.NewCounter(
		"ryvex_bus_publish_failures_total",
		"Bus publish attempts that failed to reach JetStream persistence (broker disconnect, server rejection, marshal error).")

	// busDLQTotal counts events dead-lettered into RYVEX_DLQ, by
	// reason (poison | max_deliver).
	busDLQTotal = metrics.Default.NewCounterVec(
		"ryvex_bus_dlq_total",
		"Events dead-lettered to the RYVEX_DLQ stream, by reason (poison | max_deliver).",
		"reason")
)

// New connects to url, ensures the RYVEX and RYVEX_DLQ streams exist
// (reconciling drifted configs) and returns a ready bus. Any failure
// (dial, JetStream unavailable, bad options) is returned as an error
// so callers can fail at boot — the daemon never silently falls back
// to the memory bus once durability was requested.
func New(url string, opts Options) (*Bus, error) {
	log := opts.Logger
	if log == nil {
		log = slog.Default()
	}
	log = log.With("component", "natsbus")

	switch opts.Storage {
	case "", "file", "memory":
	default:
		return nil, fmt.Errorf("natsbus: unsupported storage %q (want \"file\" or \"memory\")", opts.Storage)
	}

	storage := nats.FileStorage
	if opts.Storage == "memory" {
		storage = nats.MemoryStorage
	}
	maxAge := opts.MaxAge
	if maxAge <= 0 {
		maxAge = defaultMaxAge
	}
	dlqMaxAge := opts.DLQMaxAge
	if dlqMaxAge <= 0 {
		dlqMaxAge = defaultDLQMaxAge
	}
	maxDeliver := opts.MaxDeliver
	if maxDeliver <= 0 {
		maxDeliver = defaultMaxDeliver
	}
	ackWait := opts.AckWait
	if ackWait <= 0 {
		ackWait = defaultAckWait
	}

	nc, err := nats.Connect(url,
		nats.Name("ryvexd-bus"),
		nats.Timeout(connectTimeout),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(2*time.Second),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			if err != nil {
				log.Warn("nats connection lost; retrying", "err", err)
			}
		}),
		nats.ReconnectHandler(func(c *nats.Conn) {
			log.Info("nats connection re-established", "url", c.ConnectedUrl())
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("natsbus: connect %s: %w", url, err)
	}
	js, err := nc.JetStream(nats.MaxWait(jsTimeout))
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("natsbus: jetstream context: %w", err)
	}
	if err := ensureStream(js, StreamName, bus.SubjectNamespace+".>", maxAge, storage); err != nil {
		nc.Close()
		return nil, fmt.Errorf("natsbus: ensure stream %s: %w", StreamName, err)
	}
	if err := ensureStream(js, DLQStreamName, DLQSubjectPrefix+".>", dlqMaxAge, storage); err != nil {
		nc.Close()
		return nil, fmt.Errorf("natsbus: ensure stream %s: %w", DLQStreamName, err)
	}
	return &Bus{
		nc: nc, js: js, log: log,
		maxDeliver: maxDeliver,
		ackWait:    ackWait,
		dlqMaxAge:  dlqMaxAge,
	}, nil
}

// ensureStream creates the named stream when missing and reconciles
// an existing one onto the desired config (issue #81: previously a
// stream created by an old daemon version kept its config forever).
// Only the fields Ryvex owns (MaxAge, and the stream's coverage of
// its subject namespace) are updated; the update config is rebuilt
// from the live StreamInfo so operator-tuned fields (retention
// policy, replicas, ...) survive.
func ensureStream(js nats.JetStreamContext, name, subject string, maxAge time.Duration, storage nats.StorageType) error {
	si, err := js.StreamInfo(name)
	switch {
	case errors.Is(err, nats.ErrStreamNotFound):
		_, err = js.AddStream(&nats.StreamConfig{
			Name:     name,
			Subjects: []string{subject},
			MaxAge:   maxAge,
			Storage:  storage,
		})
		return err
	case err != nil:
		return err
	}
	cfg := si.Config
	drift := false
	if cfg.MaxAge != maxAge {
		cfg.MaxAge = maxAge
		drift = true
	}
	if !coversSubject(cfg.Subjects, subject) {
		cfg.Subjects = append(append([]string(nil), cfg.Subjects...), subject)
		drift = true
	}
	if drift {
		_, err = js.UpdateStream(&cfg)
	}
	return err
}

// coversSubject reports whether any of subjects already covers want —
// an exact match, or a superset trailing-">" wildcard. A narrower
// operator-configured list is not considered covering, so the daemon
// unions its namespace back in instead of clobbering the list.
func coversSubject(subjects []string, want string) bool {
	for _, s := range subjects {
		if s == want {
			return true
		}
		if strings.HasSuffix(s, ".>") {
			prefix := strings.TrimSuffix(s, ".>")
			if want == prefix || strings.HasPrefix(want, prefix+".") {
				return true
			}
		}
	}
	return false
}

// Publish marshals the event to JSON and publishes it on its subject.
// The JetStream publish waits for the server ack (persisted) before
// returning, and only that confirmed success advances the
// ryvex_bus_events_published_total counter (issue #40) — failed
// publishes must not pollute publish-rate alerting or SLOs. Publish
// keeps the bus.BusI signature of the memory bus (failures are logged
// and counted on ryvex_bus_publish_failures_total); callers that must
// observe the outcome use PublishErr.
//
// Metric contract (issue #109): both bus backends count
// ryvex_bus_events_published_total as "accepted by the bus for
// delivery", but their acceptance points differ by design. The
// in-memory bus has no persistence boundary and cannot fail, so it
// increments at the Publish call itself; this backend's acceptance
// gate is the JetStream persist ack, so it increments only after an
// event the stream actually retained. Publishes that fail to persist
// are counted on ryvex_bus_publish_failures_total, never on
// published_total.
func (b *Bus) Publish(e bus.Event) {
	_ = b.PublishErr(e)
}

// PublishErr is Publish with the outcome surfaced to the caller
// (issue #81): nil once the event is durably persisted into the
// stream, non-nil on marshal failure, disconnect or server rejection.
// Every failure increments ryvex_bus_publish_failures_total, so a
// mid-outage loss is visible in metrics even when callers ignore the
// error (plain Publish path). Only the nil-outcome path advances
// ryvex_bus_events_published_total (see Publish for the cross-backend
// contract, issue #109).
func (b *Bus) PublishErr(e bus.Event) error {
	if e.Subject == "" {
		e.Subject = bus.Subject(e.Org, e.Kind, e.Type)
	}
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	if e.ID == "" {
		e.ID = fmt.Sprintf("evt-%d", b.seq.Add(1))
	}

	data, err := json.Marshal(e)
	if err != nil {
		// Nothing was persisted, so the published counter must not move.
		busPublishFailuresTotal.Inc()
		err = fmt.Errorf("natsbus: marshal event %s: %w", e.Subject, err)
		b.log.Error("natsbus: marshal event failed", "subject", e.Subject, "err", err)
		return err
	}
	if _, err := b.js.Publish(e.Subject, data, nats.AckWait(publishTimeout)); err != nil {
		busPublishFailuresTotal.Inc()
		err = fmt.Errorf("natsbus: publish %s: %w", e.Subject, err)
		b.log.Error("natsbus: publish failed", "subject", e.Subject, "err", err)
		return err
	}
	metrics.BusEventsPublishedTotal.WithLabelValues(eventTypeLabel(e.Type)).Inc()
	return nil
}

// eventTypeLabel bounds metric cardinality for typeless events.
func eventTypeLabel(t string) string {
	if t == "" {
		return "unknown"
	}
	return t
}

// Subscription is a live NATS subscription handle (from Subscribe)
// or a durable JetStream consumer handle (from SubscribeDurable).
type Subscription struct {
	ID      string
	Pattern string

	sub      *nats.Subscription // core-NATS delivery (Subscribe)
	pull     *nats.Subscription // durable pull consumer (SubscribeDurable)
	done     chan struct{}      // closed on Cancel; wakes the durable fetch loop
	canceled atomic.Bool
	once     sync.Once
}

// Cancel stops delivery immediately: the local flag suppresses any
// in-flight callback and the NATS subscription (or durable fetch
// loop) is removed (drain on the wire; publishes issued after Cancel
// returns on this connection are ordered after the UNSUB, so they are
// never delivered). A durable consumer survives Cancel — it stays
// registered server-side so events published while no fetcher is
// attached are redelivered to the next SubscribeDurable with the same
// name (that is the at-least-once guarantee, issue #81).
func (s *Subscription) Cancel() {
	s.canceled.Store(true)
	s.once.Do(func() {
		if s.done != nil {
			close(s.done)
		}
		if s.pull != nil {
			_ = s.pull.Unsubscribe() // durable consumer is kept server-side
		}
		if s.sub != nil {
			_ = s.sub.Unsubscribe()
		}
	})
}

// Subscribe registers a handler for a NATS subject pattern. Our
// grammar maps 1:1 ("*" = one segment, trailing ">" = tail), so the
// pattern is used verbatim. Handlers are invoked asynchronously on
// NATS dispatcher goroutines; panics are contained. A pattern NATS
// rejects (or a closed connection) yields an inert subscription —
// parity with the memory bus, where any pattern is accepted and
// simply never matches.
func (b *Bus) Subscribe(pattern string, h bus.Handler) bus.Sub {
	if h == nil {
		return nil
	}
	sub := &Subscription{
		ID:      fmt.Sprintf("nsub-%d", b.seq.Add(1)),
		Pattern: pattern,
	}
	dispatch := func(m *nats.Msg) {
		if sub.canceled.Load() {
			return
		}
		var e bus.Event
		if err := json.Unmarshal(m.Data, &e); err != nil {
			b.log.Error("natsbus: undecodable event on stream", "subject", m.Subject, "err", err)
			return
		}
		if e.ID == "" {
			if md, err := m.Metadata(); err == nil {
				e.ID = fmt.Sprintf("evt-%d", md.Sequence.Stream)
			}
		}
		metrics.BusEventsDeliveredTotal.Inc()
		defer func() { _ = recover() }() // subscriber bugs must not kill the control plane
		h(e)
	}
	ns, err := b.nc.Subscribe(pattern, dispatch)
	if err != nil {
		b.log.Error("natsbus: subscribe failed; subscription is inert", "pattern", pattern, "err", err)
		return sub
	}
	sub.sub = ns
	return sub
}

// SubscribeDurable attaches h to a named, restart-idempotent JetStream
// pull consumer for events matching pattern (issue #81): at-least-once
// delivery with explicit acks, redelivery of handler failures
// (bus.ErrEventRetry and any other non-poison error) bounded by the
// consumer's MaxDeliver, and dead-lettering of exhausted or poison
// events (bus.ErrEventPoison, undecodable payloads) into RYVEX_DLQ.
//
// The durable name must be deterministic (e.g. RYVEX_DISPATCHER):
// restarts bind the SAME consumer, so events published while the
// process was down are delivered after it comes back. Consumer config
// drift (AckWait, MaxDeliver, filter) detected at subscribe time is
// reconciled via UpdateConsumer. A consumer created for the first time
// starts at the current stream tail — replaying pre-existing history
// to a fresh consumer would flood webhook receivers with old events on
// the first boot; from then on the consumer's own cursor provides
// resume-after-restart redelivery.
//
// The returned handle stops the fetch loop on Cancel (the server-side
// consumer is kept). Safe for concurrent use; multiple fetchers on the
// same durable (rolling deploy) split the work.
func (b *Bus) SubscribeDurable(durable, pattern string, h bus.DurableHandler) (bus.Sub, error) {
	if h == nil {
		return nil, errors.New("natsbus: nil durable handler")
	}
	if err := validateDurableName(durable); err != nil {
		return nil, err
	}
	if pattern == "" {
		return nil, errors.New("natsbus: empty durable subscription pattern")
	}
	if err := b.ensureConsumer(durable, pattern); err != nil {
		return nil, fmt.Errorf("natsbus: ensure durable consumer %s: %w", durable, err)
	}
	psub, err := b.js.PullSubscribe(pattern, durable, nats.Bind(StreamName, durable))
	if err != nil {
		return nil, fmt.Errorf("natsbus: bind durable consumer %s: %w", durable, err)
	}
	sub := &Subscription{
		ID:      "dsub-" + durable,
		Pattern: pattern,
		done:    make(chan struct{}),
		pull:    psub,
	}
	go b.durableLoop(sub, psub, h)
	return sub, nil
}

// validateDurableName enforces the deterministic-naming contract:
// a non-empty NATS subject token without wildcards or separators that
// would make DLQ subjects ambiguous. Names are caller-owned constants
// (e.g. RYVEX_DISPATCHER), never derived, so they survive restarts.
func validateDurableName(name string) error {
	if name == "" {
		return errors.New("natsbus: empty durable consumer name")
	}
	for _, r := range name {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z',
			r >= '0' && r <= '9', r == '_', r == '-':
		default:
			return fmt.Errorf("natsbus: durable consumer name %q must contain only [A-Za-z0-9_-]", name)
		}
	}
	return nil
}

// ensureConsumer creates the durable consumer when missing (starting
// at the stream tail) or reconciles the mutable config fields we own
// on drift (issue #81: UpdateConsumer on config change). Immutable
// fields (DeliverPolicy, AckPolicy, OptStartSeq) are left as-is.
func (b *Bus) ensureConsumer(durable, filter string) error {
	ci, err := b.js.ConsumerInfo(StreamName, durable)
	switch {
	case errors.Is(err, nats.ErrConsumerNotFound):
		cfg := b.consumerConfig(durable, filter)
		if si, serr := b.js.StreamInfo(StreamName); serr == nil {
			cfg.OptStartSeq = si.State.LastSeq + 1 // first boot: start "now"
		}
		_, err = b.js.AddConsumer(StreamName, &cfg)
		return err
	case err != nil:
		return err
	}
	want := b.consumerConfig(durable, filter)
	live := ci.Config
	if live.FilterSubject == want.FilterSubject &&
		live.AckWait == want.AckWait &&
		live.MaxDeliver == want.MaxDeliver {
		return nil
	}
	cfg := live // preserve operator-visible immutable fields
	cfg.FilterSubject = want.FilterSubject
	cfg.AckWait = want.AckWait
	cfg.MaxDeliver = want.MaxDeliver
	_, err = b.js.UpdateConsumer(StreamName, &cfg)
	return err
}

// consumerConfig is the desired config for a durable consumer.
func (b *Bus) consumerConfig(durable, filter string) nats.ConsumerConfig {
	return nats.ConsumerConfig{
		Durable:       durable,
		DeliverPolicy: nats.DeliverAllPolicy,
		AckPolicy:     nats.AckExplicitPolicy,
		AckWait:       b.ackWait,
		MaxDeliver:    b.maxDeliver,
		FilterSubject: filter,
	}
}

// durableLoop is the fetch-ack pump of one durable consumer: pull a
// batch, dispatch every message, repeat until canceled. Timeouts mean
// "drained"; other errors (reconnecting, consumer deleted) back off
// and retry — after a broker outage the loop picks up exactly where
// the consumer's cursor left off, which is the durability guarantee.
func (b *Bus) durableLoop(sub *Subscription, psub *nats.Subscription, h bus.DurableHandler) {
	for {
		if sub.canceled.Load() {
			return
		}
		msgs, err := psub.Fetch(durableBatchSize, nats.MaxWait(durableFetchWait))
		if err != nil {
			if errors.Is(err, nats.ErrTimeout) {
				continue // drained to the current end of the stream
			}
			if sub.canceled.Load() {
				return
			}
			if b.nc == nil || errors.Is(err, nats.ErrConnectionClosed) || b.nc.Status() == nats.CLOSED {
				return
			}
			b.log.Error("natsbus: durable fetch failed; retrying", "consumer", sub.ID, "err", err)
			select {
			case <-sub.done:
				return
			case <-time.After(durableErrorWait):
			}
			continue
		}
		for _, m := range msgs {
			if sub.canceled.Load() {
				return
			}
			b.dispatchDurable(durableNameOf(sub), m.Data, m, h)
		}
	}
}

// durableNameOf maps the subscription handle back to its deterministic
// consumer name (ID carries the "dsub-" prefix).
func durableNameOf(sub *Subscription) string {
	return strings.TrimPrefix(sub.ID, "dsub-")
}

// ackable is the subset of *nats.Msg the durable dispatch path needs.
// *nats.Msg satisfies it; unit tests substitute a fake (the Data and
// Subject fields of nats.Msg cannot be faked, so the payload travels
// alongside the handle).
type ackable interface {
	Ack(opts ...nats.AckOpt) error
	Nak(opts ...nats.AckOpt) error
	Term(opts ...nats.AckOpt) error
	Metadata() (*nats.MsgMetadata, error)
}

// dispatchDurable delivers one message to h and applies the failure
// taxonomy (issue #81): success acks explicitly; ErrEventPoison (and
// undecodable payloads, which would replay forever) dead-letters
// immediately; any other error naks for redelivery until the
// MaxDeliver budget is spent, then dead-letters. Handler panics are
// contained and treated as transient failures.
func (b *Bus) dispatchDurable(durable string, data []byte, m ackable, h bus.DurableHandler) {
	var e bus.Event
	if err := json.Unmarshal(data, &e); err != nil {
		b.deadLetter(durable, data, m, DLQReasonPoison, err)
		return
	}
	if e.ID == "" {
		if md, err := m.Metadata(); err == nil {
			e.ID = fmt.Sprintf("evt-%d", md.Sequence.Stream)
		}
	}
	metrics.BusEventsDeliveredTotal.Inc()
	var herr error
	func() {
		defer func() {
			if r := recover(); r != nil {
				herr = fmt.Errorf("natsbus: durable handler panic: %v", r)
			}
		}()
		herr = h(e)
	}()
	switch {
	case herr == nil:
		if aerr := m.Ack(); aerr != nil {
			b.log.Warn("natsbus: durable ack failed; server will redeliver", "consumer", durable, "err", aerr)
		}
	case errors.Is(herr, bus.ErrEventPoison):
		b.deadLetter(durable, data, m, DLQReasonPoison, herr)
	default:
		if md, err := m.Metadata(); err == nil && b.maxDeliver > 0 && md.NumDelivered >= uint64(b.maxDeliver) {
			b.deadLetter(durable, data, m, DLQReasonMaxDeliver, herr)
			return
		}
		_ = m.Nak() // transient failure: redeliver (immediately)
	}
}

// deadLetter republishes the original payload into RYVEX_DLQ with
// failure headers, then terminates the delivery. The DLQ subject is
// "ryvex.dlq.<stream-seq>", unique per dead-lettered event. If the
// DLQ publish itself fails on a poison event the delivery is nacked
// instead so the DLQ attempt is retried (bounded by MaxDeliver); on
// an exhausted budget there is nothing left to retry, so the message
// is terminated after a loud log + failure metric.
func (b *Bus) deadLetter(durable string, data []byte, m ackable, reason string, cause error) {
	seq := uint64(0)
	if md, err := m.Metadata(); err == nil {
		seq = md.Sequence.Stream
	}
	subject := fmt.Sprintf("%s.%d", DLQSubjectPrefix, seq)
	hdr := nats.Header{}
	hdr.Set(DLQHeaderReason, reason)
	if cause != nil {
		hdr.Set(DLQHeaderCause, cause.Error())
	}
	hdr.Set(DLQHeaderStreamSeq, strconv.FormatUint(seq, 10))
	hdr.Set(DLQHeaderConsumer, durable)
	msg := &nats.Msg{Subject: subject, Header: hdr, Data: data}
	if _, err := b.js.PublishMsg(msg); err != nil {
		busPublishFailuresTotal.Inc()
		b.log.Error("natsbus: dead-letter publish failed",
			"consumer", durable, "reason", reason, "stream_seq", seq, "err", err)
		if reason == DLQReasonPoison {
			_ = m.Nak() // retry the DLQ publish on redelivery
			return
		}
	} else {
		busDLQTotal.WithLabelValues(reason).Inc()
		b.log.Warn("natsbus: event dead-lettered",
			"consumer", durable, "reason", reason, "stream_seq", seq,
			"dlq_subject", subject, "cause", cause)
	}
	_ = m.Term() // terminal ack: no redelivery of a dead-lettered event
}

// Recent returns up to limit events for org (empty = all orgs),
// newest first. limit <= 0 falls back to 100 (memory-bus parity).
// The scan starts near the stream tail and examines at most ScanCap
// messages, server-side filtered to the org's subject prefix.
func (b *Bus) Recent(org string, limit int) ([]bus.Event, error) {
	if limit <= 0 {
		limit = defaultLimit
	}
	start := uint64(1)
	if si, err := b.js.StreamInfo(StreamName); err == nil && si.State.Msgs > ScanCap {
		start = si.State.Msgs - ScanCap + 1
	}
	newest, _, _, err := b.scan(org, uint64(limit), start, ScanCap)
	return newest, err
}

// RecentFrom returns up to limit events for org with stream sequence
// greater than from, newest first, together with the sequence callers
// should pass as from next time (last_seq). A scan examines at most
// ScanCap messages; last_seq always advances past everything seen, so
// cursor pagination never replays or skips.
func (b *Bus) RecentFrom(org string, limit int, from uint64) ([]bus.Event, uint64, error) {
	if limit <= 0 {
		limit = defaultLimit
	}
	if from == math.MaxUint64 {
		return []bus.Event{}, from, nil
	}
	newest, newestSeq, lastSeen, err := b.scan(org, uint64(limit), from+1, ScanCap)
	if err != nil {
		return nil, 0, err
	}
	last := lastSeen
	if len(newest) > 0 {
		last = newestSeq // resume exactly after the newest returned event
	}
	if last < from {
		last = from
	}
	return newest, last, nil
}

// scan replays the stream from startSeq (inclusive), server-side
// filtered to the org prefix, examining at most maxFetch messages. It
// returns up to keep matched events newest-first, the stream sequence
// of the newest match, and the highest sequence observed during the
// scan (0 when the stream had nothing at or after startSeq).
func (b *Bus) scan(org string, keep, startSeq, maxFetch uint64) (newest []bus.Event, newestSeq, lastSeen uint64, err error) {
	filter, err := orgFilter(org)
	if err != nil {
		return nil, 0, 0, err
	}
	sub, err := b.js.PullSubscribe(filter, "",
		nats.BindStream(StreamName),
		nats.StartSequence(startSeq),
	)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("natsbus: replay consumer: %w", err)
	}
	defer func() { _ = sub.Unsubscribe() }() // deletes the ephemeral consumer

	var matched []bus.Event
	lastMatchedSeq := uint64(0)
	fetched := uint64(0)
	for fetched < maxFetch {
		batch := uint64(fetchBatch)
		if remaining := maxFetch - fetched; remaining < batch {
			batch = remaining
		}
		msgs, ferr := sub.Fetch(int(batch), nats.MaxWait(scanWait))
		for _, m := range msgs {
			fetched++
			seq := uint64(0)
			if md, merr := m.Metadata(); merr == nil {
				seq = md.Sequence.Stream
				lastSeen = seq
				_ = m.Ack() // best-effort; the consumer is deleted right after
			}
			var e bus.Event
			if uerr := json.Unmarshal(m.Data, &e); uerr != nil {
				b.log.Warn("natsbus: skipping undecodable stream message", "subject", m.Subject, "err", uerr)
				continue
			}
			if e.ID == "" && seq > 0 {
				e.ID = fmt.Sprintf("evt-%d", seq)
			}
			matched = append(matched, e)
			lastMatchedSeq = seq
		}
		if ferr != nil {
			if errors.Is(ferr, nats.ErrTimeout) {
				break // drained to the current end of the stream
			}
			return nil, 0, lastSeen, fmt.Errorf("natsbus: replay fetch: %w", ferr)
		}
	}

	if uint64(len(matched)) > keep {
		matched = matched[len(matched)-int(keep):]
	}
	// Reverse the tail: scan order is oldest->newest, callers want
	// newest first.
	newest = make([]bus.Event, len(matched))
	for i, e := range matched {
		newest[len(matched)-1-i] = e
	}
	newestSeq = lastMatchedSeq
	return newest, newestSeq, lastSeen, nil
}

// orgFilter builds the server-side consumer filter for an org
// ("" = whole namespace). Orgs are single subject tokens; anything
// containing subject wildcards/dots cannot be expressed and is
// rejected rather than silently over-matching.
func orgFilter(org string) (string, error) {
	if org == "" {
		return bus.SubjectNamespace + ".>", nil
	}
	if strings.ContainsAny(org, ".*>") {
		return "", fmt.Errorf("natsbus: invalid org %q (must be a single subject token)", org)
	}
	return bus.SubjectNamespace + "." + org + ".>", nil
}

// Close unsubscribes everything and drains the connection. Safe to
// call more than once.
func (b *Bus) Close() error {
	var err error
	b.closeOnce.Do(func() { err = b.nc.Drain() })
	return err
}

// Healthy reports bus dependency health for /healthz and /readyz
// (issue #71): the JetStream bus is healthy only while its NATS
// connection is up. Any other state (reconnecting, closed, draining)
// is reported as unhealthy so /readyz can hold the pod out of
// rotation during a broker outage.
func (b *Bus) Healthy() error {
	if b.nc == nil {
		return fmt.Errorf("natsbus: no connection")
	}
	if st := b.nc.Status(); st != nats.CONNECTED {
		return fmt.Errorf("natsbus: connection status %s", st)
	}
	return nil
}
