// Package natsbus implements a durable Ryvex event bus on NATS
// JetStream (issue #15). It satisfies bus.BusI with the same
// constructor-level surface as the in-memory bus (internal/bus),
// reusing that package's Event type and Subject grammar 1:1:
//
//	stream  RYVEX  on  ryvex.resource.>
//
// Publishes are acknowledged by the server before Publish returns
// (at-least-once, persisted into the stream), subscriptions are core
// NATS deliveries of live events (no replay — parity with the memory
// bus), and Recent/RecentFrom replay history from the stream with a
// bounded 5000-message scan for safety.
package natsbus

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
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

// ScanCap bounds how many stream messages a single Recent/RecentFrom
// call will examine, so a huge stream can never stall the API.
const ScanCap = 5000

// fetchBatch is the per-round-trip pull size during stream scans.
const fetchBatch = 256

const (
	defaultMaxAge  = 24 * time.Hour
	defaultLimit   = 100
	publishTimeout = 5 * time.Second
	jsTimeout      = 5 * time.Second
	connectTimeout = 5 * time.Second
	// scanWait bounds each pull round-trip during Recent/RecentFrom
	// scans; the final (empty) fetch of a drained stream costs this
	// much, which keeps a scan bounded while publishing stays fast.
	scanWait = 200 * time.Millisecond
)

// Options configures the JetStream bus.
type Options struct {
	// MaxAge is the stream retention window (default 24h). Applied
	// when the stream is first created; an existing RYVEX stream is
	// reused with its server-side config untouched.
	MaxAge time.Duration

	// Storage selects JetStream storage: "" or "file" (default, makes
	// events survive nats-server restarts) or "memory".
	Storage string

	// Logger receives operational warnings (publish failures, inert
	// subscriptions). Nil falls back to slog.Default.
	Logger *slog.Logger
}

// Bus is the JetStream-backed event bus. Construct with New; satisfy
// bus.BusI and bus.Replayer.
type Bus struct {
	nc  *nats.Conn
	js  nats.JetStreamContext
	log *slog.Logger

	seq       atomic.Uint64 // local event-ID sequencing (parity with memory bus)
	closeOnce sync.Once
}

var (
	_ bus.BusI     = (*Bus)(nil)
	_ bus.Replayer = (*Bus)(nil)
)

// New connects to url, ensures the RYVEX stream exists and returns a
// ready bus. Any failure (dial, JetStream unavailable, bad options)
// is returned as an error so callers can fail at boot — the daemon
// never silently falls back to the memory bus once durability was
// requested.
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
	if err := ensureStream(js, opts); err != nil {
		nc.Close()
		return nil, fmt.Errorf("natsbus: ensure stream %s: %w", StreamName, err)
	}
	return &Bus{nc: nc, js: js, log: log}, nil
}

// ensureStream creates RYVEX when missing; an existing stream is kept
// as-is (the first daemon to boot owns the config).
func ensureStream(js nats.JetStreamContext, opts Options) error {
	storage := nats.FileStorage
	if opts.Storage == "memory" {
		storage = nats.MemoryStorage
	}
	maxAge := opts.MaxAge
	if maxAge <= 0 {
		maxAge = defaultMaxAge
	}
	_, err := js.StreamInfo(StreamName)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, nats.ErrStreamNotFound):
		_, err = js.AddStream(&nats.StreamConfig{
			Name:     StreamName,
			Subjects: []string{bus.SubjectNamespace + ".>"},
			MaxAge:   maxAge,
			Storage:  storage,
		})
		return err
	default:
		return err
	}
}

// Publish marshals the event to JSON and publishes it on its subject.
// The JetStream publish waits for the server ack (persisted) before
// returning; failures are logged and counted against delivery, never
// panic — Publish keeps the bus.BusI signature of the memory bus.
func (b *Bus) Publish(e bus.Event) {
	if e.Subject == "" {
		e.Subject = bus.Subject(e.Org, e.Kind, e.Type)
	}
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	if e.ID == "" {
		e.ID = fmt.Sprintf("evt-%d", b.seq.Add(1))
	}
	metrics.BusEventsPublishedTotal.WithLabelValues(eventTypeLabel(e.Type)).Inc()

	data, err := json.Marshal(e)
	if err != nil {
		b.log.Error("natsbus: marshal event failed", "subject", e.Subject, "err", err)
		return
	}
	if _, err := b.js.Publish(e.Subject, data, nats.AckWait(publishTimeout)); err != nil {
		b.log.Error("natsbus: publish failed", "subject", e.Subject, "err", err)
	}
}

// eventTypeLabel bounds metric cardinality for typeless events.
func eventTypeLabel(t string) string {
	if t == "" {
		return "unknown"
	}
	return t
}

// Subscription is a live NATS subscription handle.
type Subscription struct {
	ID      string
	Pattern string

	sub      *nats.Subscription
	canceled atomic.Bool
	once     sync.Once
}

// Cancel stops delivery immediately: the local flag suppresses any
// in-flight callback and the NATS subscription is removed (drain on
// the wire; publishes issued after Cancel returns on this connection
// are ordered after the UNSUB, so they are never delivered).
func (s *Subscription) Cancel() {
	s.canceled.Store(true)
	s.once.Do(func() {
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
