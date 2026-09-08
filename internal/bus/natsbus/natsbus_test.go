package natsbus

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/Roy-Wanyoike/Ryvex/internal/bus"
	"github.com/Roy-Wanyoike/Ryvex/internal/bus/bustest"
	"github.com/Roy-Wanyoike/Ryvex/internal/metrics"
)

// testURL returns the live nats-server URL or skips. The full parity
// suite and the backend-specific tests below only run against a real
// nats-server (issue #15): start one and export
// RYVEX_TEST_NATS_URL=nats://127.0.0.1:18422 to exercise them.
func testURL(t *testing.T) string {
	t.Helper()
	url := os.Getenv("RYVEX_TEST_NATS_URL")
	if url == "" {
		t.Skip("RYVEX_TEST_NATS_URL not set; skipping live NATS JetStream tests")
	}
	return url
}

// newTestBus connects and hands back a bus over a PURGED stream, so
// every test sees a fresh event history (stream sequences keep
// advancing; expectations are derived from StreamInfo, not assumed).
func newTestBus(t *testing.T) *Bus {
	t.Helper()
	b, _ := newTestBusNoPurge(t)
	if err := b.js.PurgeStream(StreamName); err != nil {
		t.Fatalf("purge stream: %v", err)
	}
	return b
}

func newTestBusNoPurge(t *testing.T) (*Bus, string) {
	t.Helper()
	url := testURL(t)
	b, err := New(url, Options{MaxAge: time.Hour})
	if err != nil {
		t.Fatalf("New(%s): %v", url, err)
	}
	t.Cleanup(func() { _ = b.Close() })
	return b, url
}

// TestParitySuiteNATS runs the shared backend-parity suite against
// the live server. If this diverges from the in-memory bus, fix
// natsbus, not the suite.
func TestParitySuiteNATS(t *testing.T) {
	url := testURL(t)
	bustest.RunSuite(t, "natsbus", func(t *testing.T) (bustest.Bus, func()) {
		b, err := New(url, Options{MaxAge: time.Hour})
		if err != nil {
			t.Fatalf("New(%s): %v", url, err)
		}
		if err := b.js.PurgeStream(StreamName); err != nil {
			_ = b.Close()
			t.Fatalf("purge stream: %v", err)
		}
		done := func() { _ = b.Close() }
		t.Cleanup(done) // RunSuite also defers done; Close is idempotent
		return b, done
	}, bustest.SuiteOptions{})
}

func TestNewConnectFailure(t *testing.T) {
	if _, err := New("nats://127.0.0.1:1", Options{}); err == nil {
		t.Fatal("expected a connect error against a closed port")
	}
}

func TestOrgFilter(t *testing.T) {
	if f, err := orgFilter(""); err != nil || f != "ryvex.resource.>" {
		t.Fatalf("orgFilter(\"\") = %q, %v; want ryvex.resource.>, nil", f, err)
	}
	if f, err := orgFilter("acme"); err != nil || f != "ryvex.resource.acme.>" {
		t.Fatalf("orgFilter(acme) = %q, %v; want ryvex.resource.acme.>, nil", f, err)
	}
	for _, bad := range []string{"a.b", "*", ">", "acme.>"} {
		if _, err := orgFilter(bad); err == nil {
			t.Fatalf("orgFilter(%q) should reject wildcard/dotted orgs", bad)
		}
	}
}

func TestSubscribeInvalidPatternIsInert(t *testing.T) {
	b := newTestBus(t)
	var hits atomic.Int64
	sub := b.Subscribe("ryvex..bad", func(bus.Event) { hits.Add(1) })
	if sub == nil {
		t.Fatal("invalid pattern must still yield a usable (inert) subscription handle")
	}
	b.Publish(bus.Event{Org: "acme", Kind: "Node", Type: bus.EventCreated})
	time.Sleep(200 * time.Millisecond)
	if hits.Load() != 0 {
		t.Fatalf("inert subscription delivered %d events", hits.Load())
	}
	sub.Cancel() // must not panic
	if _, err := b.Recent("acme", 10); err != nil {
		t.Fatalf("bus unusable after inert subscribe: %v", err)
	}
}

func TestCloseIdempotent(t *testing.T) {
	b := newTestBus(t)
	if err := b.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := b.Close(); err != nil {
		t.Fatalf("second Close must be a no-op, got %v", err)
	}
}

// TestRecentFromSemantics pins the replay-cursor contract of
// bus.Replayer: from is exclusive, results are newest-first, and
// last_seq always advances past everything observed so callers can
// paginate without duplicates or gaps.
func TestRecentFromSemantics(t *testing.T) {
	b := newTestBus(t)
	for i := 0; i < 6; i++ {
		b.Publish(bus.Event{Org: "acme", Kind: "Deployment", Type: bus.EventCreated, Name: fmt.Sprintf("f%02d", i)})
	}
	si, err := b.js.StreamInfo(StreamName)
	if err != nil {
		t.Fatalf("stream info: %v", err)
	}
	if si.State.Msgs != 6 {
		t.Fatalf("stream has %d messages, want 6", si.State.Msgs)
	}
	last := si.State.LastSeq

	// from=0 replays the whole history, newest first.
	evts, seq, err := b.RecentFrom("acme", 100, 0)
	if err != nil {
		t.Fatalf("RecentFrom(0): %v", err)
	}
	if len(evts) != 6 || evts[0].Name != "f05" || evts[5].Name != "f00" {
		t.Fatalf("RecentFrom(0) = %d events, newest=%q oldest=%q; want 6, f05, f00", len(evts), evts[0].Name, evts[5].Name)
	}
	if seq != last {
		t.Fatalf("last_seq = %d, want %d", seq, last)
	}

	// from=last-3 resumes after that sequence: 3 events, newest first.
	evts, seq, err = b.RecentFrom("acme", 100, last-3)
	if err != nil {
		t.Fatalf("RecentFrom(last-3): %v", err)
	}
	if len(evts) != 3 || evts[0].Name != "f05" || evts[2].Name != "f03" {
		t.Fatalf("RecentFrom(last-3) = %d events; want f05,f04,f03", len(evts))
	}
	if seq != last {
		t.Fatalf("last_seq after resume = %d, want %d", seq, last)
	}

	// A from beyond the stream end returns nothing and echoes the
	// cursor forward.
	evts, seq, err = b.RecentFrom("acme", 100, last+100)
	if err != nil {
		t.Fatalf("RecentFrom(last+100): %v", err)
	}
	if len(evts) != 0 || seq != last+100 {
		t.Fatalf("RecentFrom(last+100) = %d events, last_seq=%d; want 0, %d", len(evts), seq, last+100)
	}

	// limit truncates but last_seq still advances to the newest match,
	// so the next page (from=last_seq) continues without overlap.
	evts, seq, err = b.RecentFrom("acme", 2, 0)
	if err != nil {
		t.Fatalf("RecentFrom(0, limit=2): %v", err)
	}
	if len(evts) != 2 || evts[0].Name != "f05" || evts[1].Name != "f04" {
		t.Fatalf("RecentFrom(0, limit=2) = %v; want f05,f04", evts)
	}
	if seq != last {
		t.Fatalf("last_seq with truncation = %d, want %d", seq, last)
	}

	// Org filter is server-side: other orgs stay invisible.
	b.Publish(bus.Event{Org: "globex", Kind: "Node", Type: bus.EventUpdated, Name: "foreign"})
	evts, seq, err = b.RecentFrom("acme", 100, 0)
	if err != nil {
		t.Fatalf("RecentFrom(acme): %v", err)
	}
	for _, e := range evts {
		if e.Org != "acme" {
			t.Fatalf("org filter leaked event from %q", e.Org)
		}
	}
	if seq != last { // the globex publish is newer but filtered out
		t.Fatalf("acme last_seq = %d, want %d (filtered events must not move the cursor)", seq, last)
	}
}

// stubJS stands in for nats.JetStreamContext in Publish-path unit
// tests. Only Publish is wired up; the embedded nil interface makes
// any other JetStream call panic loudly instead of silently passing,
// so a test fails fast if natsbus ever uses an unstubbed method.
type stubJS struct {
	nats.JetStreamContext
	pub func(subject string, data []byte, opts ...nats.PubOpt) (*nats.PubAck, error)
}

func (s *stubJS) Publish(subject string, data []byte, opts ...nats.PubOpt) (*nats.PubAck, error) {
	return s.pub(subject, data, opts...)
}

// TestPublishMetricCountsOnlyConfirmedSuccess pins issue #40: the
// ryvex_bus_events_published_total counter advances only after the
// JetStream publish is acknowledged by the server. A failed publish
// must leave the counter untouched (the metric feeds publish-rate
// alerting and SLOs) and must surface in the error log.
func TestPublishMetricCountsOnlyConfirmedSuccess(t *testing.T) {
	label := eventTypeLabel(bus.EventCreated)
	published := metrics.BusEventsPublishedTotal.WithLabelValues(label)
	before := published.Value()

	// Success path: server acks -> counter increments exactly once.
	var gotSubject string
	var gotData []byte
	okBus := &Bus{
		js: &stubJS{pub: func(subject string, data []byte, _ ...nats.PubOpt) (*nats.PubAck, error) {
			gotSubject, gotData = subject, data
			return &nats.PubAck{Stream: StreamName, Sequence: 1}, nil
		}},
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	okBus.Publish(bus.Event{Org: "acme", Kind: "Node", Type: bus.EventCreated, Name: "n1"})

	if want := before + 1; published.Value() != want {
		t.Fatalf("after acked publish, ryvex_bus_events_published_total{type=%q} = %v, want %v", label, published.Value(), want)
	}
	if want := bus.Subject("acme", "Node", bus.EventCreated); gotSubject != want {
		t.Fatalf("published subject = %q, want %q", gotSubject, want)
	}
	if len(gotData) == 0 {
		t.Fatal("published payload is empty")
	}

	// Failure path: server refuses the publish -> counter unchanged,
	// failure logged (the only failure signal until internal/metrics
	// grows a publish-failure instrument).
	var logBuf bytes.Buffer
	failBus := &Bus{
		js: &stubJS{pub: func(string, []byte, ...nats.PubOpt) (*nats.PubAck, error) {
			return nil, errors.New("nats: no responders")
		}},
		log: slog.New(slog.NewTextHandler(&logBuf, nil)),
	}
	failBus.Publish(bus.Event{Org: "acme", Kind: "Node", Type: bus.EventCreated, Name: "n2"})

	if want := before + 1; published.Value() != want {
		t.Fatalf("failed publish moved ryvex_bus_events_published_total{type=%q}: %v, want %v", label, published.Value(), want)
	}
	logs := logBuf.String()
	for _, want := range []string{"natsbus: publish failed", "subject=", "nats: no responders"} {
		if !strings.Contains(logs, want) {
			t.Fatalf("failed-publish log missing %q; got:\n%s", want, logs)
		}
	}
}
