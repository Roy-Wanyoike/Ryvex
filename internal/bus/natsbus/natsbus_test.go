package natsbus

import (
	"bytes"
	"encoding/json"
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

// ---- issue #81 unit tests: durable consumers, DLQ, publish failures ----
//
// These run WITHOUT a nats-server: JetStream is a big interface, so the
// stubs below embed it (any unstubbed call panics loudly, same fail-fast
// policy as stubJS) and implement only what the code under test uses.

// streamStub stands in for stream management (ensureStream).
type streamStub struct {
	nats.JetStreamContext
	info    *nats.StreamInfo
	infoErr error

	added   *nats.StreamConfig
	updated *nats.StreamConfig
}

func (s *streamStub) StreamInfo(name string, _ ...nats.JSOpt) (*nats.StreamInfo, error) {
	if s.infoErr != nil {
		return nil, s.infoErr
	}
	if s.info != nil {
		si := *s.info
		si.Config.Name = name
		return &si, nil
	}
	return nil, nats.ErrStreamNotFound
}

func (s *streamStub) AddStream(cfg *nats.StreamConfig, _ ...nats.JSOpt) (*nats.StreamInfo, error) {
	s.added = cfg
	return &nats.StreamInfo{Config: *cfg}, nil
}

func (s *streamStub) UpdateStream(cfg *nats.StreamConfig, _ ...nats.JSOpt) (*nats.StreamInfo, error) {
	s.updated = cfg
	return &nats.StreamInfo{Config: *cfg}, nil
}

// TestEnsureStreamCreatesMissing asserts the create path.
func TestEnsureStreamCreatesMissing(t *testing.T) {
	js := &streamStub{}
	err := ensureStream(js, StreamName, bus.SubjectNamespace+".>", time.Hour, nats.FileStorage)
	if err != nil {
		t.Fatalf("ensureStream: %v", err)
	}
	if js.added == nil || js.updated != nil {
		t.Fatalf("missing stream must be created, not updated: added=%v updated=%v", js.added, js.updated)
	}
	if js.added.Name != StreamName || js.added.MaxAge != time.Hour || js.added.Storage != nats.FileStorage {
		t.Fatalf("created config = %+v", js.added)
	}
	if len(js.added.Subjects) != 1 || js.added.Subjects[0] != "ryvex.resource.>" {
		t.Fatalf("created subjects = %v", js.added.Subjects)
	}
}

// TestEnsureStreamReconcilesDrift pins issue #81's stream-config
// acceptance: an existing stream whose MaxAge or subject coverage
// drifted from the desired config is updated; operator-tuned fields
// (retention policy, replicas) are preserved because the update is
// rebuilt from the live config; a matching stream is left untouched.
func TestEnsureStreamReconcilesDrift(t *testing.T) {
	// Matching config: no update.
	js := &streamStub{info: &nats.StreamInfo{Config: nats.StreamConfig{
		Name: StreamName, MaxAge: time.Hour, Subjects: []string{"ryvex.resource.>"},
		Retention: nats.LimitsPolicy, Replicas: 3,
	}}}
	if err := ensureStream(js, StreamName, bus.SubjectNamespace+".>", time.Hour, nats.FileStorage); err != nil {
		t.Fatalf("ensureStream(matching): %v", err)
	}
	if js.updated != nil {
		t.Fatalf("matching stream must not be updated, got %+v", js.updated)
	}

	// MaxAge drift + narrowed subject list: update restores both and
	// keeps operator fields.
	js2 := &streamStub{info: &nats.StreamInfo{Config: nats.StreamConfig{
		Name: StreamName, MaxAge: time.Hour, Subjects: []string{"ryvex.resource.acme.>"},
		Retention: nats.InterestPolicy, Replicas: 1,
	}}}
	if err := ensureStream(js2, StreamName, bus.SubjectNamespace+".>", 24*time.Hour, nats.FileStorage); err != nil {
		t.Fatalf("ensureStream(drifted): %v", err)
	}
	if js2.updated == nil {
		t.Fatal("drifted stream must be updated")
	}
	if js2.updated.MaxAge != 24*time.Hour {
		t.Fatalf("updated MaxAge = %v, want 24h", js2.updated.MaxAge)
	}
	if !coversSubject(js2.updated.Subjects, "ryvex.resource.>") {
		t.Fatalf("updated subjects %v lost namespace coverage", js2.updated.Subjects)
	}
	if !coversSubject(js2.updated.Subjects, "ryvex.resource.acme.>") {
		t.Fatalf("updated subjects %v clobbered operator list", js2.updated.Subjects)
	}
	if js2.updated.Retention != nats.InterestPolicy || js2.updated.Replicas != 1 {
		t.Fatalf("operator-tuned fields not preserved: %+v", js2.updated)
	}
}

func TestCoversSubject(t *testing.T) {
	for _, tc := range []struct {
		subjects []string
		want     string
		covered  bool
	}{
		{[]string{"ryvex.resource.>"}, "ryvex.resource.>", true},
		{[]string{"ryvex.>"}, "ryvex.resource.>", true},
		{[]string{"ryvex.resource.acme.>"}, "ryvex.resource.>", false}, // narrower is not covering
		{nil, "ryvex.resource.>", false},
	} {
		if got := coversSubject(tc.subjects, tc.want); got != tc.covered {
			t.Fatalf("coversSubject(%v, %q) = %v, want %v", tc.subjects, tc.want, got, tc.covered)
		}
	}
}

// consumerStub stands in for consumer management (ensureConsumer).
type consumerStub struct {
	nats.JetStreamContext
	info    *nats.ConsumerInfo
	infoErr error

	lastSeq uint64

	added   *nats.ConsumerConfig
	updated *nats.ConsumerConfig
}

func (s *consumerStub) ConsumerInfo(_, name string, _ ...nats.JSOpt) (*nats.ConsumerInfo, error) {
	if s.infoErr != nil {
		return nil, s.infoErr
	}
	if s.info != nil {
		ci := *s.info
		ci.Name = name
		return &ci, nil
	}
	return nil, nats.ErrConsumerNotFound
}

func (s *consumerStub) StreamInfo(_ string, _ ...nats.JSOpt) (*nats.StreamInfo, error) {
	return &nats.StreamInfo{State: nats.StreamState{LastSeq: s.lastSeq}}, nil
}

func (s *consumerStub) AddConsumer(_ string, cfg *nats.ConsumerConfig, _ ...nats.JSOpt) (*nats.ConsumerInfo, error) {
	s.added = cfg
	return &nats.ConsumerInfo{Config: *cfg}, nil
}

func (s *consumerStub) UpdateConsumer(_ string, cfg *nats.ConsumerConfig, _ ...nats.JSOpt) (*nats.ConsumerInfo, error) {
	s.updated = cfg
	return &nats.ConsumerInfo{Config: *cfg}, nil
}

func testDurableBus(js nats.JetStreamContext) *Bus {
	return &Bus{
		js:         js,
		log:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		maxDeliver: 3,
		ackWait:    30 * time.Second,
	}
}

// TestEnsureConsumerCreatesAtTail asserts creation: explicit-ack,
// deterministic durable name, desired budget, and OptStartSeq pinned
// at the stream tail so a first-ever boot does not replay history.
func TestEnsureConsumerCreatesAtTail(t *testing.T) {
	js := &consumerStub{lastSeq: 41}
	b := testDurableBus(js)
	if err := b.ensureConsumer("RYVEX_DISPATCHER", "ryvex.resource.>"); err != nil {
		t.Fatalf("ensureConsumer: %v", err)
	}
	if js.added == nil || js.updated != nil {
		t.Fatalf("missing consumer must be created: added=%v updated=%v", js.added, js.updated)
	}
	cfg := js.added
	if cfg.Durable != "RYVEX_DISPATCHER" || cfg.FilterSubject != "ryvex.resource.>" {
		t.Fatalf("created consumer identity = %+v", cfg)
	}
	if cfg.AckPolicy != nats.AckExplicitPolicy || cfg.DeliverPolicy != nats.DeliverAllPolicy {
		t.Fatalf("created consumer policies = %+v", cfg)
	}
	if cfg.AckWait != 30*time.Second || cfg.MaxDeliver != 3 {
		t.Fatalf("created consumer budget = %+v", cfg)
	}
	if cfg.OptStartSeq != 42 {
		t.Fatalf("OptStartSeq = %d, want 42 (lastSeq+1)", cfg.OptStartSeq)
	}
}

// TestEnsureConsumerReconcilesDrift pins the UpdateConsumer-on-drift
// acceptance: a restart reconciles the mutable fields we own onto the
// existing consumer while preserving immutable ones.
func TestEnsureConsumerReconcilesDrift(t *testing.T) {
	// Matching config (what testDurableBus wants): no update.
	matching := nats.ConsumerConfig{
		Durable: "RYVEX_DISPATCHER", FilterSubject: "ryvex.resource.>",
		AckPolicy: nats.AckExplicitPolicy, DeliverPolicy: nats.DeliverAllPolicy,
		AckWait: 30 * time.Second, MaxDeliver: 3, OptStartSeq: 7,
	}
	js := &consumerStub{info: &nats.ConsumerInfo{Config: matching}}
	b := testDurableBus(js)
	if err := b.ensureConsumer("RYVEX_DISPATCHER", "ryvex.resource.>"); err != nil {
		t.Fatalf("ensureConsumer(matching): %v", err)
	}
	if js.updated != nil {
		t.Fatalf("matching consumer must not be updated, got %+v", js.updated)
	}

	// Drift (a consumer created by an older daemon version): AckWait/
	// MaxDeliver reconciled onto the new desired budget, immutable
	// fields untouched.
	js2 := &consumerStub{info: &nats.ConsumerInfo{Config: matching}}
	js2.info.Config.AckWait = 10 * time.Second
	js2.info.Config.MaxDeliver = 99
	b2 := testDurableBus(js2)
	b2.ackWait = 45 * time.Second
	b2.maxDeliver = 8
	if err := b2.ensureConsumer("RYVEX_DISPATCHER", "ryvex.resource.>"); err != nil {
		t.Fatalf("ensureConsumer(drifted): %v", err)
	}
	if js2.updated == nil {
		t.Fatal("drifted consumer must be updated")
	}
	if js2.updated.AckWait != 45*time.Second || js2.updated.MaxDeliver != 8 {
		t.Fatalf("updated budget = %+v", js2.updated)
	}
	if js2.updated.OptStartSeq != 7 || js2.updated.DeliverPolicy != nats.DeliverAllPolicy || js2.updated.AckPolicy != nats.AckExplicitPolicy {
		t.Fatalf("immutable fields not preserved: %+v", js2.updated)
	}
	if js2.updated.Durable != "RYVEX_DISPATCHER" || js2.updated.FilterSubject != "ryvex.resource.>" {
		t.Fatalf("updated identity = %+v", js2.updated)
	}
}

func TestValidateDurableName(t *testing.T) {
	for _, ok := range []string{"RYVEX_DISPATCHER", "ryvex-test_1", "A"} {
		if err := validateDurableName(ok); err != nil {
			t.Fatalf("validateDurableName(%q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{"", "RYVEX DISPATCHER", "ry*ex", "ryvex>dispatcher", "a.b"} {
		if err := validateDurableName(bad); err == nil {
			t.Fatalf("validateDurableName(%q) = nil, want error", bad)
		}
	}
}

// fakeMsg is the fake ackable: records which terminal state the
// dispatch path chose. Unlike *nats.Msg it needs no live connection.
type fakeMsg struct {
	md                        *nats.MsgMetadata
	acked, nacked, terminated atomic.Bool
}

func (f *fakeMsg) Ack(...nats.AckOpt) error  { f.acked.Store(true); return nil }
func (f *fakeMsg) Nak(...nats.AckOpt) error  { f.nacked.Store(true); return nil }
func (f *fakeMsg) Term(...nats.AckOpt) error { f.terminated.Store(true); return nil }
func (f *fakeMsg) Metadata() (*nats.MsgMetadata, error) {
	if f.md == nil {
		return nil, errors.New("no metadata")
	}
	return f.md, nil
}

// dlqStub records dead-letter publishes.
type dlqStub struct {
	nats.JetStreamContext
	err  error
	got  chan *nats.Msg
	done bool
}

func (s *dlqStub) PublishMsg(m *nats.Msg, _ ...nats.PubOpt) (*nats.PubAck, error) {
	if s.err != nil {
		return nil, s.err
	}
	if !s.done {
		s.got <- m
		s.done = true
	}
	return &nats.PubAck{Stream: DLQStreamName, Sequence: 1}, nil
}

func eventJSON(t *testing.T, e bus.Event) []byte {
	t.Helper()
	data, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshal event: %v", err)
	}
	return data
}

// TestDispatchDurableAckOnSuccess: handler success = explicit ack, no
// redelivery, no DLQ.
func TestDispatchDurableAckOnSuccess(t *testing.T) {
	stub := &dlqStub{got: make(chan *nats.Msg, 1)}
	b := testDurableBus(stub)
	fm := &fakeMsg{md: &nats.MsgMetadata{Sequence: nats.SequencePair{Stream: 5}, NumDelivered: 1}}
	var hit bus.Event
	b.dispatchDurable("RYVEX_T", eventJSON(t, bus.Event{Org: "acme", Kind: "Node", Name: "n1", Type: bus.EventCreated}), fm,
		func(e bus.Event) error { hit = e; return nil })
	if hit.Name != "n1" {
		t.Fatalf("handler got %+v", hit)
	}
	if !fm.acked.Load() || fm.nacked.Load() || fm.terminated.Load() {
		t.Fatalf("success must ack only: ack=%v nak=%v term=%v", fm.acked.Load(), fm.nacked.Load(), fm.terminated.Load())
	}
	select {
	case m := <-stub.got:
		t.Fatalf("success must not dead-letter, got %+v", m)
	default:
	}
}

// TestDispatchDurableRetryNaks: a transient failure with delivery
// budget left must nak (redeliver), never terminate.
func TestDispatchDurableRetryNaks(t *testing.T) {
	stub := &dlqStub{got: make(chan *nats.Msg, 1)}
	b := testDurableBus(stub)
	fm := &fakeMsg{md: &nats.MsgMetadata{Sequence: nats.SequencePair{Stream: 5}, NumDelivered: 1}}
	b.dispatchDurable("RYVEX_T", eventJSON(t, bus.Event{Org: "acme", Kind: "Node"}), fm,
		func(bus.Event) error { return bus.ErrEventRetry })
	if !fm.nacked.Load() || fm.acked.Load() || fm.terminated.Load() {
		t.Fatalf("retry must nak only: ack=%v nak=%v term=%v", fm.acked.Load(), fm.nacked.Load(), fm.terminated.Load())
	}
	select {
	case m := <-stub.got:
		t.Fatalf("retry with budget left must not dead-letter, got %+v", m)
	default:
	}
}

// TestDispatchDurableExhaustedBudgetDLQ: the final allowed delivery
// (NumDelivered == MaxDeliver) that still fails is dead-lettered with
// reason max_deliver and terminated.
func TestDispatchDurableExhaustedBudgetDLQ(t *testing.T) {
	stub := &dlqStub{got: make(chan *nats.Msg, 1)}
	b := testDurableBus(stub)
	fm := &fakeMsg{md: &nats.MsgMetadata{Sequence: nats.SequencePair{Stream: 9}, NumDelivered: 3}}
	before := busDLQTotal.WithLabelValues(DLQReasonMaxDeliver).Value()
	b.dispatchDurable("RYVEX_DISPATCHER", eventJSON(t, bus.Event{Org: "acme", Kind: "Node"}), fm,
		func(bus.Event) error { return bus.ErrEventRetry })

	select {
	case m := <-stub.got:
		if m.Subject != "ryvex.dlq.9" {
			t.Fatalf("DLQ subject = %q, want ryvex.dlq.9", m.Subject)
		}
		if m.Header.Get(DLQHeaderReason) != DLQReasonMaxDeliver {
			t.Fatalf("DLQ reason header = %q", m.Header.Get(DLQHeaderReason))
		}
		if m.Header.Get(DLQHeaderConsumer) != "RYVEX_DISPATCHER" || m.Header.Get(DLQHeaderStreamSeq) != "9" {
			t.Fatalf("DLQ metadata headers = %v", m.Header)
		}
		if !bytes.Contains(m.Data, []byte(`"org":"acme"`)) {
			t.Fatalf("DLQ payload must be the original event JSON: %s", m.Data)
		}
	default:
		t.Fatal("exhausted budget must dead-letter")
	}
	if !fm.terminated.Load() || fm.acked.Load() || fm.nacked.Load() {
		t.Fatalf("dead-lettered message must be terminated: ack=%v nak=%v term=%v", fm.acked.Load(), fm.nacked.Load(), fm.terminated.Load())
	}
	if got := busDLQTotal.WithLabelValues(DLQReasonMaxDeliver).Value(); got != before+1 {
		t.Fatalf("ryvex_bus_dlq_total{max_deliver} = %v, want %v", got, before+1)
	}
}

// TestDispatchDurablePoisonDLQ: bus.ErrEventPoison dead-letters on the
// FIRST failure (no retries) with reason poison.
func TestDispatchDurablePoisonDLQ(t *testing.T) {
	stub := &dlqStub{got: make(chan *nats.Msg, 1)}
	b := testDurableBus(stub)
	fm := &fakeMsg{md: &nats.MsgMetadata{Sequence: nats.SequencePair{Stream: 3}, NumDelivered: 1}}
	before := busDLQTotal.WithLabelValues(DLQReasonPoison).Value()
	b.dispatchDurable("RYVEX_DISPATCHER", eventJSON(t, bus.Event{Org: "acme", Kind: "Node"}), fm,
		func(bus.Event) error { return bus.ErrEventPoison })

	select {
	case m := <-stub.got:
		if m.Header.Get(DLQHeaderReason) != DLQReasonPoison {
			t.Fatalf("DLQ reason = %q, want poison", m.Header.Get(DLQHeaderReason))
		}
		if m.Header.Get(DLQHeaderCause) == "" {
			t.Fatal("DLQ cause header missing")
		}
	default:
		t.Fatal("poison event must dead-letter immediately")
	}
	if !fm.terminated.Load() || fm.nacked.Load() {
		t.Fatal("poison event must be terminated, not retried")
	}
	if got := busDLQTotal.WithLabelValues(DLQReasonPoison).Value(); got != before+1 {
		t.Fatalf("ryvex_bus_dlq_total{poison} = %v, want %v", got, before+1)
	}
}

// TestDispatchDurableUndecodableDLQ: a payload that is not a Ryvex
// event would replay forever if retried; it must dead-letter
// immediately.
func TestDispatchDurableUndecodableDLQ(t *testing.T) {
	stub := &dlqStub{got: make(chan *nats.Msg, 1)}
	b := testDurableBus(stub)
	fm := &fakeMsg{md: &nats.MsgMetadata{Sequence: nats.SequencePair{Stream: 4}}}
	calls := 0
	b.dispatchDurable("RYVEX_T", []byte("{not-json"), fm, func(bus.Event) error {
		calls++
		return nil
	})
	if calls != 0 {
		t.Fatal("undecodable payload must not reach the handler")
	}
	select {
	case <-stub.got:
	default:
		t.Fatal("undecodable payload must dead-letter")
	}
	if !fm.terminated.Load() {
		t.Fatal("undecodable payload must be terminated")
	}
}

// TestDispatchDurablePanicRetries: handler panics are contained and
// treated as transient (nak), so a crashing handler cannot silently
// drop events; the MaxDeliver budget still bounds the retries.
func TestDispatchDurablePanicRetries(t *testing.T) {
	stub := &dlqStub{got: make(chan *nats.Msg, 1)}
	b := testDurableBus(stub)
	fm := &fakeMsg{md: &nats.MsgMetadata{Sequence: nats.SequencePair{Stream: 6}, NumDelivered: 1}}
	b.dispatchDurable("RYVEX_T", eventJSON(t, bus.Event{Org: "acme", Kind: "Node"}), fm,
		func(bus.Event) error { panic("boom") })
	if !fm.nacked.Load() || fm.terminated.Load() {
		t.Fatalf("panic with budget left must nak: nak=%v term=%v", fm.nacked.Load(), fm.terminated.Load())
	}
}

// TestDispatchDurableDLQPublishFailureRetriesPoison: when the DLQ
// republish itself fails on a poison event, the delivery is nacked so
// the DLQ attempt is retried (bounded by MaxDeliver) instead of
// silently dropping the event; the failed republish counts on
// ryvex_bus_publish_failures_total.
func TestDispatchDurableDLQPublishFailureRetriesPoison(t *testing.T) {
	stub := &dlqStub{err: errors.New("nats: no responders")}
	b := testDurableBus(stub)
	fm := &fakeMsg{md: &nats.MsgMetadata{Sequence: nats.SequencePair{Stream: 8}, NumDelivered: 1}}
	before := busPublishFailuresTotal.Value()
	b.dispatchDurable("RYVEX_T", eventJSON(t, bus.Event{Org: "acme", Kind: "Node"}), fm,
		func(bus.Event) error { return bus.ErrEventPoison })
	if !fm.nacked.Load() || fm.terminated.Load() || fm.acked.Load() {
		t.Fatalf("failed DLQ publish on poison must nak: ack=%v nak=%v term=%v", fm.acked.Load(), fm.nacked.Load(), fm.terminated.Load())
	}
	if got := busPublishFailuresTotal.Value(); got != before+1 {
		t.Fatalf("ryvex_bus_publish_failures_total = %v, want %v", got, before+1)
	}
}

// TestPublishErrSurfacesFailures pins issue #81's publish contract:
// PublishErr returns the persistence outcome and every failure lands
// on ryvex_bus_publish_failures_total (marshal, server rejection)
// without ever touching ryvex_bus_events_published_total.
func TestPublishErrSurfacesFailures(t *testing.T) {
	label := eventTypeLabel(bus.EventUpdated)
	published := metrics.BusEventsPublishedTotal.WithLabelValues(label)
	pubBefore := published.Value()
	failCounter := busPublishFailuresTotal
	failBefore := failCounter.Value()

	// Success: nil error, published counter moves, failure counter does not.
	okBus := &Bus{
		js: &stubJS{pub: func(subject string, data []byte, _ ...nats.PubOpt) (*nats.PubAck, error) {
			return &nats.PubAck{Stream: StreamName, Sequence: 1}, nil
		}},
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	if err := okBus.PublishErr(bus.Event{Org: "acme", Kind: "Node", Type: bus.EventUpdated}); err != nil {
		t.Fatalf("PublishErr(success) = %v, want nil", err)
	}
	if want := pubBefore + 1; published.Value() != want {
		t.Fatalf("published counter = %v, want %v", published.Value(), want)
	}
	if want := failBefore; failCounter.Value() != want {
		t.Fatalf("failure counter moved on success: %v, want %v", failCounter.Value(), want)
	}

	// Server rejection: error surfaced, failure counter incremented,
	// published counter untouched.
	rejectBus := &Bus{
		js: &stubJS{pub: func(string, []byte, ...nats.PubOpt) (*nats.PubAck, error) {
			return nil, errors.New("nats: timeout")
		}},
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	err := rejectBus.PublishErr(bus.Event{Org: "acme", Kind: "Node", Type: bus.EventUpdated})
	if err == nil {
		t.Fatal("PublishErr(reject) = nil, want error")
	}
	if !strings.Contains(err.Error(), "nats: timeout") || !strings.Contains(err.Error(), "acme") {
		t.Fatalf("PublishErr error should carry cause and subject, got %v", err)
	}
	if failCounter.Value() != failBefore+1 {
		t.Fatalf("failure counter = %v, want %v", failCounter.Value(), failBefore+1)
	}
	if published.Value() != pubBefore+1 {
		t.Fatalf("failed publish moved published counter to %v, want %v", published.Value(), pubBefore+1)
	}

	// Marshal failure: same surfacing, event was never persisted.
	marshalBus := &Bus{
		js: &stubJS{pub: func(string, []byte, ...nats.PubOpt) (*nats.PubAck, error) {
			t.Error("publish must not be attempted when marshal fails")
			return nil, nil
		}},
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	bad := bus.Event{Org: "acme", Kind: "Node", Type: bus.EventUpdated, Data: map[string]any{"ch": make(chan int)}}
	if err := marshalBus.PublishErr(bad); err == nil {
		t.Fatal("PublishErr(unmarshalable) = nil, want error")
	}
	if want := failBefore + 2; failCounter.Value() != want {
		t.Fatalf("failure counter after marshal failure = %v, want %v", failCounter.Value(), want)
	}
}

// ---- issue #81 live tests (RYVEX_TEST_NATS_URL) ----
//
// The unit tests above prove the dispatch taxonomy against stubs; the
// tests below prove the real JetStream behaviors: durable redelivery
// across restart, explicit acks, MaxDeliver exhaustion, DLQ content
// and publish-failure surfacing. They are skipped locally (no
// nats-server in the sandbox) and exercised in CI.

// waitLive polls cond until it holds or the deadline passes.
func waitLive(t *testing.T, what string, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// TestLiveStreamConfigReconcile proves the stream config update on
// version change: a second boot with a different MaxAge reconciles the
// existing stream instead of freezing the first boot's config.
func TestLiveStreamConfigReconcile(t *testing.T) {
	url := testURL(t)
	b1, err := New(url, Options{MaxAge: 2 * time.Hour})
	if err != nil {
		t.Fatalf("New(2h): %v", err)
	}
	defer b1.Close()
	si, err := b1.js.StreamInfo(StreamName)
	if err != nil {
		t.Fatalf("stream info: %v", err)
	}
	if si.Config.MaxAge != 2*time.Hour {
		t.Fatalf("MaxAge after first boot = %v, want 2h", si.Config.MaxAge)
	}

	b2, err := New(url, Options{MaxAge: 3 * time.Hour})
	if err != nil {
		t.Fatalf("New(3h): %v", err)
	}
	defer b2.Close()
	si, err = b2.js.StreamInfo(StreamName)
	if err != nil {
		t.Fatalf("stream info after drift: %v", err)
	}
	if si.Config.MaxAge != 3*time.Hour {
		t.Fatalf("MaxAge after drifted boot = %v, want 3h (stream config must be updated on version change)", si.Config.MaxAge)
	}

	// Restore the config the other tests expect.
	b3, err := New(url, Options{MaxAge: time.Hour})
	if err != nil {
		t.Fatalf("restore New(1h): %v", err)
	}
	defer b3.Close()
	si, _ = b3.js.StreamInfo(StreamName)
	if si.Config.MaxAge != time.Hour {
		t.Fatalf("restore failed: MaxAge = %v", si.Config.MaxAge)
	}
}

// TestLiveDurableAtLeastOnceAck proves: events published after a
// durable subscribe are delivered and explicitly acked (NumAckPending
// drains to zero, nothing redelivered).
func TestLiveDurableAtLeastOnceAck(t *testing.T) {
	b := newTestBus(t)
	const name = "RYVEX_T_ACK"
	t.Cleanup(func() { _ = b.js.DeleteConsumer(StreamName, name) })

	got := make(chan string, 32)
	sub, err := b.SubscribeDurable(name, "ryvex.resource.acme.>", func(e bus.Event) error {
		got <- e.Name
		return nil
	})
	if err != nil {
		t.Fatalf("SubscribeDurable: %v", err)
	}
	defer sub.Cancel()

	for i := 0; i < 3; i++ {
		b.Publish(bus.Event{Org: "acme", Kind: "Deployment", Type: bus.EventCreated, Name: fmt.Sprintf("d%02d", i)})
	}
	for i := 0; i < 3; i++ {
		select {
		case <-got:
		case <-time.After(5 * time.Second):
			t.Fatalf("only %d/3 events delivered", i)
		}
	}
	waitLive(t, "consumer ack drain", 5*time.Second, func() bool {
		ci, err := b.js.ConsumerInfo(StreamName, name)
		return err == nil && ci.NumAckPending == 0 && ci.NumPending == 0
	})
}

// TestLiveDurableRedeliversUntilAck proves the retry taxonomy end to
// end: ErrEventRetry naks, JetStream redelivers the SAME event, and a
// later success acks it.
func TestLiveDurableRedeliversUntilAck(t *testing.T) {
	b := newTestBus(t)
	const name = "RYVEX_T_RETRY"
	t.Cleanup(func() { _ = b.js.DeleteConsumer(StreamName, name) })

	var calls atomic.Int64
	var firstName atomic.Value
	sub, err := b.SubscribeDurable(name, "ryvex.resource.acme.>", func(e bus.Event) error {
		if calls.Add(1) < 3 {
			return bus.ErrEventRetry
		}
		firstName.Store(e.Name)
		return nil
	})
	if err != nil {
		t.Fatalf("SubscribeDurable: %v", err)
	}
	defer sub.Cancel()

	b.Publish(bus.Event{Org: "acme", Kind: "Deployment", Type: bus.EventCreated, Name: "redeliver-me"})

	waitLive(t, "3 deliveries of the same event", 10*time.Second, func() bool { return calls.Load() >= 3 })
	if n, _ := firstName.Load().(string); n != "redeliver-me" {
		t.Fatalf("success handler got %q", n)
	}
	waitLive(t, "ack drain", 5*time.Second, func() bool {
		ci, err := b.js.ConsumerInfo(StreamName, name)
		return err == nil && ci.NumAckPending == 0
	})
}

// TestLiveDurableSurvivesOutage is THE durability scenario: events
// published while no fetcher is attached (consumer exists, "process
// down") are delivered once a later SubscribeDurable with the same
// deterministic name binds again — and the rebinding is idempotent (no
// duplicate consumer, no error).
func TestLiveDurableSurvivesOutage(t *testing.T) {
	b, url := newTestBusNoPurge(t)
	if err := b.js.PurgeStream(StreamName); err != nil {
		t.Fatalf("purge stream: %v", err)
	}
	const name = "RYVEX_T_OUTAGE"
	t.Cleanup(func() { _ = b.js.DeleteConsumer(StreamName, name) })

	sub, err := b.SubscribeDurable(name, "ryvex.resource.acme.>", func(bus.Event) error { return nil })
	if err != nil {
		t.Fatalf("first SubscribeDurable: %v", err)
	}
	sub.Cancel() // fetcher gone; the durable consumer remains server-side

	// "Outage": event persisted into the stream with nobody consuming.
	b.Publish(bus.Event{Org: "acme", Kind: "Deployment", Type: bus.EventCreated, Name: "during-outage"})

	// "Restart": a fresh Bus binds the same durable consumer.
	b2, err := New(url, Options{MaxAge: time.Hour})
	if err != nil {
		t.Fatalf("restart New: %v", err)
	}
	defer b2.Close()

	got := make(chan string, 8)
	sub2, err := b2.SubscribeDurable(name, "ryvex.resource.acme.>", func(e bus.Event) error {
		got <- e.Name
		return nil
	})
	if err != nil {
		t.Fatalf("rebind after restart (must be idempotent, no duplicate consumer): %v", err)
	}
	defer sub2.Cancel()

	select {
	case n := <-got:
		if n != "during-outage" {
			t.Fatalf("post-restart delivery = %q, want during-outage", n)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("event published during the outage was not redelivered after restart")
	}
	waitLive(t, "ack drain", 5*time.Second, func() bool {
		ci, err := b2.js.ConsumerInfo(StreamName, name)
		return err == nil && ci.NumAckPending == 0
	})
}

// TestLiveDurableDLQOnPoison proves the RYVEX_DLQ stream: a poison
// handler failure dead-letters the original payload verbatim with the
// failure headers, and the DLQ counter advances.
func TestLiveDurableDLQOnPoison(t *testing.T) {
	b := newTestBus(t)
	_ = b.js.PurgeStream(DLQStreamName) // ignore not-found on fresh servers
	const name = "RYVEX_T_DLQ"
	t.Cleanup(func() { _ = b.js.DeleteConsumer(StreamName, name) })

	before := busDLQTotal.WithLabelValues(DLQReasonPoison).Value()
	sub, err := b.SubscribeDurable(name, "ryvex.resource.acme.>", func(bus.Event) error {
		return bus.ErrEventPoison
	})
	if err != nil {
		t.Fatalf("SubscribeDurable: %v", err)
	}
	defer sub.Cancel()

	b.Publish(bus.Event{Org: "acme", Kind: "Deployment", Type: bus.EventCreated, Name: "poison-me"})

	var raw *nats.RawStreamMsg
	waitLive(t, "DLQ message in RYVEX_DLQ", 10*time.Second, func() bool {
		si, err := b.js.StreamInfo(DLQStreamName)
		if err != nil || si.State.Msgs == 0 {
			return false
		}
		raw, err = b.js.GetMsg(DLQStreamName, si.State.LastSeq)
		return err == nil && raw != nil
	})

	var got bus.Event
	if err := json.Unmarshal(raw.Data, &got); err != nil {
		t.Fatalf("DLQ payload is not a Ryvex event: %v (%s)", err, raw.Data)
	}
	if got.Name != "poison-me" || got.Org != "acme" {
		t.Fatalf("DLQ payload = %+v, want the original event", got)
	}
	if !strings.HasPrefix(raw.Subject, DLQSubjectPrefix+".") {
		t.Fatalf("DLQ subject = %q, want prefix %q", raw.Subject, DLQSubjectPrefix)
	}
	if raw.Header.Get(DLQHeaderReason) != DLQReasonPoison {
		t.Fatalf("DLQ reason header = %q, want %q", raw.Header.Get(DLQHeaderReason), DLQReasonPoison)
	}
	if raw.Header.Get(DLQHeaderConsumer) != name {
		t.Fatalf("DLQ consumer header = %q, want %q", raw.Header.Get(DLQHeaderConsumer), name)
	}
	if after := busDLQTotal.WithLabelValues(DLQReasonPoison).Value(); after != before+1 {
		t.Fatalf("ryvex_bus_dlq_total{poison} = %v, want %v", after, before+1)
	}
}

// TestLiveDurableMaxDeliverExhaustedDLQ proves the bounded-retry path:
// a handler that always fails transiently is delivered exactly
// MaxDeliver times, then the event lands in RYVEX_DLQ with reason
// max_deliver.
func TestLiveDurableMaxDeliverExhaustedDLQ(t *testing.T) {
	b, url := newTestBusNoPurge(t)
	if err := b.js.PurgeStream(StreamName); err != nil {
		t.Fatalf("purge stream: %v", err)
	}
	_ = b.js.PurgeStream(DLQStreamName)

	bb, err := New(url, Options{MaxAge: time.Hour, MaxDeliver: 2})
	if err != nil {
		t.Fatalf("New(MaxDeliver=2): %v", err)
	}
	defer bb.Close()
	const name = "RYVEX_T_MAX"
	t.Cleanup(func() { _ = bb.js.DeleteConsumer(StreamName, name) })

	before := busDLQTotal.WithLabelValues(DLQReasonMaxDeliver).Value()
	var calls atomic.Int64
	sub, err := bb.SubscribeDurable(name, "ryvex.resource.acme.>", func(bus.Event) error {
		calls.Add(1)
		return errors.New("transient boom")
	})
	if err != nil {
		t.Fatalf("SubscribeDurable: %v", err)
	}
	defer sub.Cancel()

	bb.Publish(bus.Event{Org: "acme", Kind: "Deployment", Type: bus.EventCreated, Name: "doomed"})

	waitLive(t, "MaxDeliver deliveries", 10*time.Second, func() bool { return calls.Load() >= 2 })
	var raw *nats.RawStreamMsg
	waitLive(t, "DLQ message with reason max_deliver", 10*time.Second, func() bool {
		si, err := bb.js.StreamInfo(DLQStreamName)
		if err != nil || si.State.Msgs == 0 {
			return false
		}
		raw, err = bb.js.GetMsg(DLQStreamName, si.State.LastSeq)
		return err == nil && raw != nil && raw.Header.Get(DLQHeaderReason) == DLQReasonMaxDeliver
	})
	var got bus.Event
	if err := json.Unmarshal(raw.Data, &got); err != nil || got.Name != "doomed" {
		t.Fatalf("DLQ payload = %s (%v), want the doomed event", raw.Data, err)
	}
	if after := busDLQTotal.WithLabelValues(DLQReasonMaxDeliver).Value(); after != before+1 {
		t.Fatalf("ryvex_bus_dlq_total{max_deliver} = %v, want %v", after, before+1)
	}
	// No delivery beyond the budget.
	time.Sleep(2 * durableFetchWait)
	if c := calls.Load(); c != 2 {
		t.Fatalf("handler invoked %d times, want exactly MaxDeliver=2", c)
	}
}

// TestLivePublishErrSurfacesOnClosedConn proves publish-failure
// surfacing: after the connection is gone, PublishErr returns an error
// instead of silently dropping the event.
func TestLivePublishErrSurfacesOnClosedConn(t *testing.T) {
	b, _ := newTestBusNoPurge(t)
	if err := b.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := b.PublishErr(bus.Event{Org: "acme", Kind: "Node", Type: bus.EventCreated}); err == nil {
		t.Fatal("PublishErr after Close = nil, want error (mid-outage publishes must surface to the caller)")
	}
}
