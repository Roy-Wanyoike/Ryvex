// Package metrics implements a dependency-free Prometheus
// instrumentation toolkit for Ryvex. It provides counters, gauges and
// histograms with label dimensions, a thread-safe registry and an
// http.Handler that renders the Prometheus text exposition format
// v0.0.4 (the format scraped by Prometheus, promtool and most
// collectors). No external dependencies are used: the text format is
// written by hand.
//
// Instruments are cheap to update (a mutex-guarded float op per
// family, no allocation on the hot path once a series exists) and
// there is no background work at all: nothing happens until a scrape
// calls Gather.
package metrics

import (
	"bytes"
	"fmt"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// Metric types as rendered in "# TYPE" lines.
const (
	TypeCounter   = "counter"
	TypeGauge     = "gauge"
	TypeHistogram = "histogram"
)

// ContentType is the media type of the Prometheus text exposition
// format v0.0.4.
const ContentType = "text/plain; version=0.0.4; charset=utf-8"

// family groups series that share a name, help string, type and
// (histograms only) bucket bounds. Every mutation goes through
// fam.mu, so updates to different families never contend and updates
// within a family are race-free.
type family struct {
	name    string
	help    string
	typ     string
	buckets []float64 // histogram upper bounds, ascending, +Inf implied
	labels  []string  // label names in declaration order

	mu     sync.Mutex
	series map[string]*series
}

// series is a single time series: a fixed label tuple plus its
// accumulators. Series are created once and never removed from their
// family (stale snapshot series are zeroed instead of deleted), so
// child handles handed out by WithLabelValues stay valid for the
// life of the process.
type series struct {
	vals []string // label values, aligned with family.labels

	v float64 // counter/gauge value

	bounds []uint64 // histogram per-bound counts (cumulative)
	sum    float64
	count  uint64
}

// Registry holds metric families and renders them in the Prometheus
// text exposition format. It is safe for concurrent use. Register
// instruments at startup; Gather at scrape time.
type Registry struct {
	mu   sync.Mutex
	fams []*family
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry { return &Registry{} }

// ---- registration ----

// NewCounter registers a monotonically increasing counter. Zero-label
// counters are used directly (Inc/Add); labeled counters hand out
// children via WithLabelValues.
func (r *Registry) NewCounter(name, help string) *Counter {
	return &Counter{fam: r.registerFamily(name, help, TypeCounter, nil, nil)}
}

// NewCounterVec registers a counter partitioned by labels.
func (r *Registry) NewCounterVec(name, help string, labelNames ...string) *CounterVec {
	return &CounterVec{fam: r.registerFamily(name, help, TypeCounter, nil, labelNames)}
}

// NewGauge registers a gauge that can go up and down.
func (r *Registry) NewGauge(name, help string) *Gauge {
	return &Gauge{fam: r.registerFamily(name, help, TypeGauge, nil, nil)}
}

// NewGaugeVec registers a gauge partitioned by labels.
func (r *Registry) NewGaugeVec(name, help string, labelNames ...string) *GaugeVec {
	return &GaugeVec{fam: r.registerFamily(name, help, TypeGauge, nil, labelNames)}
}

// NewHistogram registers a cumulative histogram with the given bucket
// upper bounds (a +Inf bucket is always implied; bounds are sorted).
func (r *Registry) NewHistogram(name, help string, buckets []float64) *Histogram {
	return &Histogram{fam: r.registerFamily(name, help, TypeHistogram, buckets, nil)}
}

// NewHistogramVec registers a histogram partitioned by labels.
func (r *Registry) NewHistogramVec(name, help string, buckets []float64, labelNames ...string) *HistogramVec {
	return &HistogramVec{fam: r.registerFamily(name, help, TypeHistogram, buckets, labelNames)}
}

func (r *Registry) registerFamily(name, help, typ string, buckets []float64, labelNames []string) *family {
	if !validName(name) {
		panic("metrics: invalid metric name " + strconv.Quote(name))
	}
	for _, l := range labelNames {
		if !validName(l) {
			panic("metrics: invalid label name " + strconv.Quote(l) + " on " + name)
		}
	}
	f := &family{
		name:   name,
		help:   help,
		typ:    typ,
		labels: append([]string(nil), labelNames...),
		series: map[string]*series{},
	}
	if typ == TypeHistogram {
		if len(buckets) == 0 {
			panic("metrics: histogram " + name + " needs at least one bucket bound")
		}
		f.buckets = append([]float64(nil), buckets...)
		sort.Float64s(f.buckets)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.fams = append(r.fams, f)
	return f
}

// ---- counters ----

// Counter is a cumulative metric that only increases (restarts to
// zero are the scrape target's business, not the instrument's).
type Counter struct{ fam *family }

// Inc adds one to the counter.
func (c *Counter) Inc() { c.fam.addCounter(nil, 1) }

// Add adds v to the counter; v must not be negative.
func (c *Counter) Add(v float64) { c.fam.addCounter(nil, v) }

// WithLabelValues returns the child for the given label tuple,
// creating it on first use. Panics when the value count does not
// match the label count declared at registration.
func (c *Counter) WithLabelValues(vals ...string) *CounterChild {
	return &CounterChild{fam: c.fam, s: c.fam.seriesFor(vals)}
}

// Value returns the current value (0 when the series was never used).
func (c *Counter) Value() float64 { return c.fam.valueOf(nil) }

// CounterChild is a single labeled series of a counter.
type CounterChild struct {
	fam *family
	s   *series
}

// Inc adds one to the child counter.
func (c *CounterChild) Inc() { c.fam.addCounter(c.s, 1) }

// Add adds v to the child counter; v must not be negative.
func (c *CounterChild) Add(v float64) { c.fam.addCounter(c.s, v) }

// Value returns the current value of the child series.
func (c *CounterChild) Value() float64 { return c.fam.valueOf(c.s) }

// CounterVec is a counter partitioned by labels (same type as
// Counter; the alias documents intent at use sites).
type CounterVec = Counter

// ---- gauges ----

// Gauge is a metric that can go up and down.
type Gauge struct{ fam *family }

// Set sets the gauge to v.
func (g *Gauge) Set(v float64) { g.fam.set(nil, v) }

// Add adds v (possibly negative) to the gauge.
func (g *Gauge) Add(v float64) { g.fam.addTo(nil, v) }

// Inc adds one; Dec subtracts one.
func (g *Gauge) Inc() { g.fam.addTo(nil, 1) }
func (g *Gauge) Dec() { g.fam.addTo(nil, -1) }

// WithLabelValues returns the child for the given label tuple,
// creating it on first use.
func (g *Gauge) WithLabelValues(vals ...string) *GaugeChild {
	return &GaugeChild{fam: g.fam, s: g.fam.seriesFor(vals)}
}

// Value returns the current value (0 when the series was never used).
func (g *Gauge) Value() float64 { return g.fam.valueOf(nil) }

// GaugeChild is a single labeled series of a gauge.
type GaugeChild struct {
	fam *family
	s   *series
}

// Set sets the child gauge to v.
func (g *GaugeChild) Set(v float64) { g.fam.set(g.s, v) }

// Add adds v (possibly negative) to the child gauge.
func (g *GaugeChild) Add(v float64) { g.fam.addTo(g.s, v) }

// Inc adds one; Dec subtracts one.
func (g *GaugeChild) Inc() { g.fam.addTo(g.s, 1) }
func (g *GaugeChild) Dec() { g.fam.addTo(g.s, -1) }

// Value returns the current value of the child series.
func (g *GaugeChild) Value() float64 { return g.fam.valueOf(g.s) }

// GaugeVec is a gauge partitioned by labels (same type as Gauge).
type GaugeVec = Gauge

// ---- histograms ----

// Histogram is a cumulative histogram: observations fall into the
// configured upper bounds (plus an implied +Inf bucket) and the sum
// and count of observations are tracked.
type Histogram struct{ fam *family }

// Observe records v in the histogram.
func (h *Histogram) Observe(v float64) { h.fam.observe(nil, v) }

// WithLabelValues returns the child for the given label tuple,
// creating it on first use.
func (h *Histogram) WithLabelValues(vals ...string) *HistogramChild {
	return &HistogramChild{fam: h.fam, s: h.fam.seriesFor(vals)}
}

// Count returns the number of observations (0 when never used).
func (h *Histogram) Count() uint64 { return h.fam.histCount(nil) }

// Sum returns the accumulated sum of observations.
func (h *Histogram) Sum() float64 { return h.fam.histSum(nil) }

// HistogramChild is a single labeled series of a histogram.
type HistogramChild struct {
	fam *family
	s   *series
}

// Observe records v in the child histogram.
func (h *HistogramChild) Observe(v float64) { h.fam.observe(h.s, v) }

// Count returns the number of observations of the child series.
func (h *HistogramChild) Count() uint64 { return h.fam.histCount(h.s) }

// Sum returns the accumulated sum of the child series.
func (h *HistogramChild) Sum() float64 { return h.fam.histSum(h.s) }

// HistogramVec is a histogram partitioned by labels (same type as
// Histogram).
type HistogramVec = Histogram

// ---- family internals ----

func (f *family) seriesFor(vals []string) *series {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.getOrCreateLocked(vals)
}

// getOrCreateLocked returns the series for vals, creating it on first
// use. Caller must hold f.mu.
func (f *family) getOrCreateLocked(vals []string) *series {
	if len(vals) != len(f.labels) {
		panic(fmt.Sprintf("metrics: %s: got %d label values, want %d", f.name, len(vals), len(f.labels)))
	}
	key := encodeKey(vals)
	if s, ok := f.series[key]; ok {
		return s
	}
	s := &series{vals: append([]string(nil), vals...)}
	if f.typ == TypeHistogram {
		s.bounds = make([]uint64, len(f.buckets))
	}
	f.series[key] = s
	return s
}

func (f *family) addCounter(s *series, v float64) {
	if v < 0 {
		panic(fmt.Sprintf("metrics: negative add %v on counter %s", v, f.name))
	}
	f.addTo(s, v)
}

func (f *family) addTo(s *series, v float64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if s == nil {
		s = f.getOrCreateLocked(nil)
	}
	s.v += v
}

func (f *family) set(s *series, v float64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if s == nil {
		s = f.getOrCreateLocked(nil)
	}
	s.v = v
}

func (f *family) observe(s *series, v float64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if s == nil {
		s = f.getOrCreateLocked(nil)
	}
	for i, ub := range f.buckets {
		if v <= ub {
			s.bounds[i]++
		}
	}
	s.sum += v
	s.count++
}

// valueOf reads a series value without creating it. A nil series
// means the zero-label series.
func (f *family) valueOf(s *series) float64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	if s == nil {
		s = f.series[encodeKey(nil)]
		if s == nil {
			return 0
		}
	}
	return s.v
}

func (f *family) histCount(s *series) uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	if s == nil {
		s = f.series[encodeKey(nil)]
		if s == nil {
			return 0
		}
	}
	return s.count
}

func (f *family) histSum(s *series) float64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	if s == nil {
		s = f.series[encodeKey(nil)]
		if s == nil {
			return 0
		}
	}
	return s.sum
}

// ---- exposition rendering ----

// Gather renders every registered family in the Prometheus text
// exposition format v0.0.4. Families are sorted by name and series
// within a family by label values, so output is byte-stable across
// scrapes when the label sets are stable. Registered families are
// announced with # HELP / # TYPE even before they carry samples.
func (r *Registry) Gather() []byte {
	r.mu.Lock()
	fams := make([]*family, len(r.fams))
	copy(fams, r.fams)
	r.mu.Unlock()
	sort.Slice(fams, func(i, j int) bool { return fams[i].name < fams[j].name })

	var buf bytes.Buffer
	for _, f := range fams {
		f.writeTo(&buf)
	}
	return buf.Bytes()
}

// Handler returns an http.Handler serving the registry with the
// correct exposition content type.
func (r *Registry) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", ContentType)
		_, _ = w.Write(r.Gather())
	})
}

func (f *family) writeTo(buf *bytes.Buffer) {
	f.mu.Lock()
	defer f.mu.Unlock()

	buf.WriteString("# HELP ")
	buf.WriteString(f.name)
	buf.WriteByte(' ')
	buf.WriteString(escapeDoc(f.help))
	buf.WriteByte('\n')
	buf.WriteString("# TYPE ")
	buf.WriteString(f.name)
	buf.WriteByte(' ')
	buf.WriteString(f.typ)
	buf.WriteByte('\n')

	if len(f.series) == 0 {
		return
	}

	keys := make([]string, 0, len(f.series))
	for k := range f.series {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		s := f.series[k]
		switch f.typ {
		case TypeCounter, TypeGauge:
			writeSample(buf, f.name, f.labels, s.vals, s.v)
		case TypeHistogram:
			names := make([]string, 0, len(f.labels)+1)
			names = append(names, "le")
			names = append(names, f.labels...)
			for i, ub := range f.buckets {
				writeSample(buf, f.name+"_bucket", names, append([]string{formatFloat(ub)}, s.vals...), float64(s.bounds[i]))
			}
			writeSample(buf, f.name+"_bucket", names, append([]string{"+Inf"}, s.vals...), float64(s.count))
			writeSample(buf, f.name+"_sum", f.labels, s.vals, s.sum)
			writeSample(buf, f.name+"_count", f.labels, s.vals, float64(s.count))
		}
	}
}

func writeSample(buf *bytes.Buffer, name string, labelNames, labelVals []string, v float64) {
	buf.WriteString(name)
	if len(labelVals) > 0 {
		buf.WriteByte('{')
		for i, val := range labelVals {
			if i > 0 {
				buf.WriteByte(',')
			}
			buf.WriteString(labelNames[i])
			buf.WriteString(`="`)
			buf.WriteString(escapeLabelValue(val))
			buf.WriteByte('"')
		}
		buf.WriteByte('}')
	}
	buf.WriteByte(' ')
	buf.WriteString(formatFloat(v))
	buf.WriteByte('\n')
}

// encodeKey builds a collision-free map key from label values by
// length-prefixing each one.
func encodeKey(vals []string) string {
	var b strings.Builder
	for _, v := range vals {
		b.WriteString(strconv.Itoa(len(v)))
		b.WriteByte(':')
		b.WriteString(v)
	}
	return b.String()
}

// validName enforces the classic Prometheus metric/label name syntax:
// [a-zA-Z_:][a-zA-Z0-9_:]*
func validName(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c == '_', c == ':':
		case c >= '0' && c <= '9' && i > 0:
		default:
			return false
		}
	}
	return true
}

// escapeLabelValue escapes backslash, double quote and line feed as
// required by the text format.
func escapeLabelValue(v string) string {
	if !strings.ContainsAny(v, "\\\n\"") {
		return v
	}
	var b strings.Builder
	b.Grow(len(v) + 4)
	for _, r := range v {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\n':
			b.WriteString(`\n`)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// escapeDoc escapes a HELP docstring (backslash and line feed only;
// quotes are legal there).
func escapeDoc(s string) string {
	if !strings.ContainsAny(s, "\\\n") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 4)
	for _, r := range s {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// formatFloat renders a sample value the way the text format expects
// (Go's shortest round-trip form, plus the NaN/+Inf/-Inf literals).
func formatFloat(v float64) string {
	switch {
	case math.IsNaN(v):
		return "NaN"
	case math.IsInf(v, 1):
		return "+Inf"
	case math.IsInf(v, -1):
		return "-Inf"
	}
	return strconv.FormatFloat(v, 'g', -1, 64)
}
