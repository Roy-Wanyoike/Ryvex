package metrics

import (
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// ---- test-only exposition parser ----
// We parse our own output the way a scraper would: validating the
// HELP/TYPE structure, label syntax and value grammar of every line.

type sample struct {
	name   string
	labels map[string]string
	value  float64
}

func parseExposition(t *testing.T, body string) (helps, types map[string]string, samples []sample) {
	t.Helper()
	helps = map[string]string{}
	types = map[string]string{}
	nameRe := regexp.MustCompile(`^[a-zA-Z_:][a-zA-Z0-9_:]*$`)

	lines := strings.Split(body, "\n")
	for i, line := range lines {
		if line == "" {
			if i == len(lines)-1 {
				continue // trailing newline
			}
			t.Fatalf("blank line %d in exposition", i)
		}
		if strings.HasSuffix(line, " ") || strings.HasSuffix(line, "\t") {
			t.Fatalf("line %d has trailing whitespace: %q", i, line)
		}
		switch {
		case strings.HasPrefix(line, "# HELP "):
			rest := strings.TrimPrefix(line, "# HELP ")
			name, doc, _ := strings.Cut(rest, " ")
			if !nameRe.MatchString(name) {
				t.Fatalf("bad HELP name %q on line %d", name, i)
			}
			if _, dup := helps[name]; dup {
				t.Fatalf("duplicate HELP for %s", name)
			}
			helps[name] = doc
		case strings.HasPrefix(line, "# TYPE "):
			rest := strings.TrimPrefix(line, "# TYPE ")
			name, typ, _ := strings.Cut(rest, " ")
			if !nameRe.MatchString(name) {
				t.Fatalf("bad TYPE name %q on line %d", name, i)
			}
			if _, ok := helps[name]; !ok {
				t.Fatalf("TYPE for %s appears before its HELP line", name)
			}
			switch typ {
			case TypeCounter, TypeGauge, TypeHistogram:
			default:
				t.Fatalf("bad TYPE %q for %s", typ, name)
			}
			types[name] = typ
		case strings.HasPrefix(line, "#"):
			t.Fatalf("unexpected comment on line %d: %q", i, line)
		default:
			metric, rest, found := strings.Cut(line, " ")
			if !found || rest == "" {
				t.Fatalf("sample without value on line %d: %q", i, line)
			}
			name := metric
			labels := map[string]string{}
			if brace := strings.Index(metric, "{"); brace >= 0 {
				if !strings.HasSuffix(metric, "}") {
					t.Fatalf("unterminated label set on line %d: %q", i, line)
				}
				name = metric[:brace]
				inner := metric[brace+1 : len(metric)-1]
				if inner != "" {
					for _, pair := range splitLabelPairs(t, inner) {
						k, v, ok := strings.Cut(pair, "=")
						if !ok || k == "" || !strings.HasPrefix(v, `"`) || !strings.HasSuffix(v, `"`) || len(v) < 2 {
							t.Fatalf("bad label pair %q on line %d", pair, i)
						}
						if !nameRe.MatchString(k) {
							t.Fatalf("bad label name %q on line %d", k, i)
						}
						labels[k] = unescapeLabelValue(strings.Trim(v, `"`))
					}
				}
			}
			if !nameRe.MatchString(name) {
				t.Fatalf("bad sample name %q on line %d", name, i)
			}
			val, err := strconv.ParseFloat(rest, 64)
			if err != nil {
				t.Fatalf("unparseable value %q on line %d: %v", rest, i, err)
			}
			samples = append(samples, sample{name: name, labels: labels, value: val})
		}
	}
	return helps, types, samples
}

// splitLabelPairs splits a label set body on commas that are outside
// quoted values, honoring backslash escapes.
func splitLabelPairs(t *testing.T, s string) []string {
	t.Helper()
	var out []string
	var cur strings.Builder
	inQuote, esc := false, false
	for _, r := range s {
		switch {
		case esc:
			cur.WriteRune(r)
			esc = false
		case r == '\\':
			cur.WriteRune(r)
			esc = true
		case r == '"':
			cur.WriteRune(r)
			inQuote = !inQuote
		case r == ',' && !inQuote:
			out = append(out, cur.String())
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}
	if inQuote || esc {
		t.Fatalf("unterminated label value in %q", s)
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

func unescapeLabelValue(s string) string {
	var b strings.Builder
	esc := false
	for _, r := range s {
		if esc {
			switch r {
			case 'n':
				b.WriteRune('\n')
			case '\\':
				b.WriteRune('\\')
			case '"':
				b.WriteRune('"')
			default:
				b.WriteRune(r)
			}
			esc = false
			continue
		}
		if r == '\\' {
			esc = true
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// findSample returns the value of the named sample with exactly the
// given labels, failing the test when absent.
func findSample(t *testing.T, samples []sample, name string, labels map[string]string) float64 {
	t.Helper()
	for _, s := range samples {
		if s.name != name || len(s.labels) != len(labels) {
			continue
		}
		match := true
		for k, v := range labels {
			if s.labels[k] != v {
				match = false
				break
			}
		}
		if match {
			return s.value
		}
	}
	t.Fatalf("sample %s%s not found in exposition", name, labels)
	return 0
}

// ---- counter tests ----

func TestCounterMath(t *testing.T) {
	reg := NewRegistry()
	c := reg.NewCounter("test_counter_total", "a counter")
	if c.Value() != 0 {
		t.Fatalf("fresh counter = %v, want 0", c.Value())
	}
	c.Inc()
	c.Inc()
	c.Add(5)
	if c.Value() != 7 {
		t.Fatalf("counter = %v, want 7", c.Value())
	}

	_, _, samples := parseExposition(t, string(reg.Gather()))
	if got := findSample(t, samples, "test_counter_total", nil); got != 7 {
		t.Fatalf("exposed counter = %v, want 7", got)
	}
}

func TestCounterVecAccumulatesPerLabelSet(t *testing.T) {
	reg := NewRegistry()
	cv := reg.NewCounterVec("test_labeled_total", "a labeled counter", "code")

	cv.WithLabelValues("200").Inc()
	cv.WithLabelValues("200").Add(2)
	cv.WithLabelValues("500").Inc()
	cv.WithLabelValues("500").Inc()

	// distinct label sets are independent series
	if got := cv.WithLabelValues("200").Value(); got != 3 {
		t.Fatalf("code=200 counter = %v, want 3", got)
	}
	if got := cv.WithLabelValues("500").Value(); got != 2 {
		t.Fatalf("code=500 counter = %v, want 2", got)
	}

	_, _, samples := parseExposition(t, string(reg.Gather()))
	if got := findSample(t, samples, "test_labeled_total", map[string]string{"code": "200"}); got != 3 {
		t.Fatalf("exposed 200 series = %v, want 3", got)
	}
	if got := findSample(t, samples, "test_labeled_total", map[string]string{"code": "500"}); got != 2 {
		t.Fatalf("exposed 500 series = %v, want 2", got)
	}
}

func TestLabelCardinalityIsExactlyTheDistinctLabelSets(t *testing.T) {
	reg := NewRegistry()
	cv := reg.NewCounterVec("test_card_total", "cardinality probe", "route", "method")

	cv.WithLabelValues("resources", "GET").Inc()
	cv.WithLabelValues("resources", "GET").Inc() // same set again
	cv.WithLabelValues("resources", "POST").Inc()
	cv.WithLabelValues("healthz", "GET").Inc()

	fam := cv.fam
	fam.mu.Lock()
	n := len(fam.series)
	fam.mu.Unlock()
	if n != 3 {
		t.Fatalf("series count = %d, want 3 (distinct label sets only)", n)
	}
	_, _, samples := parseExposition(t, string(reg.Gather()))
	count := 0
	for _, s := range samples {
		if s.name == "test_card_total" {
			count++
		}
	}
	if count != 3 {
		t.Fatalf("exposed series = %d, want 3", count)
	}
}

func TestCounterRejectsNegativeAdd(t *testing.T) {
	reg := NewRegistry()
	c := reg.NewCounter("test_nonneg_total", "counters only go up")
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic on negative counter add")
		}
	}()
	c.Add(-1)
}

// ---- gauge tests ----

func TestGaugeMath(t *testing.T) {
	reg := NewRegistry()
	g := reg.NewGauge("test_gauge", "a gauge")
	g.Set(3)
	g.Add(2)
	if g.Value() != 5 {
		t.Fatalf("gauge = %v, want 5", g.Value())
	}
	g.Dec()
	if g.Value() != 4 {
		t.Fatalf("gauge after Dec = %v, want 4", g.Value())
	}
	g.Set(-1.5) // gauges may be negative and fractional
	if g.Value() != -1.5 {
		t.Fatalf("gauge = %v, want -1.5", g.Value())
	}

	gv := reg.NewGaugeVec("test_gauge_vec", "a labeled gauge", "kind")
	gv.WithLabelValues("Database").Set(1.25)
	gv.WithLabelValues("Cache").Add(-2)

	_, _, samples := parseExposition(t, string(reg.Gather()))
	if got := findSample(t, samples, "test_gauge_vec", map[string]string{"kind": "Database"}); got != 1.25 {
		t.Fatalf("Database gauge = %v, want 1.25", got)
	}
	if got := findSample(t, samples, "test_gauge_vec", map[string]string{"kind": "Cache"}); got != -2 {
		t.Fatalf("Cache gauge = %v, want -2", got)
	}
}

// ---- histogram tests ----

func TestHistogramMath(t *testing.T) {
	reg := NewRegistry()
	h := reg.NewHistogram("test_hist_seconds", "a histogram", []float64{1, 2, 5})

	h.Observe(0.5) // lands in le=1,2,5
	h.Observe(1.5) // lands in le=2,5
	h.Observe(3)   // lands in le=5
	h.Observe(10)  // only +Inf

	if h.Count() != 4 {
		t.Fatalf("count = %d, want 4", h.Count())
	}
	if h.Sum() != 15 {
		t.Fatalf("sum = %v, want 15", h.Sum())
	}

	_, _, samples := parseExposition(t, string(reg.Gather()))
	want := []struct {
		le  string
		cum float64
	}{
		{"1", 1},
		{"2", 2},
		{"5", 3},
		{"+Inf", 4}, // +Inf bucket always equals the count
	}
	for _, w := range want {
		if got := findSample(t, samples, "test_hist_seconds_bucket", map[string]string{"le": w.le}); got != w.cum {
			t.Fatalf("bucket le=%s = %v, want %v", w.le, got, w.cum)
		}
	}
	if got := findSample(t, samples, "test_hist_seconds_sum", nil); got != 15 {
		t.Fatalf("sum = %v, want 15", got)
	}
	if got := findSample(t, samples, "test_hist_seconds_count", nil); got != 4 {
		t.Fatalf("count = %v, want 4", got)
	}
}

func TestHistogramLabelDimensions(t *testing.T) {
	reg := NewRegistry()
	hv := reg.NewHistogramVec("test_histl_seconds", "labeled histogram", []float64{0.1, 1}, "route")

	hv.WithLabelValues("/fast").Observe(0.05)
	hv.WithLabelValues("/fast").Observe(0.5)
	hv.WithLabelValues("/slow").Observe(4)

	_, _, samples := parseExposition(t, string(reg.Gather()))
	if got := findSample(t, samples, "test_histl_seconds_count", map[string]string{"route": "/fast"}); got != 2 {
		t.Fatalf("/fast count = %v, want 2", got)
	}
	if got := findSample(t, samples, "test_histl_seconds_count", map[string]string{"route": "/slow"}); got != 1 {
		t.Fatalf("/slow count = %v, want 1", got)
	}
	if got := findSample(t, samples, "test_histl_seconds_bucket", map[string]string{"le": "0.1", "route": "/fast"}); got != 1 {
		t.Fatalf("/fast le=0.1 = %v, want 1", got)
	}
	if got := findSample(t, samples, "test_histl_seconds_bucket", map[string]string{"le": "+Inf", "route": "/slow"}); got != 1 {
		t.Fatalf("/slow +Inf = %v, want 1", got)
	}
}

// ---- exposition format ----

func TestExpositionFormatValidAndEscaped(t *testing.T) {
	reg := NewRegistry()
	cv := reg.NewCounterVec("aaa_total", "doc one", "code")
	cv.WithLabelValues("200").Inc()

	gv := reg.NewGaugeVec("bbb_depth", "doc two", "scope", "name")
	gv.WithLabelValues(`a"b`, `c\d`).Set(2.5)      // quote + backslash escaping
	gv.WithLabelValues("multi\nline", "x").Set(-1) // newline escaping

	hv := reg.NewHistogramVec("ccc_seconds", "doc three", []float64{0.5, 1}, "route")
	hv.WithLabelValues("/res").Observe(0.25)
	hv.WithLabelValues("/res").Observe(2)

	body := string(reg.Gather())
	helps, types, samples := parseExposition(t, body) // must parse cleanly

	if helps["aaa_total"] != "doc one" || helps["bbb_depth"] != "doc two" || helps["ccc_seconds"] != "doc three" {
		t.Fatalf("HELP lines wrong: %v", helps)
	}
	if types["aaa_total"] != TypeCounter || types["bbb_depth"] != TypeGauge || types["ccc_seconds"] != TypeHistogram {
		t.Fatalf("TYPE lines wrong: %v", types)
	}

	// escaping round-trips: the parsed labels equal the originals
	if got := findSample(t, samples, "bbb_depth", map[string]string{"scope": `a"b`, "name": `c\d`}); got != 2.5 {
		t.Fatalf("escaped quote/backslash labels lost: %v", got)
	}
	if got := findSample(t, samples, "bbb_depth", map[string]string{"scope": "multi\nline", "name": "x"}); got != -1 {
		t.Fatalf("escaped newline label lost: %v", got)
	}

	// histogram family emits bucket/sum/count with le labels
	if got := findSample(t, samples, "ccc_seconds_bucket", map[string]string{"le": "0.5", "route": "/res"}); got != 1 {
		t.Fatalf("bucket 0.5 = %v, want 1", got)
	}
	if got := findSample(t, samples, "ccc_seconds_bucket", map[string]string{"le": "+Inf", "route": "/res"}); got != 2 {
		t.Fatalf("bucket +Inf = %v, want 2", got)
	}
	if got := findSample(t, samples, "ccc_seconds_sum", map[string]string{"route": "/res"}); got != 2.25 {
		t.Fatalf("sum = %v, want 2.25", got)
	}

	// families render in sorted name order
	i1 := strings.Index(body, "# TYPE aaa_total")
	i2 := strings.Index(body, "# TYPE bbb_depth")
	i3 := strings.Index(body, "# TYPE ccc_seconds")
	if !(0 <= i1 && i1 < i2 && i2 < i3) {
		t.Fatalf("families not sorted by name: %d %d %d", i1, i2, i3)
	}

	// large values round-trip through the short 'g' float format
	big := reg.NewCounter("ddd_big_total", "big values")
	big.Add(1234567)
	_, _, samples = parseExposition(t, string(reg.Gather()))
	if got := findSample(t, samples, "ddd_big_total", nil); got != 1234567 {
		t.Fatalf("big value = %v, want 1234567", got)
	}
}

func TestUnusedFamilyAnnouncedHeaderOnly(t *testing.T) {
	reg := NewRegistry()
	reg.NewCounter("lonely_total", "never used")
	reg.NewGauge("ghost_depth", "also unused")

	body := string(reg.Gather())
	if !strings.Contains(body, "# HELP lonely_total never used\n") ||
		!strings.Contains(body, "# TYPE lonely_total counter\n") {
		t.Fatalf("unused family must still announce HELP/TYPE:\n%s", body)
	}
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, "lonely_total ") || strings.HasPrefix(line, "ghost_depth ") {
			t.Fatalf("unused family must not carry samples, got %q", line)
		}
	}
	_, _, _ = parseExposition(t, body) // still structurally valid
}

func TestLabelArityPanics(t *testing.T) {
	reg := NewRegistry()
	cv := reg.NewCounterVec("test_arity_total", "arity probe", "a", "b")
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic on wrong label value count")
		}
	}()
	cv.WithLabelValues("only-one")
}

// ---- concurrency ----

func TestConcurrentUpdatesRaceSafe(t *testing.T) {
	reg := NewRegistry()
	c := reg.NewCounterVec("test_conc_total", "concurrent counter", "kind")
	g := reg.NewGauge("test_conc_depth", "concurrent gauge")
	h := reg.NewHistogram("test_conc_seconds", "concurrent histogram", []float64{1, 5, 10})

	const goroutines, iters = 50, 200
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			child := c.WithLabelValues("hot")
			for j := 0; j < iters; j++ {
				child.Inc()
				g.Add(1)
				h.Observe(float64(j % 10))
			}
		}()
	}
	wg.Wait()

	total := float64(goroutines * iters)
	if got := c.WithLabelValues("hot").Value(); got != total {
		t.Fatalf("counter = %v, want %v", got, total)
	}
	if got := g.Value(); got != total {
		t.Fatalf("gauge = %v, want %v", got, total)
	}
	if got := h.Count(); got != uint64(goroutines*iters) {
		t.Fatalf("histogram count = %d, want %d", got, goroutines*iters)
	}
	wantSum := 0.0
	for j := 0; j < iters; j++ {
		wantSum += float64(j % 10)
	}
	if got := h.Sum(); math.Abs(got-wantSum*goroutines) > 1e-6 {
		t.Fatalf("histogram sum = %v, want %v", got, wantSum*goroutines)
	}

	// cumulative bucket math: values j%%10 with buckets 1,5,10
	_, _, samples := parseExposition(t, string(reg.Gather()))
	if got := findSample(t, samples, "test_conc_seconds_bucket", map[string]string{"le": "1"}); got != 2*iters*goroutines/10 {
		t.Fatalf("le=1 bucket = %v", got)
	}
	if got := findSample(t, samples, "test_conc_seconds_bucket", map[string]string{"le": "5"}); got != 6*iters*goroutines/10 {
		t.Fatalf("le=5 bucket = %v", got)
	}
	if got := findSample(t, samples, "test_conc_seconds_bucket", map[string]string{"le": "+Inf"}); got != total {
		t.Fatalf("+Inf bucket = %v, want %v", got, total)
	}
}

// ---- handler ----

func TestHandlerServesExposition(t *testing.T) {
	reg := NewRegistry()
	reg.NewCounter("handler_total", "served counter").Inc()

	srv := httptest.NewServer(reg.Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != ContentType {
		t.Fatalf("content-type = %q, want %q", ct, ContentType)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	helps, _, samples := parseExposition(t, string(body))
	if helps["handler_total"] != "served counter" {
		t.Fatalf("help = %q", helps["handler_total"])
	}
	if got := findSample(t, samples, "handler_total", nil); got != 1 {
		t.Fatalf("sample = %v, want 1", got)
	}
}

// ---- resources snapshot ----

type fakeStore map[string]map[string]int64

func (f fakeStore) CountByKindPhase() map[string]map[string]int64 { return f }

func TestReconcileMetricsSnapshot(t *testing.T) {
	// Two live kind/phase pairs.
	if n := ReconcileMetrics(fakeStore{"Application": {"Pending": 2}, "Database": {"Ready": 1}}); n != 2 {
		t.Fatalf("live pairs = %d, want 2", n)
	}
	if got := Resources.WithLabelValues("Application", "Pending").Value(); got != 2 {
		t.Fatalf("Application/Pending = %v, want 2", got)
	}
	if got := Resources.WithLabelValues("Database", "Ready").Value(); got != 1 {
		t.Fatalf("Database/Ready = %v, want 1", got)
	}

	// A pair that vanishes from the snapshot must be zeroed, not left
	// stale (series are kept for scrape stability, value goes to 0).
	if n := ReconcileMetrics(fakeStore{"Application": {"Ready": 3}}); n != 1 {
		t.Fatalf("live pairs = %d, want 1", n)
	}
	if got := Resources.WithLabelValues("Application", "Pending").Value(); got != 0 {
		t.Fatalf("stale Application/Pending = %v, want 0", got)
	}
	if got := Resources.WithLabelValues("Database", "Ready").Value(); got != 0 {
		t.Fatalf("stale Database/Ready = %v, want 0", got)
	}
	if got := Resources.WithLabelValues("Application", "Ready").Value(); got != 3 {
		t.Fatalf("Application/Ready = %v, want 3", got)
	}

	// The gauge is announced as a gauge in the default registry output.
	out := string(Default.Gather())
	if !strings.Contains(out, "# TYPE ryvex_resources gauge") {
		t.Fatalf("ryvex_resources not announced:\n%s", out)
	}
	if !strings.Contains(out, fmt.Sprintf("ryvex_resources{kind=%q,phase=%q} 3", "Application", "Ready")) {
		t.Fatalf("ryvex_resources sample missing:\n%s", out)
	}
}
