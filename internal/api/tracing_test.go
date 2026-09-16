package api

// OpenTelemetry tracing tests (issue #83): enabled-mode assertions with
// the in-memory sdktrace exporter, plus the disabled-by-default
// contract (no header, no middleware).

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Roy-Wanyoike/Ryvex/internal/bus"
	"github.com/Roy-Wanyoike/Ryvex/internal/reconcile"
	"github.com/Roy-Wanyoike/Ryvex/internal/state"

	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

// newTracedServer is newTestServer with an SDK tracer provider wired
// into the API server only (the reconciler stays no-op so the recorder
// sees exactly the request-driven spans).
func newTracedServer(t *testing.T, exp *tracetest.InMemoryExporter) http.Handler {
	t.Helper()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exp))
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })
	store := state.NewStore()
	eventBus := bus.New()
	rec := reconcile.New(store, eventBus, reconcile.Options{Interval: time.Hour, Logger: discardLogger()})
	ctx, cancel := context.WithCancel(context.Background())
	rec.Start(ctx)
	t.Cleanup(func() {
		cancel()
		rec.Stop(2 * time.Second)
	})
	return NewServer(store, eventBus, rec, ServerOptions{
		Auth:           AuthOptions{APIKeys: map[string]string{testToken: "ci"}},
		Logger:         discardLogger(),
		TracerProvider: tp,
	})
}

func serverSpan(t *testing.T, exp *tracetest.InMemoryExporter) *tracetest.SpanStub {
	t.Helper()
	spans := exp.GetSpans()
	for i := range spans {
		if spans[i].SpanKind == trace.SpanKindServer {
			return &spans[i]
		}
	}
	t.Fatalf("no server span exported (have %d spans)", len(exp.GetSpans()))
	return nil
}

func attrOf(s *tracetest.SpanStub, key string) attribute.Value {
	for _, kv := range s.Attributes {
		if string(kv.Key) == key {
			return kv.Value
		}
	}
	return attribute.Value{}
}

// Disabled by default (#83): no TracerProvider -> no X-Ryvex-Trace-Id
// header, while the plain X-Request-Id contract is untouched.
func TestTracingDisabledByDefault(t *testing.T) {
	h := newTestServer(t)
	w := do(t, h, http.MethodGet, "/v1", "")
	if got := w.Header().Get(TraceIDHeader); got != "" {
		t.Errorf("X-Ryvex-Trace-Id = %q with tracing disabled; want absent", got)
	}
	if got := w.Header().Get("X-Request-Id"); got == "" {
		t.Error("X-Request-Id response header missing")
	}
}

// Enabled mode: the server span exists, is route-labeled and carries
// the request_id audit bridge; the store write is a child span; the
// trace ID is echoed to the caller.
func TestTracingEnabledServerAndStoreSpans(t *testing.T) {
	exp := tracetest.NewInMemoryExporter()
	h := newTracedServer(t, exp)

	w := do(t, h, http.MethodPost, "/v1/resources", appBody)
	if w.Code != http.StatusCreated {
		t.Fatalf("want 201, got %d: %s", w.Code, w.Body.String())
	}

	server := serverSpan(t, exp)
	if server.Name != "POST resources" {
		t.Errorf("server span name = %q, want %q", server.Name, "POST resources")
	}
	if route := attrOf(server, "http.route").AsString(); route != "resources" {
		t.Errorf("http.route = %q, want %q", route, "resources")
	}
	// Request-ID <-> trace-ID coherence (#83): the server span's
	// request_id attribute equals the echoed X-Request-Id, and the
	// X-Ryvex-Trace-Id header equals the span's trace ID.
	if rid := attrOf(server, "request_id").AsString(); rid == "" || rid != w.Header().Get("X-Request-Id") {
		t.Errorf("span request_id = %q, response X-Request-Id = %q", rid, w.Header().Get("X-Request-Id"))
	}
	if got := w.Header().Get(TraceIDHeader); got != server.SpanContext.TraceID().String() {
		t.Errorf("X-Ryvex-Trace-Id = %q, want span trace %s", got, server.SpanContext.TraceID())
	}
	if code := attrOf(server, "http.response.status_code").AsInt64(); code != http.StatusCreated {
		t.Errorf("http.response.status_code = %d, want %d", code, http.StatusCreated)
	}

	// The store write is a child span under the server span.
	var storeSpan *tracetest.SpanStub
	spans := exp.GetSpans()
	for i := range spans {
		if spans[i].Name == "store.create" {
			storeSpan = &spans[i]
			break
		}
	}
	if storeSpan == nil {
		t.Fatalf("store.create span missing (spans: %d)", len(exp.GetSpans()))
	}
	if storeSpan.SpanContext.TraceID() != server.SpanContext.TraceID() {
		t.Errorf("store span trace %s != server span trace %s", storeSpan.SpanContext.TraceID(), server.SpanContext.TraceID())
	}
	if storeSpan.Parent.SpanID() != server.SpanContext.SpanID() {
		t.Errorf("store span parent %s != server span id %s", storeSpan.Parent.SpanID(), server.SpanContext.SpanID())
	}
	if kind := attrOf(storeSpan, "ryvex.resource.kind").AsString(); kind != "Application" {
		t.Errorf("store span ryvex.resource.kind = %q, want Application", kind)
	}
}

// W3C incoming traceparent is honored: the server span continues the
// caller's trace instead of starting a new root, and a client-supplied
// X-Request-Id lands on the span as the audit bridge.
func TestTracingContinuesIncomingTrace(t *testing.T) {
	exp := tracetest.NewInMemoryExporter()
	h := newTracedServer(t, exp)

	// W3C spec example traceparent (version 00, sampled).
	const (
		incomingTrace = "4bf92f3577b34da6a3ce929d0e0e4736"
		incomingSpan  = "00f067aa0ba902b7"
	)
	req := httptest.NewRequest(http.MethodGet, "/v1", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	req.Header.Set("traceparent", "00-"+incomingTrace+"-"+incomingSpan+"-01")
	req.Header.Set("X-Request-Id", "coherence-check-1")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}

	server := serverSpan(t, exp)
	if got := server.SpanContext.TraceID().String(); got != incomingTrace {
		t.Errorf("server span trace = %s, want incoming trace continued (%s)", got, incomingTrace)
	}
	if got := w.Header().Get(TraceIDHeader); got != incomingTrace {
		t.Errorf("X-Ryvex-Trace-Id = %q, want %q", got, incomingTrace)
	}
	if rid := attrOf(server, "request_id").AsString(); rid != "coherence-check-1" {
		t.Errorf("span request_id = %q, want %q", rid, "coherence-check-1")
	}
}
