package webhook

// Tracing tests (issue #83): the delivery-attempt span exists, nests
// under the dispatcher's start context, and injects a W3C traceparent
// into the outgoing POST so receivers can join the trace.

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Roy-Wanyoike/Ryvex/internal/bus"
	"github.com/Roy-Wanyoike/Ryvex/internal/state"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestDeliveryAttemptSpanNestsAndInjectsTraceparent(t *testing.T) {
	exp := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exp))
	defer func() { _ = tp.Shutdown(context.Background()) }()

	st := state.NewStore()
	b := bus.New()
	srv, deliveries := captureServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	sub := createSubscription(t, st, "hooks", "main", map[string]any{
		"url":      srv.URL + "/hook",
		"subjects": []any{"ryvex.resource.acme.application.>"},
	})

	d := NewDispatcher(st, b, testOptions("secret", func(o *Options) {
		o.TracerProvider = tp
	}))

	// Start the dispatcher under a traced context: the delivery span
	// must nest under it. (In the daemon, Start gets the plain root
	// context, so attempts are their own traces — the causing bus event
	// carries no trace context; the bus wire contract is untouched.)
	parentCtx, parentSpan := tp.Tracer("test").Start(context.Background(), "test.root")
	d.Start(parentCtx)
	defer d.Stop(2 * time.Second)
	defer parentSpan.End()

	publishCreated(b, "acme", "checkout")
	got := recv(t, deliveries, 5*time.Second)

	var delivery *tracetest.SpanStub
	waitUntil(t, "webhook.deliver span", 2*time.Second, func() bool {
		spans := exp.GetSpans()
		for i := range spans {
			if spans[i].Name == "webhook.deliver" {
				delivery = &spans[i]
				return true
			}
		}
		return false
	})

	// The span nests under the start context (child of test.root).
	if delivery.SpanContext.TraceID() != parentSpan.SpanContext().TraceID() {
		t.Errorf("delivery trace %s != parent trace %s",
			delivery.SpanContext.TraceID(), parentSpan.SpanContext().TraceID())
	}
	if delivery.Parent.SpanID() != parentSpan.SpanContext().SpanID() {
		t.Errorf("delivery parent %s != parent span id %s",
			delivery.Parent.SpanID(), parentSpan.SpanContext().SpanID())
	}

	// The receiver got a W3C traceparent continuing the delivery trace.
	parts := strings.Split(got.header.Get("traceparent"), "-")
	if len(parts) != 4 || parts[0] != "00" {
		t.Fatalf("malformed traceparent %q on webhook delivery", got.header.Get("traceparent"))
	}
	if parts[1] != delivery.SpanContext.TraceID().String() {
		t.Errorf("traceparent trace %s != delivery span trace %s", parts[1], delivery.SpanContext.TraceID())
	}
	for _, kv := range delivery.Attributes {
		switch string(kv.Key) {
		case "ryvex.webhook.subscription_id":
			if kv.Value.AsString() != sub.ID {
				t.Errorf("subscription_id attr = %q, want %q", kv.Value.AsString(), sub.ID)
			}
		case "ryvex.event.subject":
			if kv.Value.AsString() != "ryvex.resource.acme.application.created" {
				t.Errorf("event subject attr = %q", kv.Value.AsString())
			}
		case "http.response.status_code":
			if kv.Value.AsInt64() != http.StatusOK {
				t.Errorf("http.response.status_code attr = %d, want 200", kv.Value.AsInt64())
			}
		}
	}
}
