package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Roy-Wanyoike/Ryvex/internal/metrics"
)

func TestRouteLabelBuckets(t *testing.T) {
	cases := map[string]string{
		"/healthz":                     "healthz",
		"/":                            "index",
		"/v1":                          "index",
		"/v1/":                         "index",
		"/v1/resources":                "resources",
		"/v1/resources/r-abc123":       "resources/{id}",
		"/v1/acme/events":              "org/events",
		"/v1/acme/audit":               "org/audit",
		"/v1/acme/reconcile/r-abc123":  "org/reconcile/{id}",
		"/v1/acme/core/prod/Database":  "scope/{kind}",
		"/v1/acme/core/prod/Bucket/a1": "scope/{kind}/{name}",
		"/v1/globex":                   "other",
		"/v1/a/b/c/d/e/f":              "other",
		"/favicon.ico":                 "other",
	}
	for path, want := range cases {
		if got := routeLabel(path); got != want {
			t.Errorf("routeLabel(%q) = %q, want %q", path, got, want)
		}
	}
}

func TestRequestMetricsRecorded(t *testing.T) {
	h := newTestServer(t)

	// /healthz: open route, counted with route="healthz".
	ctr0 := metrics.HTTPRequestsTotal.WithLabelValues("healthz", "GET", "200").Value()
	dur0 := metrics.HTTPRequestDuration.WithLabelValues("healthz", "GET").Count()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("healthz: got %d", w.Code)
	}
	if got := metrics.HTTPRequestsTotal.WithLabelValues("healthz", "GET", "200").Value() - ctr0; got != 1 {
		t.Fatalf("healthz request counter delta = %v, want 1", got)
	}
	if got := metrics.HTTPRequestDuration.WithLabelValues("healthz", "GET").Count() - dur0; got != 1 {
		t.Fatalf("healthz duration count delta = %v, want 1", got)
	}

	// POST /v1/resources -> route bucket "resources", status 201.
	ctr0 = metrics.HTTPRequestsTotal.WithLabelValues("resources", "POST", "201").Value()
	w = do(t, h, "POST", "/v1/resources", appBody)
	if w.Code != http.StatusCreated {
		t.Fatalf("create: got %d", w.Code)
	}
	if got := metrics.HTTPRequestsTotal.WithLabelValues("resources", "POST", "201").Value() - ctr0; got != 1 {
		t.Fatalf("create request counter delta = %v, want 1", got)
	}

	// GET /v1/resources -> list bucket, same route label, different method.
	ctr0 = metrics.HTTPRequestsTotal.WithLabelValues("resources", "GET", "200").Value()
	w = do(t, h, "GET", "/v1/resources", "")
	if w.Code != http.StatusOK {
		t.Fatalf("list: got %d", w.Code)
	}
	if got := metrics.HTTPRequestsTotal.WithLabelValues("resources", "GET", "200").Value() - ctr0; got != 1 {
		t.Fatalf("list request counter delta = %v, want 1", got)
	}

	// Unauthorized POST still lands in the same route bucket with 401.
	ctr0 = metrics.HTTPRequestsTotal.WithLabelValues("resources", "POST", "401").Value()
	req = httptest.NewRequest(http.MethodPost, "/v1/resources", strings.NewReader(appBody))
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated: got %d, want 401", w.Code)
	}
	if got := metrics.HTTPRequestsTotal.WithLabelValues("resources", "POST", "401").Value() - ctr0; got != 1 {
		t.Fatalf("401 request counter delta = %v, want 1", got)
	}

	// The exposition carries the recorded samples.
	out := string(metrics.Default.Gather())
	if !strings.Contains(out, `ryvex_http_requests_total{route="healthz",method="GET",status="200"}`) {
		t.Fatalf("exposition missing healthz request sample:\n%s", out)
	}
	if !strings.Contains(out, `ryvex_http_requests_total{route="resources",method="POST",status="201"}`) {
		t.Fatalf("exposition missing resources request sample:\n%s", out)
	}
	if !strings.Contains(out, `# TYPE ryvex_http_request_duration_seconds histogram`) {
		t.Fatalf("exposition missing duration histogram type:\n%s", out)
	}
	if !strings.Contains(out, `ryvex_http_request_duration_seconds_count{route="healthz",method="GET"}`) {
		t.Fatalf("exposition missing duration sample:\n%s", out)
	}
}
