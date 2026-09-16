package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Roy-Wanyoike/Ryvex/internal/authz"
	"github.com/Roy-Wanyoike/Ryvex/internal/state"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

// ---- logger levels ----

func TestNewLoggerLevels(t *testing.T) {
	cases := []struct {
		name  string
		level string
		want  slog.Level
	}{
		{"debug", "debug", slog.LevelDebug},
		{"info", "info", slog.LevelInfo},
		{"warn", "warn", slog.LevelWarn},
		{"error", "error", slog.LevelError},
		{"empty defaults to info", "", slog.LevelInfo},
		{"case-insensitive", "WARN", slog.LevelWarn},
	}
	for _, c := range cases {
		log, err := newLogger(c.level)
		if err != nil {
			t.Fatalf("%s: newLogger(%q): %v", c.name, c.level, err)
		}
		// A handler must accept records at its configured level and
		// reject everything strictly below it (levels are spaced 4 apart).
		h := log.Handler()
		if !h.Enabled(context.Background(), c.want) {
			t.Errorf("%s: handler not enabled at %v", c.name, c.want)
		}
		if h.Enabled(context.Background(), c.want-4) {
			t.Errorf("%s: handler unexpectedly enabled below %v", c.name, c.want)
		}
	}
}

func TestNewLoggerRejectsInvalidLevel(t *testing.T) {
	for _, level := range []string{"trace", "verbose", "critical", "info "} {
		log, err := newLogger(level)
		if err == nil {
			t.Fatalf("newLogger(%q) = %v, want error", level, log)
		}
		if !strings.Contains(err.Error(), "invalid --log-level") {
			t.Errorf("newLogger(%q) error = %q, want invalid --log-level message", level, err)
		}
	}
}

// ---- env fallbacks ----

func TestEnvOr(t *testing.T) {
	t.Setenv("RYVEX_TEST_SET", "from-env")
	t.Setenv("RYVEX_TEST_EMPTY", "")
	cases := []struct {
		name string
		key  string
		def  string
		want string
	}{
		{"set env wins", "RYVEX_TEST_SET", "default", "from-env"},
		{"unset falls back", "RYVEX_TEST_UNSET", "fallback", "fallback"},
		{"empty env falls back", "RYVEX_TEST_EMPTY", "fallback", "fallback"},
		{"empty default when unset", "RYVEX_TEST_UNSET", "", ""},
	}
	for _, c := range cases {
		if got := envOr(c.key, c.def); got != c.want {
			t.Errorf("%s: envOr(%q, %q) = %q, want %q", c.name, c.key, c.def, got, c.want)
		}
	}
}

// Issue #83 flag fallbacks: float (--tracing-sample-ratio) and bool
// (--otlp-insecure) env reads, each falling back on unset OR invalid.
func TestEnvFloatOr(t *testing.T) {
	t.Setenv("RYVEX_TEST_F_SET", "0.25")
	t.Setenv("RYVEX_TEST_F_BAD", "not-a-float")
	t.Setenv("RYVEX_TEST_F_EMPTY", "")
	if got := envFloatOr("RYVEX_TEST_F_SET", 1.0); got != 0.25 {
		t.Errorf("envFloatOr set = %v, want 0.25", got)
	}
	for _, key := range []string{"RYVEX_TEST_F_UNSET", "RYVEX_TEST_F_BAD", "RYVEX_TEST_F_EMPTY"} {
		if got := envFloatOr(key, 1.0); got != 1.0 {
			t.Errorf("envFloatOr(%q) = %v, want fallback 1.0", key, got)
		}
	}
}

func TestEnvBoolOr(t *testing.T) {
	t.Setenv("RYVEX_TEST_B_SET", "true")
	t.Setenv("RYVEX_TEST_B_BAD", "maybe")
	t.Setenv("RYVEX_TEST_B_EMPTY", "")
	if got := envBoolOr("RYVEX_TEST_B_SET", false); got != true {
		t.Errorf("envBoolOr set = %v, want true", got)
	}
	for _, key := range []string{"RYVEX_TEST_B_UNSET", "RYVEX_TEST_B_BAD", "RYVEX_TEST_B_EMPTY"} {
		if got := envBoolOr(key, false); got != false {
			t.Errorf("envBoolOr(%q) = %v, want fallback false", key, got)
		}
	}
}

// ---- comma-list parsing ----

func TestSplitCommaList(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{"empty string is nil", "", nil},
		{"whitespace only is nil", "  \t ", nil},
		{"single entry", "https://a.example.com", []string{"https://a.example.com"}},
		{"plain list", "a,b,c", []string{"a", "b", "c"}},
		{"padded entries trimmed", " a , b ,c ", []string{"a", "b", "c"}},
		{"empty entries dropped", "a,,b,", []string{"a", "b"}},
		{"duplicates are preserved", "a,a,a", []string{"a", "a", "a"}},
	}
	for _, c := range cases {
		if got := splitCommaList(c.in); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: splitCommaList(%q) = %#v, want %#v", c.name, c.in, got, c.want)
		}
	}
}

// ---- seed idempotency ----

func TestSeedDemoDataIdempotent(t *testing.T) {
	store := state.NewStore()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx := context.Background()

	first, err := seedDemoData(ctx, store, log)
	if err != nil {
		t.Fatalf("first seed: %v", err)
	}
	if first == 0 {
		t.Fatalf("first seed created %d resources, want > 0", first)
	}

	// A restart must tolerate ErrAlreadyExists silently: the second run
	// reports zero creations and the store keeps exactly the first set.
	second, err := seedDemoData(ctx, store, log)
	if err != nil {
		t.Fatalf("second seed: %v (ErrAlreadyExists must be tolerated in place)", err)
	}
	if second != 0 {
		t.Fatalf("second seed created %d resources, want 0", second)
	}
	if got, err := store.Count(); err != nil || got != first {
		t.Fatalf("store holds %d resources after reseed (err=%v), want %d", got, err, first)
	}

	page, next, err := store.ListResources(state.ListOptions{})
	if err != nil {
		t.Fatalf("ListResources: %v", err)
	}
	if len(page) != first || next != "" {
		t.Fatalf("ListResources = %d items (next=%q), want %d and empty cursor", len(page), next, first)
	}

	apps, _, err := store.ListResources(state.ListOptions{Org: "acme", Kind: state.KindApplication})
	if err != nil {
		t.Fatalf("ListResources(applications): %v", err)
	}
	if len(apps) != 2 {
		t.Fatalf("seeded %d applications, want 2", len(apps))
	}

	// Spot-check one resource's kind/spec shape. Spec values round-trip
	// through JSON on create, so numbers come back as float64; compare
	// via marshalled JSON instead of direct typing.
	checkout, err := store.GetByLogicalKey("acme", "core", "prod", state.KindApplication, "checkout")
	if err != nil {
		t.Fatalf("GetByLogicalKey(checkout): %v", err)
	}
	if checkout.Kind != state.KindApplication || checkout.Org != "acme" ||
		checkout.Project != "core" || checkout.Env != "prod" || checkout.Name != "checkout" {
		t.Errorf("checkout scope = %s/%s/%s/%s/%s, want acme/core/prod/Application/checkout",
			checkout.Org, checkout.Project, checkout.Env, checkout.Kind, checkout.Name)
	}
	if checkout.Labels["managed-by"] != "ryvex" {
		t.Errorf("checkout labels = %v, want managed-by=ryvex", checkout.Labels)
	}
	gotSpec, err := json.Marshal(checkout.Spec)
	if err != nil {
		t.Fatalf("marshal checkout spec: %v", err)
	}
	wantSpec, err := json.Marshal(map[string]any{
		"image":    "registry.acme.io/checkout:1.42.0",
		"replicas": 4,
		"port":     8080,
	})
	if err != nil {
		t.Fatalf("marshal expected spec: %v", err)
	}
	if string(gotSpec) != string(wantSpec) {
		t.Errorf("checkout spec = %s, want %s", gotSpec, wantSpec)
	}
}

// ---- boot flag validation ----

// clearServeEnv pins every env fallback runServe reads while defining
// flags, so the boot tests are hermetic no matter the invoking shell.
func clearServeEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"RYVEX_HTTP_ADDR", "RYVEX_API_KEYS", "RYVEX_CORS_ORIGINS",
		"RYVEX_METRICS_ADDR", "RYVEX_DATABASE_URL", "RYVEX_WEBHOOK_SECRET",
		"RYVEX_NATS_URL",
		"RYVEX_OTLP_ENDPOINT", "RYVEX_OTLP_INSECURE", "RYVEX_TRACING_SAMPLE_RATIO",
	} {
		t.Setenv(k, "")
	}
}

// runServe validates --store and --bus backend selection before it
// starts any listener, so these error paths are in-process and touch
// no ports, timers, or signals.
func TestRunServeFlagValidation(t *testing.T) {
	clearServeEnv(t)
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"unsupported store", []string{"--store", "bogus"}, `unsupported store "bogus"`},
		{"unsupported bus", []string{"--bus", "bogus"}, `unsupported bus "bogus"`},
	}
	for _, c := range cases {
		err := runServe(c.args)
		if err == nil {
			t.Errorf("%s: runServe(%v) = nil, want error", c.name, c.args)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: error = %q, want substring %q", c.name, err, c.want)
		}
	}
}

// ---- tracing boot (issue #83) ----

// TestSetupTracing pins the enable semantics: empty endpoint = no-op
// default (nil provider, nil error — the zero-overhead default
// posture), an unsupported URL scheme is a boot error, and a valid
// endpoint boots the SDK provider (the exporter connects lazily, so
// no collector is needed here). The otel globals that setupTracing
// mutates on the enabled path are restored so other tests stay
// hermetic.
func TestSetupTracing(t *testing.T) {
	clearServeEnv(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	restore := func() {
		otel.SetTracerProvider(trace.NewNoopTracerProvider())
		otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
			propagation.TraceContext{}, propagation.Baggage{}))
	}

	// Disabled (default): no endpoint, no provider, no error.
	tp, err := setupTracing(context.Background(), log, "", false, 1.0)
	if err != nil {
		t.Errorf("setupTracing(\"\"): %v", err)
	}
	if tp != nil {
		t.Errorf("setupTracing(\"\") = %v; want nil", tp)
	}
	// Issue #122 regression: the return used to be the concrete
	// *sdktrace.TracerProvider, so this nil landed in the interface-typed
	// Options.TracerProvider fields as a typed nil — a non-nil interface
	// wrapping a nil pointer — and every `== nil` guard in reconcile,
	// api and webhook missed, panicking on the default boot. The value
	// the consumers receive must be a TRUE nil interface.
	var iface trace.TracerProvider = tp // exactly what reconcile.Options / api.ServerOptions / webhook.Options store
	if iface != nil {
		t.Errorf("setupTracing(\"\") stored into trace.TracerProvider = %#v; want a true nil interface (typed nil, issue #122)", iface)
	}

	// Unsupported scheme: refuse to boot with a bad endpoint.
	tp, err = setupTracing(context.Background(), log, "grpc://collector:4318", false, 1.0)
	if err == nil || tp != nil {
		t.Errorf("setupTracing(grpc://...) = %v, %v; want nil provider and an error", tp, err)
	}

	// Valid endpoint: the SDK provider boots (no dial happens here).
	t.Cleanup(restore)
	tp, err = setupTracing(context.Background(), log, "http://127.0.0.1:4318", false, 1.0)
	if err != nil {
		t.Fatalf("setupTracing(http://127.0.0.1:4318): %v", err)
	}
	if tp == nil {
		t.Fatal("setupTracing with a valid endpoint returned a nil provider")
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := tp.Shutdown(shutdownCtx); err != nil {
		t.Errorf("provider shutdown: %v", err)
	}
	// Host:port form — exactly what --help, the usage text and
	// .env.example advertise (issue #123): accepted, TLS by default
	// (the insecure flag stays false when not set).
	tp, err = setupTracing(context.Background(), log, "localhost:4318", false, 1.0)
	if err != nil {
		t.Fatalf("setupTracing(localhost:4318): %v", err)
	}
	if tp == nil {
		t.Fatal("setupTracing with a host:port endpoint returned a nil provider")
	}
	if err := tp.Shutdown(shutdownCtx); err != nil {
		t.Errorf("provider shutdown (host:port): %v", err)
	}
	restore()
}

// ---- OTLP endpoint forms (issue #123) ----

// TestNormalizeOTLPEndpoint pins the accepted --otlp-endpoint forms:
// the host:port form that --help and .env.example advertise (which the
// previous url.Parse-based code rejected by reading "localhost:4318"
// as scheme "localhost", issue #123), the explicit http:// and
// https:// URLs, and rejection of garbage.
func TestNormalizeOTLPEndpoint(t *testing.T) {
	cases := []struct {
		name      string
		endpoint  string
		insecure  bool
		wantHost  string
		wantInsec bool
		wantErr   bool
	}{
		// The documented host:port form — TLS by default (issue #123).
		{name: "host:port as documented", endpoint: "localhost:4318", wantHost: "localhost:4318"},
		{name: "fqdn:port", endpoint: "collector.otel.svc.cluster.local:4318", wantHost: "collector.otel.svc.cluster.local:4318"},
		{name: "host:port keeps --otlp-insecure", endpoint: "localhost:4318", insecure: true, wantHost: "localhost:4318", wantInsec: true},
		{name: "ipv6 host:port", endpoint: "[::1]:4318", wantHost: "[::1]:4318"},
		// Explicit URLs (pre-existing behavior, preserved).
		{name: "http URL forces insecure", endpoint: "http://127.0.0.1:4318", wantHost: "127.0.0.1:4318", wantInsec: true},
		{name: "http URL keeps explicit insecure", endpoint: "http://collector:4318", insecure: true, wantHost: "collector:4318", wantInsec: true},
		{name: "https URL keeps TLS", endpoint: "https://collector.example.com:4318", wantHost: "collector.example.com:4318"},
		// Garbage rejection.
		{name: "unknown scheme", endpoint: "grpc://collector:4318", wantErr: true},
		{name: "bare hostname without port", endpoint: "localhost", wantErr: true},
		{name: "port without host", endpoint: ":4318", wantErr: true},
		{name: "empty port", endpoint: "localhost:", wantErr: true},
		{name: "non-numeric port", endpoint: "localhost:otlp", wantErr: true},
		{name: "port out of range", endpoint: "localhost:99999", wantErr: true},
		{name: "scheme URL without host", endpoint: "http://", wantErr: true},
		{name: "unbracketed ipv6 (too many colons)", endpoint: "::1:4318", wantErr: true},
		{name: "prose garbage", endpoint: "not a collector, honestly", wantErr: true},
	}
	for _, c := range cases {
		gotHost, gotInsec, err := normalizeOTLPEndpoint(c.endpoint, c.insecure)
		if c.wantErr {
			if err == nil {
				t.Errorf("%s: normalizeOTLPEndpoint(%q) = %q, %v; want error", c.name, c.endpoint, gotHost, gotInsec)
			} else if !strings.Contains(err.Error(), "invalid --otlp-endpoint") {
				t.Errorf("%s: error = %v, want the invalid --otlp-endpoint message", c.name, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: normalizeOTLPEndpoint(%q): %v", c.name, c.endpoint, err)
			continue
		}
		if gotHost != c.wantHost || gotInsec != c.wantInsec {
			t.Errorf("%s: normalizeOTLPEndpoint(%q) = %q, %v; want %q, %v", c.name, c.endpoint, gotHost, gotInsec, c.wantHost, c.wantInsec)
		}
	}
}

// ---- default boot smoke test (issue #122) ----

// TestRunServeDefaultBootSmoke boots the full daemon in-process with
// default flags — no --otlp-endpoint, exactly the README quickstart —
// which was impossible before #122: the typed-nil TracerProvider
// panicked inside reconcile.New before any listener could come up.
// Pins the acceptance points: /readyz answers 200, responses carry NO
// X-Ryvex-Trace-Id header (tracing stays off without an endpoint),
// and cancelling the lifetime context shuts the daemon down cleanly.
func TestRunServeDefaultBootSmoke(t *testing.T) {
	clearServeEnv(t)

	// Reserve a free port, then release it for the daemon. The tiny
	// bind-close-bind window is the accepted trade-off of in-process
	// boot tests; a collision just fails the run, not the machine.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	addr := l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatalf("release reserved port: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- runServeContext(ctx, []string{"--http", addr}) }()

	// Poll /readyz until the daemon is up (or dies early).
	client := &http.Client{Timeout: 2 * time.Second}
	readyz := "http://" + addr + "/readyz"
	var resp *http.Response
	deadline := time.Now().Add(15 * time.Second)
	for {
		select {
		case err := <-errCh:
			t.Fatalf("runServeContext exited before becoming ready: %v", err)
		default:
		}
		r, getErr := client.Get(readyz)
		if getErr == nil {
			if r.StatusCode == http.StatusOK {
				resp = r
				break
			}
			r.Body.Close()
		}
		if time.Now().After(deadline) {
			t.Fatalf("/readyz never returned 200 (last error: %v)", getErr)
		}
		time.Sleep(50 * time.Millisecond)
	}
	defer resp.Body.Close()

	// Tracing is OFF on the default boot: X-Ryvex-Trace-Id must be
	// absent outright (the #83 contract is absent, never empty-valued).
	if _, present := resp.Header[http.CanonicalHeaderKey("X-Ryvex-Trace-Id")]; present {
		t.Errorf("X-Ryvex-Trace-Id present on the default boot; tracing must stay disabled without --otlp-endpoint")
	}
	if resp.Header.Get("X-Request-Id") == "" {
		t.Error("X-Request-Id response header missing on /readyz")
	}

	// Graceful shutdown: cancelling the lifetime context (the test
	// stand-in for SIGTERM) must return nil from runServeContext.
	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("runServeContext shutdown: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("runServeContext did not return after lifetime cancel")
	}
}

// ---- version stamp ----

func TestVersionIsStamped(t *testing.T) {
	if Version == "" {
		t.Fatal("Version is empty, want a non-empty build stamp")
	}
}

// ---- bootstrap key seeding (issue #73) ----

func TestSeedBootstrapKeysRegistersAdminResources(t *testing.T) {
	store := state.NewStore()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	token := "ryk_bootstrap_unit_0001"
	seedBootstrapKeys(store, map[string]string{token: "root"}, log)

	// The resource must exist under the PRINCIPAL name (not the token —
	// the regression this test pins: the seed loop used to swap the two,
	// so every bootstrap seed failed validation while the static digest
	// path silently kept the token admin).
	res, err := store.GetByLogicalKey(state.ReservedOrg, state.ReservedProject, state.ReservedEnv, state.KindAPIKey, "root")
	if err != nil {
		t.Fatalf("bootstrap resource for principal root: %v", err)
	}
	spec, err := state.ParseAPIKeySpec(res.Spec)
	if err != nil {
		t.Fatalf("parse seeded spec: %v", err)
	}
	if !authz.HasRole(spec.Roles, state.RoleAdmin) {
		t.Fatalf("bootstrap roles = %v, want admin", spec.Roles)
	}
	if want := authz.HashToken(token); spec.KeyHash != want {
		t.Fatalf("seeded hash = %s, want sha256 of the configured token", spec.KeyHash)
	}

	// Seeding plus one Refresh is exactly the boot ordering runServe
	// uses, so the very first request after boot authenticates.
	az := authz.New(store, nil, authz.Options{Logger: log})
	if err := az.Refresh(); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if p, ok := az.Authenticate(token); !ok || p != "root" {
		t.Fatalf("bootstrap token must authenticate after seed+refresh: p=%q ok=%v", p, ok)
	}
}
