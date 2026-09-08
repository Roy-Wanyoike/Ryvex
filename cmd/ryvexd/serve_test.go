package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"reflect"
	"strings"
	"testing"

	"github.com/Roy-Wanyoike/Ryvex/internal/state"
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
	if got := store.Count(); got != first {
		t.Fatalf("store holds %d resources after reseed, want %d", got, first)
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

// ---- version stamp ----

func TestVersionIsStamped(t *testing.T) {
	if Version == "" {
		t.Fatal("Version is empty, want a non-empty build stamp")
	}
}
