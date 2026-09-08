//go:build integration

package main

// Integration suite: exercises the CLI end-to-end against a real
// control plane assembled in-process (store + bus + reconciler + API),
// the same stack `ryvexd serve` boots. Skipped by default; run with:
//
//	go test -tags integration ./cmd/ryvex/

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Roy-Wanyoike/Ryvex/internal/api"
	"github.com/Roy-Wanyoike/Ryvex/internal/bus"
	"github.com/Roy-Wanyoike/Ryvex/internal/reconcile"
	"github.com/Roy-Wanyoike/Ryvex/internal/state"
)

// newTestPlane boots the full control plane stack in-process with
// dev-auth enabled, mirroring `ryvexd serve --dev-auth`.
func newTestPlane(t *testing.T) *httptest.Server {
	t.Helper()
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))

	store := state.NewStore()
	eventBus := bus.New()
	rec := reconcile.New(store, eventBus, reconcile.Options{
		Interval:    50 * time.Millisecond,
		Concurrency: 2,
		Logger:      quiet,
	})
	srv := httptest.NewServer(api.NewServer(store, eventBus, rec, api.ServerOptions{
		Auth:   api.AuthOptions{DevAuth: true},
		Logger: quiet,
	}))
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		rec.Stop(2 * time.Second)
		srv.Close()
	})
	rec.Start(ctx)
	return srv
}

func writeFixture(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "resource.json")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}

func TestE2EFullResourceLifecycle(t *testing.T) {
	plane := newTestPlane(t)
	url := plane.URL
	fixture := writeFixture(t, `{"kind":"Application","org":"e2e","project":"core","env":"prod","name":"app1","spec":{"image":"demo:1","replicas":1}}`)

	// apply from file
	code, out, errOut := captureCLI(t, strings.NewReader(""), "--api", url, "--token", "ryk_e2e_test", "apply", "-f", fixture)
	if code != 0 {
		t.Fatalf("apply: code=%d stderr=%q", code, errOut)
	}
	if !strings.Contains(out, "created r-") || !strings.Contains(out, "e2e/core/prod/Application/app1") {
		t.Fatalf("apply output = %q", out)
	}
	id := strings.Fields(out)[1]

	// apply from stdin
	stdinFixture := `{"kind":"Cache","org":"e2e","project":"core","env":"prod","name":"cache1","spec":{"max_memory":"256mb"}}`
	code, out, errOut = captureCLI(t, strings.NewReader(stdinFixture), "--api", url, "--token", "ryk_e2e_test", "apply", "-f", "-")
	if code != 0 {
		t.Fatalf("apply stdin: code=%d stderr=%q", code, errOut)
	}
	if !strings.Contains(out, "created r-") {
		t.Fatalf("apply stdin output = %q", out)
	}

	// get by scope address (table)
	code, out, errOut = captureCLI(t, strings.NewReader(""), "--api", url, "--token", "ryk_e2e_test", "get", "e2e/core/prod/Application/app1")
	if code != 0 {
		t.Fatalf("get scope: code=%d stderr=%q", code, errOut)
	}
	for _, want := range []string{"KIND", "NAME", "ENV", "PHASE", "GEN", "AGE", "Application", "app1", "prod"} {
		if !strings.Contains(out, want) {
			t.Fatalf("get table output %q missing %q", out, want)
		}
	}

	// get by handle ID (json): full document round-trip
	code, out, errOut = captureCLI(t, strings.NewReader(""), "--api", url, "--token", "ryk_e2e_test", "-o", "json", "get", id)
	if code != 0 {
		t.Fatalf("get id: code=%d stderr=%q", code, errOut)
	}
	var doc struct {
		ID         string `json:"id"`
		Kind       string `json:"kind"`
		Env        string `json:"env"`
		Generation int64  `json:"generation"`
		Spec       map[string]any
		Status     struct {
			Phase string `json:"phase"`
		} `json:"status"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("get id json: %v (out=%q)", err, out)
	}
	if doc.ID != id || doc.Kind != "Application" || doc.Env != "prod" || doc.Generation < 1 || doc.Status.Phase == "" {
		t.Fatalf("get id json decoded = %+v", doc)
	}

	// reconcile trigger
	code, out, errOut = captureCLI(t, strings.NewReader(""), "--api", url, "--token", "ryk_e2e_test", "reconcile", "e2e", id)
	if code != 0 || !strings.Contains(out, "accepted") || !strings.Contains(out, id) {
		t.Fatalf("reconcile: code=%d out=%q stderr=%q", code, out, errOut)
	}

	// events (bus subjects for the org)
	code, out, errOut = captureCLI(t, strings.NewReader(""), "--api", url, "--token", "ryk_e2e_test", "events", "e2e", "--limit", "5")
	if code != 0 {
		t.Fatalf("events: code=%d stderr=%q", code, errOut)
	}
	for _, want := range []string{"SUBJECT", "ryvex.resource.e2e.application.created", "app1"} {
		if !strings.Contains(out, want) {
			t.Fatalf("events output %q missing %q", out, want)
		}
	}

	// audit trail (actor attributed via dev-auth)
	code, out, errOut = captureCLI(t, strings.NewReader(""), "--api", url, "--token", "ryk_e2e_test", "audit", "e2e", "--limit", "5")
	if code != 0 {
		t.Fatalf("audit: code=%d stderr=%q", code, errOut)
	}
	for _, want := range []string{"ACTOR", "ACTION", "KEY", "AGE", "dev:e2e_test", "created", "e2e/core/prod/Application/app1"} {
		if !strings.Contains(out, want) {
			t.Fatalf("audit output %q missing %q", out, want)
		}
	}

	// health (no auth)
	code, out, errOut = captureCLI(t, strings.NewReader(""), "--api", url, "health")
	if code != 0 || !strings.Contains(out, "status") || !strings.Contains(out, "ok") {
		t.Fatalf("health: code=%d out=%q stderr=%q", code, out, errOut)
	}

	// delete by scope address, then get must 404 with the error envelope
	code, out, errOut = captureCLI(t, strings.NewReader(""), "--api", url, "--token", "ryk_e2e_test", "delete", "e2e/core/prod/Application/app1")
	if code != 0 || !strings.Contains(out, "deleted e2e/core/prod/Application/app1") {
		t.Fatalf("delete: code=%d out=%q stderr=%q", code, out, errOut)
	}
	code, _, errOut = captureCLI(t, strings.NewReader(""), "--api", url, "--token", "ryk_e2e_test", "get", "e2e/core/prod/Application/app1")
	if code != 1 || !strings.HasPrefix(errOut, "ryvex: resource not found (code=not_found, request_id=") {
		t.Fatalf("get after delete: code=%d err=%q", code, errOut)
	}
}

func TestE2EAuthEnforcement(t *testing.T) {
	plane := newTestPlane(t)
	url := plane.URL

	// health never needs a token
	if code, _, _ := captureCLI(t, strings.NewReader(""), "--api", url, "health"); code != 0 {
		t.Fatalf("health without token must succeed")
	}

	// token without the ryk_ prefix (rejected by dev-auth) -> server 401
	// envelope on stderr, exit 1
	code, _, errOut := captureCLI(t, strings.NewReader(""), "--api", url, "--token", "bad_token", "get", "e2e/core/prod/Application/app1")
	if code != 1 || !strings.Contains(errOut, "ryvex: ") || !strings.Contains(errOut, "(code=unauthorized, request_id=") {
		t.Fatalf("wrong token: code=%d err=%q", code, errOut)
	}

	// missing token on a write command -> client-side usage error, exit 2
	t.Setenv("RYVEX_TOKEN", "")
	code, _, errOut = captureCLI(t, strings.NewReader(""), "--api", url, "apply", "-f", "-")
	if code != 2 || !strings.Contains(errOut, "RYVEX_TOKEN") {
		t.Fatalf("missing token: code=%d err=%q", code, errOut)
	}
}

func TestE2EUsageErrors(t *testing.T) {
	plane := newTestPlane(t)
	url := plane.URL

	cases := []struct {
		name string
		args []string
	}{
		{"unknown command", []string{"frobnicate"}},
		{"partial scope address", []string{"--api", url, "--token", "ryk_e2e_test", "get", "e2e/core/prod/Application"}},
		{"missing -f", []string{"--api", url, "--token", "ryk_e2e_test", "apply"}},
		{"bad output format", []string{"--api", url, "-o", "yaml", "health"}},
		{"reconcile missing id", []string{"--api", url, "--token", "ryk_e2e_test", "reconcile", "e2e"}},
	}
	for _, c := range cases {
		if code, _, _ := captureCLI(t, strings.NewReader(""), c.args...); code != 2 {
			t.Fatalf("%s: code = %d, want 2", c.name, code)
		}
	}
}
