//go:build integration

package main

// Integration suite: exercises the CLI end-to-end against a real
// control plane assembled in-process (store + bus + reconciler + API),
// the same stack `ryvexd serve` boots. Skipped by default; run with:
//
//      go test -tags integration ./cmd/ryvex/

import (
	"context"
	"encoding/json"
	"fmt"
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

func TestE2EListPagination(t *testing.T) {
	plane := newTestPlane(t)
	url := plane.URL

	// Three applications in a dedicated org, so page boundaries are
	// deterministic regardless of what other tests created.
	for _, name := range []string{"app-1", "app-2", "app-3"} {
		fixture := writeFixture(t, fmt.Sprintf(`{"kind":"Application","org":"pager","project":"core","env":"prod","name":%q,"spec":{"image":"demo:1"}}`, name))
		if code, _, errOut := captureCLI(t, strings.NewReader(""), "--api", url, "--token", "ryk_e2e_test", "apply", "-f", fixture); code != 0 {
			t.Fatalf("apply %s: code=%d stderr=%q", name, code, errOut)
		}
	}

	// Page 1: --limit 2 rows plus the next_cursor hint.
	code, out, errOut := captureCLI(t, strings.NewReader(""), "--api", url, "--token", "ryk_e2e_test", "list", "pager", "--limit", "2")
	if code != 0 || errOut != "" {
		t.Fatalf("list page 1: code=%d stderr=%q", code, errOut)
	}
	if rows := strings.Count(out, "\nr-"); rows != 2 {
		t.Fatalf("page 1 rows = %d, want 2 (out=%q)", rows, out)
	}
	idx := strings.Index(out, "next_cursor: ")
	if idx < 0 {
		t.Fatalf("page 1 output %q missing next_cursor hint", out)
	}
	cursor := strings.TrimSpace(out[idx+len("next_cursor: "):])
	page1 := out

	// Page 2: the remaining row via --cursor, no further hint.
	code, out, errOut = captureCLI(t, strings.NewReader(""), "--api", url, "--token", "ryk_e2e_test", "list", "pager", "--limit", "2", "--cursor", cursor)
	if code != 0 || errOut != "" {
		t.Fatalf("list page 2: code=%d stderr=%q", code, errOut)
	}
	if rows := strings.Count(out, "\nr-"); rows != 1 {
		t.Fatalf("page 2 rows = %d, want 1 (out=%q)", rows, out)
	}
	if strings.Contains(out, "next_cursor") {
		t.Fatalf("last page must not hint, got %q", out)
	}

	// Both pages together cover everything that was created.
	all := page1 + out
	for _, name := range []string{"app-1", "app-2", "app-3"} {
		if !strings.Contains(all, name) {
			t.Fatalf("pages missing %q (out=%q)", name, all)
		}
	}

	// -o json dumps the raw envelope, next_cursor included.
	code, out, errOut = captureCLI(t, strings.NewReader(""), "--api", url, "--token", "ryk_e2e_test", "-o", "json", "list", "pager")
	if code != 0 || errOut != "" {
		t.Fatalf("json list: code=%d stderr=%q", code, errOut)
	}
	var page struct {
		Items []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"items"`
		NextCursor string `json:"next_cursor"`
	}
	if err := json.Unmarshal([]byte(out), &page); err != nil {
		t.Fatalf("json list decode: %v (out=%q)", err, out)
	}
	if len(page.Items) != 3 || page.NextCursor != "" {
		t.Fatalf("json list decoded = %+v", page)
	}

	// A kind selector pins the 4-segment scope route; this server
	// version always answers next_cursor "" there.
	code, out, errOut = captureCLI(t, strings.NewReader(""), "--api", url, "--token", "ryk_e2e_test", "list", "pager/core/prod/applications")
	if code != 0 || errOut != "" {
		t.Fatalf("scope list: code=%d stderr=%q", code, errOut)
	}
	for _, name := range []string{"app-1", "app-2", "app-3"} {
		if !strings.Contains(out, name) {
			t.Fatalf("scope list output %q missing %q", out, name)
		}
	}
	if strings.Contains(out, "next_cursor") {
		t.Fatalf("scope route must not hint while the server sends \"\", got %q", out)
	}

	// Unknown org: empty result, not an error.
	code, out, errOut = captureCLI(t, strings.NewReader(""), "--api", url, "--token", "ryk_e2e_test", "list", "nosuchorg")
	if code != 0 || out != "no resources\n" {
		t.Fatalf("unknown org: code=%d out=%q stderr=%q", code, out, errOut)
	}
}

func TestE2EApplyCASGeneration(t *testing.T) {
	plane := newTestPlane(t)
	url := plane.URL

	// Plain POST create (no --generation): unchanged behavior.
	fixture := writeFixture(t, `{"kind":"Application","org":"casorg","project":"core","env":"prod","name":"svc","spec":{"image":"demo:1","replicas":1}}`)
	code, out, errOut := captureCLI(t, strings.NewReader(""), "--api", url, "--token", "ryk_e2e_test", "apply", "-f", fixture)
	if code != 0 {
		t.Fatalf("apply: code=%d stderr=%q", code, errOut)
	}
	id := strings.Fields(out)[1]

	// CAS apply with the current generation 1: spec change is
	// accepted and bumps the stored document to generation 2.
	update := writeFixture(t, `{"kind":"Application","org":"casorg","project":"core","env":"prod","name":"svc","spec":{"image":"demo:2","replicas":2}}`)
	code, out, errOut = captureCLI(t, strings.NewReader(""), "--api", url, "--token", "ryk_e2e_test", "apply", "--generation", "1", "-f", update)
	if code != 0 {
		t.Fatalf("CAS update: code=%d stderr=%q", code, errOut)
	}
	if !strings.Contains(out, "updated "+id) || !strings.Contains(out, "generation 2") {
		t.Fatalf("CAS update output = %q", out)
	}
	code, out, errOut = captureCLI(t, strings.NewReader(""), "--api", url, "--token", "ryk_e2e_test", "-o", "json", "get", id)
	if code != 0 {
		t.Fatalf("get after CAS update: code=%d stderr=%q", code, errOut)
	}
	var doc struct {
		Generation int64 `json:"generation"`
		Spec       struct {
			Image string `json:"image"`
		} `json:"spec"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil || doc.Generation != 2 || doc.Spec.Image != "demo:2" {
		t.Fatalf("get after CAS update: gen=%d spec=%v (err=%v)", doc.Generation, doc.Spec, err)
	}

	// Stale --generation 1 against the now-generation-2 resource:
	// 409 with the server's current generation on stderr, exit 1.
	code, _, errOut = captureCLI(t, strings.NewReader(""), "--api", url, "--token", "ryk_e2e_test", "apply", "--generation", "1", "-f", update)
	if code != 1 {
		t.Fatalf("stale CAS: code = %d, want 1", code)
	}
	staleWant := "ryvex: generation conflict: resource is at generation 2, not 1; re-fetch and retry with --generation 2 (code=conflict, request_id="
	if !strings.HasPrefix(errOut, staleWant) || !strings.HasSuffix(errOut, ")\n") {
		t.Fatalf("stale CAS stderr = %q, want prefix %q", errOut, staleWant)
	}

	// CAS upsert to a fresh address creates (201), and a document
	// without an identity is a client-side usage error.
	fresh := writeFixture(t, `{"kind":"Cache","org":"casorg","project":"core","env":"prod","name":"sessions","spec":{"engine":"redis"}}`)
	code, out, errOut = captureCLI(t, strings.NewReader(""), "--api", url, "--token", "ryk_e2e_test", "apply", "--generation", "1", "-f", fresh)
	if code != 0 || !strings.Contains(out, "created r-") {
		t.Fatalf("CAS create: code=%d out=%q stderr=%q", code, out, errOut)
	}
	code, _, errOut = captureCLI(t, strings.NewReader(`{"kind":"Application"}`), "--api", url, "--token", "ryk_e2e_test", "apply", "--generation", "1", "-f", "-")
	if code != 2 || !strings.Contains(errOut, "scope address") {
		t.Fatalf("CAS without identity: code=%d stderr=%q, want exit 2", code, errOut)
	}
}
