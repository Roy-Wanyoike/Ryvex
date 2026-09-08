package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// captureCLI swaps the package IO streams, runs one CLI invocation and
// returns the exit code plus captured stdout and stderr.
func captureCLI(t *testing.T, in io.Reader, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	oldOut, oldErr, oldIn := stdout, stderr, stdin
	stdout, stderr, stdin = &out, &errb, in
	defer func() { stdout, stderr, stdin = oldOut, oldErr, oldIn }()
	code := run(args)
	return code, out.String(), errb.String()
}

// ---- address parsing ----

func TestParseAddressHandleID(t *testing.T) {
	a, err := parseAddress("r-00b52b6eb859f432")
	if err != nil {
		t.Fatalf("parseAddress: %v", err)
	}
	if a.id != "r-00b52b6eb859f432" || a.org != "" {
		t.Fatalf("want handle address, got %+v", a)
	}
	if got, want := a.path(), "/v1/resources/r-00b52b6eb859f432"; got != want {
		t.Fatalf("path = %q, want %q", got, want)
	}
	if got, want := a.String(), "r-00b52b6eb859f432"; got != want {
		t.Fatalf("String = %q, want %q", got, want)
	}
}

func TestParseAddressScope(t *testing.T) {
	const addr = "acme/core/prod/Application/checkout"
	a, err := parseAddress(addr)
	if err != nil {
		t.Fatalf("parseAddress: %v", err)
	}
	if a.id != "" || a.org != "acme" || a.project != "core" || a.env != "prod" || a.kind != "Application" || a.name != "checkout" {
		t.Fatalf("want scope address, got %+v", a)
	}
	if got, want := a.path(), "/v1/acme/core/prod/Application/checkout"; got != want {
		t.Fatalf("path = %q, want %q", got, want)
	}
	if got, want := a.String(), addr; got != want {
		t.Fatalf("String = %q, want %q", got, want)
	}
}

func TestParseAddressRejectsMalformed(t *testing.T) {
	for _, in := range []string{"", "/", "a/b", "a/b/c", "a/b/c/d", "a/b/c/d/e/f", "acme//prod/Application/x", "acme/core/prod//x"} {
		a, err := parseAddress(in)
		if err == nil {
			t.Fatalf("parseAddress(%q) = %+v, want error", in, a)
		}
		var ue usageError
		if !errors.As(err, &ue) {
			t.Fatalf("parseAddress(%q) error %T is not a usageError", in, err)
		}
	}
}

func TestAddressPathEscapesSegments(t *testing.T) {
	a, err := parseAddress("r 1")
	if err != nil {
		t.Fatalf("parseAddress: %v", err)
	}
	if got, want := a.path(), "/v1/resources/r%201"; got != want {
		t.Fatalf("path = %q, want %q", got, want)
	}
	a, err = parseAddress("acme/core/prod/Application/big name")
	if err != nil {
		t.Fatalf("parseAddress: %v", err)
	}
	if got, want := a.path(), "/v1/acme/core/prod/Application/big%20name"; got != want {
		t.Fatalf("path = %q, want %q", got, want)
	}
}

// ---- global flag parsing ----

func TestParseGlobalsDefaults(t *testing.T) {
	t.Setenv("RYVEX_API", "")
	t.Setenv("RYVEX_TOKEN", "")
	g, rest, err := parseGlobals([]string{"get", "r-1"})
	if err != nil {
		t.Fatalf("parseGlobals: %v", err)
	}
	if g.api != DefaultAPI {
		t.Fatalf("api = %q, want %q", g.api, DefaultAPI)
	}
	if g.token != "" {
		t.Fatalf("token = %q, want empty", g.token)
	}
	if g.out != "table" {
		t.Fatalf("out = %q, want table", g.out)
	}
	if len(rest) != 2 || rest[0] != "get" || rest[1] != "r-1" {
		t.Fatalf("rest = %v, want [get r-1]", rest)
	}
}

func TestParseGlobalsEnvAndFlags(t *testing.T) {
	t.Setenv("RYVEX_API", "http://env-ryvexd:1")
	t.Setenv("RYVEX_TOKEN", "ryk_env")
	g, rest, err := parseGlobals([]string{"--api", "http://flag-ryvexd:2", "--token=ryk_flag", "-o", "json", "health"})
	if err != nil {
		t.Fatalf("parseGlobals: %v", err)
	}
	if g.api != "http://flag-ryvexd:2" {
		t.Fatalf("api flag should override env, got %q", g.api)
	}
	if g.token != "ryk_flag" {
		t.Fatalf("token flag should override env, got %q", g.token)
	}
	if g.out != "json" {
		t.Fatalf("out = %q, want json", g.out)
	}
	if len(rest) != 1 || rest[0] != "health" {
		t.Fatalf("rest = %v, want [health]", rest)
	}
}

func TestParseGlobalsRejectsBadFormat(t *testing.T) {
	_, _, err := parseGlobals([]string{"-o", "yaml", "health"})
	if err == nil || !strings.Contains(err.Error(), "invalid -o") {
		t.Fatalf("err = %v, want invalid -o message", err)
	}
}

func TestParseGlobalsStopsAtSubcommand(t *testing.T) {
	// Flags after the subcommand belong to the subcommand; the global
	// parser must not consume (or reject) them.
	g, rest, err := parseGlobals([]string{"get", "--limit", "5"})
	if err != nil {
		t.Fatalf("parseGlobals: %v", err)
	}
	if g.out != "table" || len(rest) != 3 || rest[0] != "get" {
		t.Fatalf("globals = %+v rest = %v, want table + [get --limit 5]", g, rest)
	}
}

func TestParseCmdArgsFlagsAmongPositionals(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want []string
		n    int
	}{
		{"flag after positional", []string{"acme", "--limit", "3"}, []string{"acme"}, 3},
		{"flag before positional", []string{"--limit", "3", "acme"}, []string{"acme"}, 3},
		{"equals form", []string{"--limit=7", "acme"}, []string{"acme"}, 7},
		{"multiple positionals", []string{"e2e", "r-1"}, []string{"e2e", "r-1"}, 0},
		{"terminator", []string{"e2e", "--", "--limit", "3"}, []string{"e2e", "--limit", "3"}, 0},
	}
	for _, c := range cases {
		fs := flag.NewFlagSet("events", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		n := fs.Int("limit", 0, "")
		pos, err := parseCmdArgs(fs, c.args)
		if err != nil {
			t.Fatalf("%s: parseCmdArgs: %v", c.name, err)
		}
		if *n != c.n {
			t.Errorf("%s: limit = %d, want %d", c.name, *n, c.n)
		}
		if strings.Join(pos, "|") != strings.Join(c.want, "|") {
			t.Errorf("%s: pos = %v, want %v", c.name, pos, c.want)
		}
	}
}

func TestParseCmdArgsRejectsUnknownFlag(t *testing.T) {
	fs := flag.NewFlagSet("events", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Int("limit", 0, "")
	if _, err := parseCmdArgs(fs, []string{"acme", "--bogus"}); err == nil {
		t.Fatal("want error for unknown flag")
	}
}

// ---- table rendering ----

func TestTableRenderFixedWidth(t *testing.T) {
	var buf bytes.Buffer
	tb := newTable("KIND", "NAME", "PHASE")
	tb.addRow("Application", "checkout", "Ready")
	tb.addRow("Database", "db", "Pending")
	tb.render(&buf)
	want := "KIND         NAME      PHASE\n" +
		"Application  checkout  Ready\n" +
		"Database     db        Pending\n"
	if buf.String() != want {
		t.Fatalf("render =\n%q\nwant\n%q", buf.String(), want)
	}
}

func TestTableRenderHeaderOnly(t *testing.T) {
	var buf bytes.Buffer
	newTable("A", "B").render(&buf)
	if got, want := buf.String(), "A  B\n"; got != want {
		t.Fatalf("render = %q, want %q", got, want)
	}
}

func TestRenderKV(t *testing.T) {
	var buf bytes.Buffer
	renderKV(&buf, [][2]string{{"status", "ok"}, {"resources", "15"}})
	want := "status     ok\nresources  15\n"
	if buf.String() != want {
		t.Fatalf("renderKV = %q, want %q", buf.String(), want)
	}
}

func TestAge(t *testing.T) {
	cases := []struct {
		d    time.Duration
		want string
	}{
		{0, "0s"},
		{45 * time.Second, "45s"},
		{90 * time.Second, "1m"},
		{5 * time.Minute, "5m"},
		{3 * time.Hour, "3h"},
		{23*time.Hour + 59*time.Minute, "23h"},
		{24 * time.Hour, "1d"},
		{5 * 24 * time.Hour, "5d"},
	}
	for _, c := range cases {
		if got := age(time.Now().Add(-c.d)); got != c.want {
			t.Errorf("age(-%s) = %q, want %q", c.d, got, c.want)
		}
	}
	if got := age(time.Time{}); got != "unknown" {
		t.Errorf("age(zero) = %q, want unknown", got)
	}
}

// ---- dispatch and exit codes ----

func TestRunHelpAndVersion(t *testing.T) {
	if code, out, _ := captureCLI(t, strings.NewReader(""), "help"); code != 0 || !strings.Contains(out, "Exit codes:") {
		t.Fatalf("help: code=%d out=%q", code, out)
	}
	if code, out, _ := captureCLI(t, strings.NewReader(""), "version"); code != 0 || !strings.HasPrefix(out, "ryvex ") {
		t.Fatalf("version: code=%d out=%q", code, out)
	}
}

func TestRunNoArgsAndUnknownCommand(t *testing.T) {
	if code, _, errOut := captureCLI(t, strings.NewReader("")); code != 2 || !strings.Contains(errOut, "Usage:") {
		t.Fatalf("no args: code=%d err=%q", code, errOut)
	}
	code, _, errOut := captureCLI(t, strings.NewReader(""), "frobnicate")
	if code != 2 || !strings.Contains(errOut, `unknown command "frobnicate"`) {
		t.Fatalf("unknown command: code=%d err=%q", code, errOut)
	}
}

func TestRunGlobalUsageError(t *testing.T) {
	code, _, errOut := captureCLI(t, strings.NewReader(""), "-o", "yaml", "health")
	if code != 2 || !strings.Contains(errOut, "invalid -o") {
		t.Fatalf("code=%d err=%q", code, errOut)
	}
}

func TestRunWriteCommandRequiresToken(t *testing.T) {
	t.Setenv("RYVEX_TOKEN", "")
	for _, args := range [][]string{
		{"apply", "-f", "x.json"},
		{"delete", "r-1"},
		{"reconcile", "acme", "r-1"},
	} {
		code, _, errOut := captureCLI(t, strings.NewReader(""), args...)
		if code != 2 || !strings.Contains(errOut, "RYVEX_TOKEN") {
			t.Fatalf("%v: code=%d err=%q, want exit 2 mentioning RYVEX_TOKEN", args, code, errOut)
		}
	}
}

// ---- end-to-end dispatch against httptest (no external server) ----

func TestRunGetAPIErrorEnvelope(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":{"code":"not_found","message":"resource not found","request_id":"e3b0c44298fc"}}`))
	}))
	defer srv.Close()

	code, _, errOut := captureCLI(t, strings.NewReader(""), "--api", srv.URL, "--token", "ryk_test", "get", "r-missing")
	if code != 1 {
		t.Fatalf("code = %d, want 1", code)
	}
	want := "ryvex: resource not found (code=not_found, request_id=e3b0c44298fc)\n"
	if errOut != want {
		t.Fatalf("err = %q, want %q", errOut, want)
	}
}

// ---- list: scope parsing and path building ----

func TestParseScope(t *testing.T) {
	cases := []struct {
		in   string
		want scope
	}{
		{"", scope{}},
		{"acme", scope{org: "acme"}},
		{"acme/core", scope{org: "acme", project: "core"}},
		{"acme/core/prod", scope{org: "acme", project: "core", env: "prod"}},
		{"acme/core/prod/Application", scope{org: "acme", project: "core", env: "prod", kind: "Application"}},
	}
	for _, c := range cases {
		sc, err := parseScope(c.in)
		if err != nil {
			t.Fatalf("parseScope(%q): %v", c.in, err)
		}
		if sc != c.want {
			t.Errorf("parseScope(%q) = %+v, want %+v", c.in, sc, c.want)
		}
	}
	for _, in := range []string{"a/b/c/d/e", "acme/", "/core", "acme//prod", "acme/core/"} {
		if sc, err := parseScope(in); err == nil {
			t.Fatalf("parseScope(%q) = %+v, want error", in, sc)
		}
	}
}

func TestScopeListPathFilteredRoute(t *testing.T) {
	// Coarser selectors use the filtered /v1/resources route, which
	// carries real pagination; query values go through url.Values.
	sc, err := parseScope("acme/core")
	if err != nil {
		t.Fatalf("parseScope: %v", err)
	}
	if got, want := sc.listPath(5, ""), "/v1/resources?limit=5&org=acme&project=core"; got != want {
		t.Fatalf("listPath = %q, want %q", got, want)
	}
	if got, want := sc.listPath(50, "tok"), "/v1/resources?cursor=tok&limit=50&org=acme&project=core"; got != want {
		t.Fatalf("listPath = %q, want %q", got, want)
	}
	if got, want := (scope{}).listPath(1, ""), "/v1/resources?limit=1"; got != want {
		t.Fatalf("listPath = %q, want %q", got, want)
	}
}

func TestScopeListPathScopeRouteEscapesSegments(t *testing.T) {
	// A kind pins the 4-segment scope route; segments are escaped
	// exactly like address.path().
	sc, err := parseScope("acme/core/prod/Application")
	if err != nil {
		t.Fatalf("parseScope: %v", err)
	}
	if got, want := sc.listPath(7, "tok"), "/v1/acme/core/prod/Application?cursor=tok&limit=7"; got != want {
		t.Fatalf("listPath = %q, want %q", got, want)
	}
	sc, err = parseScope("ac me/core/pr od/App lication")
	if err != nil {
		t.Fatalf("parseScope: %v", err)
	}
	if got, want := sc.listPath(50, ""), "/v1/ac%20me/core/pr%20od/App%20lication?limit=50"; got != want {
		t.Fatalf("listPath = %q, want %q", got, want)
	}
}

func TestRunListRejectsBadArgs(t *testing.T) {
	for _, args := range [][]string{
		{"list", "acme", "--limit", "0"},
		{"list", "acme", "--limit", "201"},
		{"list", "acme", "--limit", "-3"},
		{"list", "a", "b"},
		{"list", "a/b/c/d/e"},
		{"list", "acme//core"},
	} {
		code, _, errOut := captureCLI(t, strings.NewReader(""), args...)
		if code != 2 {
			t.Fatalf("%v: code = %d, want 2 (err=%q)", args, code, errOut)
		}
	}
}

func TestRunListTableAndCursorHint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"items":[` +
			`{"id":"r-1","kind":"Application","org":"acme","project":"core","env":"prod","name":"checkout","generation":3,"status":{"phase":"Ready"},"created_at":"2026-01-01T00:00:00Z"},` +
			`{"id":"r-2","kind":"Database","org":"acme","project":"core","env":"prod","name":"orders","generation":1,"status":{"phase":"Pending"},"created_at":"2026-01-01T00:00:00Z"}` +
			`],"next_cursor":"AA"}`))
	}))
	defer srv.Close()

	code, out, errOut := captureCLI(t, strings.NewReader(""), "--api", srv.URL, "--token", "ryk_test", "list", "acme", "--limit", "2")
	if code != 0 || errOut != "" {
		t.Fatalf("code=%d err=%q", code, errOut)
	}
	for _, want := range []string{"ID", "KIND", "NAME", "ENV", "PHASE", "GEN", "AGE", "r-1", "Application", "checkout", "r-2", "Pending"} {
		if !strings.Contains(out, want) {
			t.Fatalf("list output %q missing %q", out, want)
		}
	}
	if !strings.Contains(out, "\nnext_cursor: AA\n") {
		t.Fatalf("list output %q missing next_cursor hint", out)
	}

	code, out, _ = captureCLI(t, strings.NewReader(""), "--api", srv.URL, "-o", "json", "list", "acme")
	if code != 0 || !strings.Contains(out, `"next_cursor": "AA"`) || !strings.Contains(out, `"id": "r-1"`) {
		t.Fatalf("json list: code=%d out=%q", code, out)
	}
}

func TestRunListEmptyAndNoHint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"items":[],"next_cursor":""}`))
	}))
	defer srv.Close()

	code, out, errOut := captureCLI(t, strings.NewReader(""), "--api", srv.URL, "list", "acme")
	if code != 0 || errOut != "" {
		t.Fatalf("code=%d err=%q", code, errOut)
	}
	if want := "no resources\n"; out != want {
		t.Fatalf("out = %q, want %q", out, want)
	}
}

// ---- apply CAS (--generation) ----

func TestCASRequestBuildsPathAndBody(t *testing.T) {
	doc := []byte(`{"kind":"Application","org":"acme","project":"core","env":"prod","name":"check out",` +
		`"spec":{"image":"c:1","replicas":4},"labels":{"team":"payments"},"note":"kept"}`)
	path, body, err := casRequest(doc, 7)
	if err != nil {
		t.Fatalf("casRequest: %v", err)
	}
	if got, want := path, "/v1/acme/core/prod/Application/check%20out"; got != want {
		t.Fatalf("path = %q, want %q", got, want)
	}
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("body: %v", err)
	}
	if m["generation"] != float64(7) {
		t.Fatalf("generation = %v, want 7", m["generation"])
	}
	spec, ok := m["spec"].(map[string]any)
	if !ok || spec["image"] != "c:1" || spec["replicas"] != float64(4) {
		t.Fatalf("spec not preserved: %v", m["spec"])
	}
	labels, ok := m["labels"].(map[string]any)
	if !ok || labels["team"] != "payments" {
		t.Fatalf("labels not preserved: %v", m["labels"])
	}
	if m["note"] != "kept" {
		t.Fatalf("unknown fields must survive: %v", m)
	}
}

func TestCASRequestRejectsMissingIdentity(t *testing.T) {
	for _, doc := range []string{
		`null`,
		`[]`,
		`{"kind":"Application","org":"acme","project":"core","env":"prod"}`,
		`{"kind":"Application","org":"acme","project":"core","env":"prod","name":""}`,
	} {
		_, _, err := casRequest([]byte(doc), 1)
		if err == nil {
			t.Fatalf("casRequest(%q) = nil error, want usage error", doc)
		}
		var ue usageError
		if !errors.As(err, &ue) {
			t.Fatalf("casRequest(%q) error %T is not a usageError", doc, err)
		}
	}
}

func TestGenerationFromDetails(t *testing.T) {
	if n, ok := generationFromDetails([]string{"current_generation=9"}); !ok || n != 9 {
		t.Fatalf("got %d,%v want 9,true", n, ok)
	}
	if _, ok := generationFromDetails([]string{"other", "current_generation=bad"}); ok {
		t.Fatal("malformed hint must not parse")
	}
	if _, ok := generationFromDetails(nil); ok {
		t.Fatal("empty details must not parse")
	}
}

func TestRunApplyCASUpsert(t *testing.T) {
	t.Run("update returns 200", func(t *testing.T) {
		var gotMethod, gotPath string
		var gotBody []byte
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotMethod, gotPath = r.Method, r.URL.Path
			gotBody, _ = io.ReadAll(r.Body)
			_, _ = w.Write([]byte(`{"id":"r-1","kind":"Application","org":"acme","project":"core","env":"prod","name":"checkout","generation":2,"status":{"phase":"Ready"}}`))
		}))
		defer srv.Close()

		doc := `{"kind":"Application","org":"acme","project":"core","env":"prod","name":"checkout","spec":{"image":"c:2"}}`
		code, out, errOut := captureCLI(t, strings.NewReader(doc), "--api", srv.URL, "--token", "ryk_test", "apply", "--generation", "1", "-f", "-")
		if code != 0 || errOut != "" {
			t.Fatalf("code=%d err=%q", code, errOut)
		}
		if gotMethod != http.MethodPut {
			t.Fatalf("method = %q, want PUT", gotMethod)
		}
		if gotPath != "/v1/acme/core/prod/Application/checkout" {
			t.Fatalf("path = %q", gotPath)
		}
		var m map[string]any
		if err := json.Unmarshal(gotBody, &m); err != nil || m["generation"] != float64(1) {
			t.Fatalf("CAS body = %s (err=%v)", gotBody, err)
		}
		if want := "updated r-1 (generation 2)\n"; out != want {
			t.Fatalf("out = %q, want %q", out, want)
		}
	})

	t.Run("create returns 201", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":"r-9","kind":"Cache","org":"acme","project":"core","env":"prod","name":"sessions","generation":1}`))
		}))
		defer srv.Close()

		doc := `{"kind":"Cache","org":"acme","project":"core","env":"prod","name":"sessions","spec":{"engine":"redis"}}`
		code, out, errOut := captureCLI(t, strings.NewReader(doc), "--api", srv.URL, "--token", "ryk_test", "apply", "--generation", "1", "-f", "-")
		if code != 0 || errOut != "" {
			t.Fatalf("code=%d err=%q", code, errOut)
		}
		if want := "created r-9 (acme/core/prod/Cache/sessions)\n"; out != want {
			t.Fatalf("out = %q, want %q", out, want)
		}
	})
}

func TestRunApplyCASConflictFetchesCurrentGeneration(t *testing.T) {
	var gets int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPut:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"error":{"code":"conflict","message":"generation conflict: resource was modified concurrently","request_id":"abc123","details":[]}}`))
		case http.MethodGet:
			gets++
			_, _ = w.Write([]byte(`{"id":"r-1","kind":"Application","org":"acme","project":"core","env":"prod","name":"checkout","generation":5}`))
		}
	}))
	defer srv.Close()

	doc := `{"kind":"Application","org":"acme","project":"core","env":"prod","name":"checkout","spec":{"image":"c:2"}}`
	code, _, errOut := captureCLI(t, strings.NewReader(doc), "--api", srv.URL, "--token", "ryk_test", "apply", "--generation", "2", "-f", "-")
	if code != 1 {
		t.Fatalf("code = %d, want 1", code)
	}
	if gets != 1 {
		t.Fatalf("conflict must re-read the resource once, got %d GETs", gets)
	}
	want := "ryvex: generation conflict: resource is at generation 5, not 2; re-fetch and retry with --generation 5 (code=conflict, request_id=abc123)\n"
	if errOut != want {
		t.Fatalf("err = %q, want %q", errOut, want)
	}
}

func TestRunApplyCASConflictUsesDetailsHint(t *testing.T) {
	// When the envelope carries a current_generation detail the CLI
	// must not spend a round trip re-reading the resource.
	var gets int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			gets++
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"error":{"code":"conflict","message":"generation conflict: resource was modified concurrently","request_id":"xyz","details":["current_generation=9"]}}`))
	}))
	defer srv.Close()

	doc := `{"kind":"Application","org":"acme","project":"core","env":"prod","name":"checkout","spec":{"image":"c:2"}}`
	code, _, errOut := captureCLI(t, strings.NewReader(doc), "--api", srv.URL, "--token", "ryk_test", "apply", "--generation", "4", "-f", "-")
	if code != 1 || gets != 0 {
		t.Fatalf("code=%d gets=%d, want 1 and 0", code, gets)
	}
	if !strings.Contains(errOut, "resource is at generation 9, not 4") || !strings.Contains(errOut, "(code=conflict, request_id=xyz)") {
		t.Fatalf("err = %q", errOut)
	}
}

func TestRunApplyCASConflictUnreadableResourceKeepsEnvelope(t *testing.T) {
	// If the follow-up GET also fails, the original 409 envelope is
	// surfaced unchanged rather than swallowed.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"error":{"code":"conflict","message":"generation conflict: resource was modified concurrently","request_id":"abc123","details":[]}}`))
	}))
	defer srv.Close()

	doc := `{"kind":"Application","org":"acme","project":"core","env":"prod","name":"checkout","spec":{"image":"c:2"}}`
	code, _, errOut := captureCLI(t, strings.NewReader(doc), "--api", srv.URL, "--token", "ryk_test", "apply", "--generation", "2", "-f", "-")
	if code != 1 {
		t.Fatalf("code = %d, want 1", code)
	}
	want := "ryvex: generation conflict: resource was modified concurrently (code=conflict, request_id=abc123)\n"
	if errOut != want {
		t.Fatalf("err = %q, want %q", errOut, want)
	}
}

func TestRunHealthLive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"status":"ok","service":"ryvexd","version":"v1.0.0","resources":3,"time":"2026-01-01T00:00:00Z"}`))
	}))
	defer srv.Close()

	code, out, errOut := captureCLI(t, strings.NewReader(""), "--api", srv.URL, "health")
	if code != 0 || errOut != "" {
		t.Fatalf("code=%d err=%q", code, errOut)
	}
	for _, want := range []string{"status", "ok", "ryvexd", "v1.0.0", "resources", "3"} {
		if !strings.Contains(out, want) {
			t.Fatalf("health output %q missing %q", out, want)
		}
	}

	code, out, _ = captureCLI(t, strings.NewReader(""), "--api", srv.URL, "-o", "json", "health")
	if code != 0 || !strings.Contains(out, `"resources": 3`) {
		t.Fatalf("json health: code=%d out=%q", code, out)
	}
}
