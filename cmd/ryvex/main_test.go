package main

import (
	"bytes"
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
