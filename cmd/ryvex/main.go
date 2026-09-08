// ryvex is the operator CLI for the Ryvex control plane API. It speaks
// the frozen /v1 contract documented in docs/api-contracts.md: global
// flags come before the subcommand, table output is the default and
// JSON is one flag away, and API failures surface the error envelope
// on stderr with exit code 1.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
)

// Version is stamped at build time in CI; the default reflects the
// current release of the control plane.
var Version = "v1.0.0"

// DefaultAPI is the control plane base URL used when neither --api
// nor RYVEX_API is set.
const DefaultAPI = "http://127.0.0.1:8080"

// IO streams live at package scope so tests can capture CLI output.
var (
	stdin  io.Reader = os.Stdin
	stdout io.Writer = os.Stdout
	stderr io.Writer = os.Stderr
)

const usage = `ryvex — the operator CLI for the Ryvex control plane

Usage:
  ryvex [global flags] <command> [args]

Commands:
  apply        create a resource from a JSON file (POST /v1/resources),
               or CAS-upsert it at its scope address (--generation, PUT)
  list         list resources by scope: [org[/project/env[/kind]]]
  get          fetch a resource by <id> or <org>/<project>/<env>/<kind>/<name>
  delete       delete a resource by <id> or scope address
  events       recent bus events for an org
  audit        audit trail entries for an org
  reconcile    trigger an immediate reconcile for a resource
  health       control plane liveness, version and resource count (no auth)

Global flags (before the command):
  --api url     control plane base URL (default "http://127.0.0.1:8080", env RYVEX_API)
  --token tok   bearer API key, ryk_… (env RYVEX_TOKEN; required for write commands)
  -o fmt        output format: table | json (default table)

Command flags:
  apply -f file            resource JSON file, or - for stdin
  apply --generation n     CAS upsert: PUT at the doc's scope address, 409 if stale
  list [org[/project/env[/kind]]]
                           --limit n (default 50, max 200), --cursor tok
  events <org>             --limit n (default: server default)
  audit <org>              --limit n, --kind k
  reconcile <org> <id>     trigger an immediate reconcile

Examples:
  ryvex health
  ryvex --api http://127.0.0.1:18202 --token ryk_local_dev apply -f app.json
  ryvex --token ryk_local_dev get acme/core/prod/Application/checkout
  ryvex --token ryk_local_dev -o json get r-00b52b6eb859f432
  ryvex list acme/core
  ryvex list acme/core/prod/applications --limit 100
  ryvex --token ryk_local_dev apply --generation 2 -f app.json
  ryvex events acme --limit 10

Exit codes:
  0  success
  1  API error (error envelope printed to stderr)
  2  usage error
`

// globals are the flags accepted before the subcommand.
type globals struct {
	api   string
	token string
	out   string // table | json
}

func main() {
	os.Exit(run(os.Args[1:]))
}

// run dispatches one CLI invocation and returns the process exit
// code: 0 success, 1 API error, 2 usage error.
func run(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "help", "--help", "-h":
		fmt.Fprint(stdout, usage)
		return 0
	case "version", "--version", "-v":
		fmt.Fprintf(stdout, "ryvex %s\n", Version)
		return 0
	}

	g, rest, err := parseGlobals(args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(stdout, usage)
			return 0
		}
		fmt.Fprintf(stderr, "ryvex: %s\n\n%s", err, usage)
		return 2
	}
	if len(rest) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}

	switch rest[0] {
	case "help", "--help", "-h":
		fmt.Fprint(stdout, usage)
		return 0
	case "version", "--version", "-v":
		fmt.Fprintf(stdout, "ryvex %s\n", Version)
		return 0
	case "apply", "delete", "reconcile":
		if g.token == "" {
			fmt.Fprintln(stderr, "ryvex: no API token for a write command; pass --token or set RYVEX_TOKEN")
			return 2
		}
	}

	commands := map[string]func(io.Writer, globals, []string) error{
		"apply":     runApply,
		"list":      runList,
		"get":       runGet,
		"delete":    runDelete,
		"events":    runEvents,
		"audit":     runAudit,
		"reconcile": runReconcile,
		"health":    runHealth,
	}
	fn, ok := commands[rest[0]]
	if !ok {
		fmt.Fprintf(stderr, "unknown command %q\n\n%s", rest[0], usage)
		return 2
	}
	if err := fn(stdout, g, rest[1:]); err != nil {
		return exitCodeFor(err)
	}
	return 0
}

// exitCodeFor maps command errors onto exit codes: API errors print
// their decoded envelope (exit 1), usage mistakes exit 2, and
// anything else (I/O, transport) is reported and exits 1.
func exitCodeFor(err error) int {
	var ae *ApiError
	if errors.As(err, &ae) {
		fmt.Fprintln(stderr, ae)
		return 1
	}
	var ue usageError
	if errors.As(err, &ue) {
		fmt.Fprintf(stderr, "ryvex: %s\n", ue.msg)
		return 2
	}
	fmt.Fprintln(stderr, "ryvex:", err)
	return 1
}

// parseGlobals consumes the flags that must precede the subcommand.
// flag.Parse stops at the first non-flag argument, so the remainder
// is returned untouched for subcommand dispatch.
func parseGlobals(args []string) (globals, []string, error) {
	fs := flag.NewFlagSet("ryvex", flag.ContinueOnError)
	fs.SetOutput(io.Discard) // failures print the hand-written usage instead
	var g globals
	fs.StringVar(&g.api, "api", envOr("RYVEX_API", DefaultAPI), "control plane base URL")
	fs.StringVar(&g.token, "token", os.Getenv("RYVEX_TOKEN"), "bearer API key (ryk_…)")
	fs.StringVar(&g.out, "o", "table", "output format: table | json")
	if err := fs.Parse(args); err != nil {
		return globals{}, nil, err
	}
	switch g.out {
	case "table", "json":
	default:
		return globals{}, nil, usageErrorf("invalid -o %q: want table or json", g.out)
	}
	return g, fs.Args(), nil
}

// usageError marks a client-side mistake — bad flags, malformed
// address, wrong argument count — that exits with code 2.
type usageError struct{ msg string }

func (e usageError) Error() string { return e.msg }

func usageErrorf(format string, a ...any) usageError {
	return usageError{msg: fmt.Sprintf(format, a...)}
}

// address is a parsed resource locator: either the opaque handle ID
// or the 5-segment logical scope address org/project/env/kind/name.
type address struct {
	id                            string
	org, project, env, kind, name string
}

// parseAddress auto-detects the two address forms used by get/delete:
// a single segment is a handle ID, exactly five segments is a scope
// address; anything else is a usage error.
func parseAddress(s string) (address, error) {
	seg := strings.Split(s, "/")
	switch len(seg) {
	case 1:
		if seg[0] == "" {
			return address{}, usageErrorf("empty resource address")
		}
		return address{id: seg[0]}, nil
	case 5:
		for i, x := range seg {
			if x == "" {
				return address{}, usageErrorf("invalid scope address %q: empty segment %d", s, i+1)
			}
		}
		return address{org: seg[0], project: seg[1], env: seg[2], kind: seg[3], name: seg[4]}, nil
	default:
		return address{}, usageErrorf("invalid address %q: want <id> or <org>/<project>/<env>/<kind>/<name>", s)
	}
}

// path builds the API path for the address: handle-addressed
// resources live under /v1/resources/{id}, logical addresses under
// /v1/{org}/….
func (a address) path() string {
	if a.id != "" {
		return "/v1/resources/" + url.PathEscape(a.id)
	}
	parts := []string{a.org, a.project, a.env, a.kind, a.name}
	for i, p := range parts {
		parts[i] = url.PathEscape(p)
	}
	return "/v1/" + strings.Join(parts, "/")
}

// String renders the address the way the user typed it.
func (a address) String() string {
	if a.id != "" {
		return a.id
	}
	return strings.Join([]string{a.org, a.project, a.env, a.kind, a.name}, "/")
}

// newFlagSet builds a subcommand flag set in the ryvexd house style;
// parse failures surface as usage errors (exit 2).
func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	return fs
}

// parseCmdArgs parses subcommand flags wherever they appear among the
// positional arguments, so both `events acme --limit 3` and
// `events --limit 3 acme` work. The stdlib FlagSet stops at the first
// non-flag token, so it is fed the remaining args repeatedly and each
// leftover head is collected as a positional. Everything after a bare
// "--" terminator is positional.
func parseCmdArgs(fs *flag.FlagSet, args []string) ([]string, error) {
	for i, a := range args {
		if a == "--" {
			pos, err := parseCmdArgs(fs, args[:i])
			if err != nil {
				return nil, err
			}
			return append(pos, args[i+1:]...), nil
		}
	}
	var pos []string
	rest := args
	for {
		if err := fs.Parse(rest); err != nil {
			return nil, usageError{err.Error()}
		}
		unconsumed := fs.Args()
		if len(unconsumed) == 0 {
			return pos, nil
		}
		pos = append(pos, unconsumed[0])
		rest = unconsumed[1:]
	}
}

// envOr falls back to def when the environment variable is unset or
// empty (same helper as ryvexd serve).
func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// readInput loads the bytes behind -f: a file path, or stdin for "-".
func readInput(name string) ([]byte, error) {
	if name == "-" {
		return io.ReadAll(stdin)
	}
	return os.ReadFile(name)
}
