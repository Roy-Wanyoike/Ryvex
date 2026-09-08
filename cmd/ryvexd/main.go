// ryvexd is the Ryvex control plane daemon.
package main

import (
	"fmt"
	"os"
)

// Version is stamped at build time in CI; the default reflects the
// current release of the control plane.
var Version = "v1.1.0"

const usage = `ryvexd — the Ryvex control plane daemon

Usage:
  ryvexd serve [flags]    start the HTTP control plane
  ryvexd version          print version information

Flags (serve):
  --http addr          listen address (default ":8080", env RYVEX_HTTP_ADDR)
  --store kind         state backend: "memory" (default) or "postgres" (requires --dsn)
  --dsn url            Postgres DSN (required when --store=postgres, env RYVEX_DATABASE_URL)
  --bus kind           event bus backend: "memory" (default) or "nats" (JetStream)
  --nats-url url       NATS server URL used when --bus=nats (default "nats://127.0.0.1:4222", env RYVEX_NATS_URL)
  --dev-auth           accept any well-formed ryk_ bearer token (dev only; refused with
                       --store postgres / --bus nats unless RYVEX_ALLOW_DEV_AUTH=1)
  --api-keys list      comma-separated name=token pairs of static API keys (env RYVEX_API_KEYS)
  --cors-origins list  comma-separated browser origins allowed to call the API (env RYVEX_CORS_ORIGINS)
  --webhook-secret key HMAC key material for webhook signatures (random per boot when unset, env RYVEX_WEBHOOK_SECRET)
  --metrics-addr addr  dedicated listen address for /metrics (empty disables, env RYVEX_METRICS_ADDR)
  --seed               load the demo dataset on boot
  --log-level lvl      debug | info | warn | error (default info)
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = runServe(os.Args[2:])
	case "version", "--version", "-v":
		fmt.Printf("ryvexd %s\n", Version)
	case "help", "--help", "-h":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "ryvexd:", err)
		os.Exit(1)
	}
}
