// ryvexd is the Ryvex control plane daemon.
package main

import (
	"fmt"
	"os"
)

// Version is stamped at build time in CI; the default reflects the
// current release of the control plane.
var Version = "v1.0.0"

const usage = `ryvexd — the Ryvex control plane daemon

Usage:
  ryvexd serve [flags]    start the HTTP control plane
  ryvexd version          print version information

Flags (serve):
  --http addr      listen address (default ":8080", env RYVEX_HTTP_ADDR)
  --store kind     state backend: "memory" (default)
  --dev-auth       accept any well-formed ryk_ bearer token (dev only)
  --api-keys list  comma-separated name=token pairs of static API keys
  --seed           load the demo dataset on boot
  --log-level lvl  debug | info | warn | error (default info)
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
