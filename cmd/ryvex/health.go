package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
)

// runHealth implements `ryvex health` against GET /healthz, which is
// unauthenticated per the API contract, printing status, version and
// resource count. The server withholds "resources" from
// anonymous/unauthorized probes (issue #38): the table shows "-" for
// a withheld count instead of 0, which would read as an empty store
// (issue #121). In -o json mode the raw response is passed through
// verbatim, so a withheld count stays omitted — absent consistently
// means withheld, never "empty store".
func runHealth(w io.Writer, g globals, args []string) error {
	fs := newFlagSet("health")
	pos, err := parseCmdArgs(fs, args)
	if err != nil {
		return err
	}
	if len(pos) > 0 {
		return usageErrorf("health takes no arguments (got %d)", len(pos))
	}
	raw, err := g.client().Do(http.MethodGet, "/healthz", nil)
	if err != nil {
		return err
	}
	if g.out == "json" {
		return dumpJSON(w, raw)
	}
	var h healthDoc
	if err := json.Unmarshal(raw, &h); err != nil {
		return fmt.Errorf("unexpected response from control plane: %w", err)
	}
	resources := "-"
	if h.Resources != nil {
		resources = strconv.Itoa(*h.Resources)
	}
	renderKV(w, [][2]string{
		{"status", h.Status},
		{"service", h.Service},
		{"version", h.Version},
		{"resources", resources},
	})
	return nil
}
