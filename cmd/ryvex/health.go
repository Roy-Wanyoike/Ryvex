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
// resource count.
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
	renderKV(w, [][2]string{
		{"status", h.Status},
		{"service", h.Service},
		{"version", h.Version},
		{"resources", strconv.Itoa(h.Resources)},
	})
	return nil
}
