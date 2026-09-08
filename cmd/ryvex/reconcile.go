package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// runReconcile implements `ryvex reconcile <org> <id>` against
// POST /v1/{org}/reconcile/{id} and prints the accepted status.
func runReconcile(w io.Writer, g globals, args []string) error {
	fs := newFlagSet("reconcile")
	pos, err := parseCmdArgs(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 2 {
		return usageErrorf("reconcile takes <org> <resource-id> (got %d arguments)", len(pos))
	}
	org, id := pos[0], pos[1]
	path := "/v1/" + url.PathEscape(org) + "/reconcile/" + url.PathEscape(id)
	raw, err := g.client().Do(http.MethodPost, path, nil)
	if err != nil {
		return err
	}
	if g.out == "json" {
		return dumpJSON(w, raw)
	}
	var out reconcileDoc
	if err := json.Unmarshal(raw, &out); err != nil {
		return fmt.Errorf("unexpected response from control plane: %w", err)
	}
	if out.Reason != "" {
		fmt.Fprintf(w, "reconcile %s for %s (%s)\n", out.Status, out.ResourceID, out.Reason)
	} else {
		fmt.Fprintf(w, "reconcile %s for %s\n", out.Status, out.ResourceID)
	}
	return nil
}
