package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
)

// runAudit implements `ryvex audit <org> [--limit n] [--kind k]`
// against GET /v1/{org}/audit, rendering ACTOR ACTION KEY AGE in
// table mode.
func runAudit(w io.Writer, g globals, args []string) error {
	fs := newFlagSet("audit")
	limit := fs.Int("limit", 0, "max entries to return (server default 100)")
	kind := fs.String("kind", "", "filter by resource kind")
	pos, err := parseCmdArgs(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usageErrorf("audit takes exactly one org (got %d arguments)", len(pos))
	}
	q := url.Values{}
	if *limit > 0 {
		q.Set("limit", strconv.Itoa(*limit))
	}
	if *kind != "" {
		q.Set("kind", *kind)
	}
	path := "/v1/" + url.PathEscape(pos[0]) + "/audit" + querySuffix(q)
	raw, err := g.client().Do(http.MethodGet, path, nil)
	if err != nil {
		return err
	}
	if g.out == "json" {
		return dumpJSON(w, raw)
	}
	var page auditPage
	if err := json.Unmarshal(raw, &page); err != nil {
		return fmt.Errorf("unexpected response from control plane: %w", err)
	}
	if len(page.Entries) == 0 {
		fmt.Fprintln(w, "no audit entries")
		return nil
	}
	t := newTable("ACTOR", "ACTION", "KEY", "AGE")
	for _, e := range page.Entries {
		t.addRow(e.Actor, e.Action, e.LogicalKey, age(e.Time))
	}
	t.render(w)
	return nil
}
