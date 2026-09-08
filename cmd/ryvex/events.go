package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
)

// runEvents implements `ryvex events <org> [--limit n]` against
// GET /v1/{org}/events, rendering SUBJECT KIND NAME AGE in table mode.
func runEvents(w io.Writer, g globals, args []string) error {
	fs := newFlagSet("events")
	limit := fs.Int("limit", 0, "max events to return (server default 100)")
	pos, err := parseCmdArgs(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usageErrorf("events takes exactly one org (got %d arguments)", len(pos))
	}
	q := url.Values{}
	if *limit > 0 {
		q.Set("limit", strconv.Itoa(*limit))
	}
	path := "/v1/" + url.PathEscape(pos[0]) + "/events" + querySuffix(q)
	raw, err := g.client().Do(http.MethodGet, path, nil)
	if err != nil {
		return err
	}
	if g.out == "json" {
		return dumpJSON(w, raw)
	}
	var page eventsPage
	if err := json.Unmarshal(raw, &page); err != nil {
		return fmt.Errorf("unexpected response from control plane: %w", err)
	}
	if len(page.Events) == 0 {
		fmt.Fprintln(w, "no events")
		return nil
	}
	t := newTable("SUBJECT", "KIND", "NAME", "AGE")
	for _, e := range page.Events {
		t.addRow(e.Subject, e.Kind, e.Name, age(e.Time))
	}
	t.render(w)
	return nil
}
