package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// runList implements `ryvex list [org[/project/env[/kind]]]`: with a
// kind it calls the scope list endpoint GET /v1/{org}/{project}/{env}/{kind},
// coarser selectors fall back to the filtered GET /v1/resources route
// (the server only routes 4-segment paths to the scope list, so there
// is no 1-3 segment scope shape). Table mode renders the same columns
// as get plus the resource ID, which operators need for
// `ryvex reconcile <org> <id>`; when the response carries a
// next_cursor, a resume hint is printed. -o json dumps the raw
// response envelope untouched.
func runList(w io.Writer, g globals, args []string) error {
	fs := newFlagSet("list")
	limit := fs.Int("limit", 50, "max resources per page, 1-200 (default 50)")
	cursor := fs.String("cursor", "", "resume from the next_cursor of a previous page")
	pos, err := parseCmdArgs(fs, args)
	if err != nil {
		return err
	}
	if len(pos) > 1 {
		return usageErrorf("list takes at most one scope: [org[/project/env[/kind]]] (got %d arguments)", len(pos))
	}
	if *limit < 1 || *limit > 200 {
		return usageErrorf("invalid --limit %d: must be between 1 and 200", *limit)
	}
	sc, err := parseScope(pos[0])
	if err != nil {
		return err
	}
	raw, err := g.client().Do(http.MethodGet, sc.listPath(*limit, *cursor), nil)
	if err != nil {
		return err
	}
	if g.out == "json" {
		return dumpJSON(w, raw)
	}
	var page listPage
	if err := json.Unmarshal(raw, &page); err != nil {
		return fmt.Errorf("unexpected response from control plane: %w", err)
	}
	if len(page.Items) == 0 {
		fmt.Fprintln(w, "no resources")
		return nil
	}
	t := newTable("ID", "KIND", "NAME", "ENV", "PHASE", "GEN", "AGE")
	for _, r := range page.Items {
		t.addRow(r.ID, r.Kind, r.Name, r.Env, r.Status.Phase,
			strconv.FormatInt(r.Generation, 10), age(r.CreatedAt))
	}
	t.render(w)
	if page.NextCursor != "" {
		fmt.Fprintf(w, "\nnext_cursor: %s\n", page.NextCursor)
	}
	return nil
}

// scope is the optional org/project/env/kind selector of `ryvex list`.
type scope struct {
	org, project, env, kind string
}

// parseScope splits the optional list selector: one to four segments,
// none empty (same rule as parseAddress). An empty string selects
// everything.
func parseScope(s string) (scope, error) {
	if s == "" {
		return scope{}, nil
	}
	seg := strings.Split(s, "/")
	if len(seg) > 4 {
		return scope{}, usageErrorf("invalid scope %q: want [org[/project/env[/kind]]]", s)
	}
	for i, x := range seg {
		if x == "" {
			return scope{}, usageErrorf("invalid scope %q: empty segment %d", s, i+1)
		}
	}
	sc := scope{org: seg[0]}
	if len(seg) > 1 {
		sc.project = seg[1]
	}
	if len(seg) > 2 {
		sc.env = seg[2]
	}
	if len(seg) > 3 {
		sc.kind = seg[3]
	}
	return sc, nil
}

// listPath builds the API path for the selector. A kind pins the
// request to the 4-segment scope route; coarser selectors use the
// filtered /v1/resources route, which carries real pagination
// (next_cursor) end to end. Segments are escaped exactly like
// address.path(); query values go through url.Values.
func (sc scope) listPath(limit int, cursor string) string {
	q := url.Values{}
	if limit > 0 {
		q.Set("limit", strconv.Itoa(limit))
	}
	if cursor != "" {
		q.Set("cursor", cursor)
	}
	if sc.kind != "" {
		parts := make([]string, 0, 4)
		for _, p := range []string{sc.org, sc.project, sc.env, sc.kind} {
			parts = append(parts, url.PathEscape(p))
		}
		return "/v1/" + strings.Join(parts, "/") + querySuffix(q)
	}
	if sc.org != "" {
		q.Set("org", sc.org)
	}
	if sc.project != "" {
		q.Set("project", sc.project)
	}
	if sc.env != "" {
		q.Set("env", sc.env)
	}
	return "/v1/resources" + querySuffix(q)
}
