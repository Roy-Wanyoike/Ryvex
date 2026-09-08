package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
)

// runGet implements `ryvex get <id | org/project/env/kind/name>`,
// auto-detecting handle vs scope addressing, and renders the classic
// KIND NAME ENV PHASE GEN AGE row in table mode. -o json dumps the
// full document untouched.
func runGet(w io.Writer, g globals, args []string) error {
	fs := newFlagSet("get")
	pos, err := parseCmdArgs(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usageErrorf("get takes exactly one address: <id> or <org>/<project>/<env>/<kind>/<name> (got %d arguments)", len(pos))
	}
	addr, err := parseAddress(pos[0])
	if err != nil {
		return err
	}
	raw, err := g.client().Do(http.MethodGet, addr.path(), nil)
	if err != nil {
		return err
	}
	if g.out == "json" {
		return dumpJSON(w, raw)
	}
	var res resourceDoc
	if err := json.Unmarshal(raw, &res); err != nil {
		return fmt.Errorf("unexpected response from control plane: %w", err)
	}
	t := newTable("KIND", "NAME", "ENV", "PHASE", "GEN", "AGE")
	t.addRow(res.Kind, res.Name, res.Env, res.Status.Phase,
		strconv.FormatInt(res.Generation, 10), age(res.CreatedAt))
	t.render(w)
	return nil
}
