package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// runDelete implements `ryvex delete <id | org/project/env/kind/name>`
// and prints a one-line confirmation in table mode.
func runDelete(w io.Writer, g globals, args []string) error {
	fs := newFlagSet("delete")
	pos, err := parseCmdArgs(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usageErrorf("delete takes exactly one address: <id> or <org>/<project>/<env>/<kind>/<name> (got %d arguments)", len(pos))
	}
	addr, err := parseAddress(pos[0])
	if err != nil {
		return err
	}
	if _, err := g.client().Do(http.MethodDelete, addr.path(), nil); err != nil {
		return err
	}
	if g.out == "json" {
		payload, err := json.Marshal(map[string]string{"status": "deleted", "address": addr.String()})
		if err != nil {
			return err
		}
		fmt.Fprintln(w, string(payload))
		return nil
	}
	fmt.Fprintf(w, "deleted %s\n", addr.String())
	return nil
}
