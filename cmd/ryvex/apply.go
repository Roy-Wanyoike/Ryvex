package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// runApply implements `ryvex apply -f FILE`: it posts the resource
// document to /v1/resources and prints the assigned ID in table mode.
func runApply(w io.Writer, g globals, args []string) error {
	fs := newFlagSet("apply")
	file := fs.String("f", "", "resource JSON file, or - for stdin")
	pos, err := parseCmdArgs(fs, args)
	if err != nil {
		return err
	}
	if len(pos) > 0 {
		return usageErrorf("apply takes no positional arguments (got %q); global flags go before the command", strings.Join(pos, " "))
	}
	if *file == "" {
		return usageErrorf("missing -f FILE (use -f - to read stdin)")
	}
	body, err := readInput(*file)
	if err != nil {
		return err
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return usageErrorf("no input: %s is empty", *file)
	}
	raw, err := g.client().Do(http.MethodPost, "/v1/resources", body)
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
	fmt.Fprintf(w, "created %s (%s)\n", res.ID, res.address())
	return nil
}
