package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// runApply implements `ryvex apply -f FILE`: without --generation it
// posts the resource document to /v1/resources and prints the assigned
// ID in table mode; with --generation N it performs a CAS-guarded
// upsert, PUTting to the document's scope address per the frozen
// contract.
func runApply(w io.Writer, g globals, args []string) error {
	fs := newFlagSet("apply")
	file := fs.String("f", "", "resource JSON file, or - for stdin")
	generation := fs.Int64("generation", 0, "expected generation for a CAS upsert (PUT at the scope address); omit for POST create")
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
	if *generation < 0 {
		return usageErrorf("invalid --generation %d: must be a positive integer", *generation)
	}
	body, err := readInput(*file)
	if err != nil {
		return err
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return usageErrorf("no input: %s is empty", *file)
	}
	if *generation != 0 {
		return applyCAS(w, g, body, *generation)
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

// applyCAS performs the generation-guarded upsert of the frozen
// contract (docs/api-contracts.md, scope-addressed resources): the
// body carries "generation": N — the generation the caller last read —
// and the request is PUT to the document's own scope address. A 201
// means the address was fresh (created), a 200 that it was updated; a
// 409 conflict is re-rendered with the server's current generation so
// the operator knows what to retry with.
func applyCAS(w io.Writer, g globals, doc []byte, generation int64) error {
	path, body, err := casRequest(doc, generation)
	if err != nil {
		return err
	}
	status, raw, err := g.client().DoStatus(http.MethodPut, path, body)
	if err != nil {
		var ae *ApiError
		if errors.As(err, &ae) && ae.Status == http.StatusConflict && ae.Code == "conflict" {
			return casConflict(g, path, ae, generation)
		}
		return err
	}
	if g.out == "json" {
		return dumpJSON(w, raw)
	}
	var res resourceDoc
	if err := json.Unmarshal(raw, &res); err != nil {
		return fmt.Errorf("unexpected response from control plane: %w", err)
	}
	if status == http.StatusCreated {
		fmt.Fprintf(w, "created %s (%s)\n", res.ID, res.address())
		return nil
	}
	fmt.Fprintf(w, "updated %s (generation %d)\n", res.ID, res.Generation)
	return nil
}

// casRequest builds the CAS PUT from the raw resource document: it
// decodes into a generic map so unknown fields survive the round trip,
// pins the expected generation, and derives the 5-segment scope
// address the PUT is sent to. Segments are escaped exactly like
// address.path().
func casRequest(doc []byte, generation int64) (string, []byte, error) {
	var m map[string]any
	if err := json.Unmarshal(doc, &m); err != nil || m == nil {
		return "", nil, usageErrorf("resource document must be a JSON object with org, project, env, kind and name")
	}
	m["generation"] = generation
	parts := make([]string, 0, 5)
	for _, k := range []string{"org", "project", "env", "kind", "name"} {
		v, ok := m[k].(string)
		if !ok || v == "" {
			return "", nil, usageErrorf("apply --generation needs the resource document to carry %q so its scope address can be built", k)
		}
		parts = append(parts, url.PathEscape(v))
	}
	body, err := json.Marshal(m)
	if err != nil {
		return "", nil, err
	}
	return "/v1/" + strings.Join(parts, "/"), body, nil
}

// casConflict turns a 409 on the CAS PUT into a readable error that
// names the server's current generation: the error envelope may carry
// details, so look for a current_generation=N hint there first, then
// fall back to a plain GET of the same address. When neither yields a
// generation the original envelope is surfaced unchanged.
func casConflict(g globals, path string, ae *ApiError, generation int64) error {
	if cur, ok := generationFromDetails(ae.Details); ok {
		return conflictError(ae, generation, cur)
	}
	raw, err := g.client().Do(http.MethodGet, path, nil)
	if err == nil {
		var doc resourceDoc
		if jerr := json.Unmarshal(raw, &doc); jerr == nil && doc.Generation > 0 {
			return conflictError(ae, generation, doc.Generation)
		}
	}
	return ae
}

// generationFromDetails scans error-envelope details for a
// current_generation=N hint.
func generationFromDetails(details []string) (int64, bool) {
	for _, d := range details {
		if v, ok := strings.CutPrefix(d, "current_generation="); ok {
			if n, err := strconv.ParseInt(v, 10, 64); err == nil {
				return n, true
			}
		}
	}
	return 0, false
}

// conflictError re-renders the conflict envelope with the generation
// mismatch spelled out; code, request id and details are preserved.
func conflictError(ae *ApiError, generation, current int64) *ApiError {
	return &ApiError{
		Status:    ae.Status,
		Code:      ae.Code,
		Message:   fmt.Sprintf("generation conflict: resource is at generation %d, not %d; re-fetch and retry with --generation %d", current, generation, current),
		RequestID: ae.RequestID,
		Details:   ae.Details,
	}
}
