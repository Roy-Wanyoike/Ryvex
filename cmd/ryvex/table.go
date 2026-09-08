package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"time"
)

// table renders fixed-width columns for table output mode: the widest
// cell in each column sets the column width, cells are left-aligned,
// and columns are separated by two spaces.
type table struct {
	headers []string
	rows    [][]string
}

func newTable(headers ...string) *table {
	return &table{headers: headers}
}

func (t *table) addRow(cells ...string) {
	t.rows = append(t.rows, cells)
}

// render writes the header row and every data row to w.
func (t *table) render(w io.Writer) {
	widths := make([]int, len(t.headers))
	for i, h := range t.headers {
		widths[i] = len(h)
	}
	for _, row := range t.rows {
		for i, c := range row {
			if i < len(widths) && len(c) > widths[i] {
				widths[i] = len(c)
			}
		}
	}
	var buf bytes.Buffer
	t.writeRow(&buf, t.headers, widths)
	for _, row := range t.rows {
		t.writeRow(&buf, row, widths)
	}
	_, _ = w.Write(buf.Bytes())
}

func (t *table) writeRow(buf *bytes.Buffer, cells []string, widths []int) {
	for i, width := range widths {
		cell := ""
		if i < len(cells) {
			cell = cells[i]
		}
		if i == len(widths)-1 {
			buf.WriteString(cell) // no trailing padding on the last column
		} else {
			fmt.Fprintf(buf, "%-*s", width+2, cell)
		}
	}
	buf.WriteByte('\n')
}

// renderKV writes aligned key/value lines, used by the health view.
func renderKV(w io.Writer, rows [][2]string) {
	width := 0
	for _, kv := range rows {
		if len(kv[0]) > width {
			width = len(kv[0])
		}
	}
	for _, kv := range rows {
		fmt.Fprintf(w, "%-*s%s\n", width+2, kv[0], kv[1])
	}
}

// age humanizes a timestamp as time since it occurred, in the compact
// form used across table output: 45s, 2m, 3h, 5d.
func age(t time.Time) string {
	if t.IsZero() {
		return "unknown"
	}
	d := time.Since(t)
	if d < 0 {
		d = 0
	}
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
}

// dumpJSON pretty-prints a raw API response body in JSON output mode,
// preserving every field the server sent per the API contract.
func dumpJSON(w io.Writer, raw []byte) error {
	var buf bytes.Buffer
	if err := json.Indent(&buf, raw, "", "  "); err != nil {
		// Not valid JSON (should not happen per contract); pass it through.
		_, err := fmt.Fprintln(w, string(raw))
		return err
	}
	buf.WriteByte('\n')
	_, err := w.Write(buf.Bytes())
	return err
}
