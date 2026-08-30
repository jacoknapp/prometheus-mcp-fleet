// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package render

import (
	"strings"
	"unicode/utf8"
)

// MaxTableCellRunes clips a single table cell. A fixed-width table whose
// columns are sized by the widest cell is only cheap if no cell is pathological.
const MaxTableCellRunes = 64

// Table renders headers and rows as fixed-width text.
//
// For wide, shallow data — scrape targets, alerts, rule groups, cluster
// listings — this is the cheapest encoding available, because a column name is
// paid for once in the header rather than once per row as a JSON object key.
//
// Every cell is sanitised and clipped: the table is built from remote data and
// a cell containing a newline would let a monitored cluster forge extra rows.
func Table(headers []string, rows [][]string) string {
	cols := len(headers)
	for _, r := range rows {
		cols = max(cols, len(r))
	}
	if cols == 0 {
		return ""
	}

	clean := func(s string) string { return ClipRunes(s, MaxTableCellRunes) }

	widths := make([]int, cols)
	head := make([]string, cols)
	for i := range cols {
		if i < len(headers) {
			head[i] = clean(headers[i])
		}
		widths[i] = utf8.RuneCountInString(head[i])
	}
	body := make([][]string, len(rows))
	for ri, r := range rows {
		body[ri] = make([]string, cols)
		for i := range cols {
			if i < len(r) {
				body[ri][i] = clean(r[i])
			}
			widths[i] = max(widths[i], utf8.RuneCountInString(body[ri][i]))
		}
	}

	var b strings.Builder
	writeRow := func(cells []string) {
		for i, c := range cells {
			b.WriteString(c)
			if i < cols-1 {
				b.WriteString(strings.Repeat(" ", widths[i]-utf8.RuneCountInString(c)+2))
			}
		}
		b.WriteByte('\n')
	}
	writeRow(head)
	sep := make([]string, cols)
	for i := range cols {
		sep[i] = strings.Repeat("-", widths[i])
	}
	writeRow(sep)
	for _, r := range body {
		writeRow(r)
	}
	return b.String()
}
