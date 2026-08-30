// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package mcptools

import (
	"fmt"
	"slices"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// PromQL structural analysis.
//
// This project deliberately does not depend on github.com/prometheus/prometheus
// (see docs/adr/0006): Prometheus itself is the authority on whether an
// expression parses, and it tells us so on every query. What this file does is
// different and complementary — it answers the question explain_promql asks,
// which is "what would happen if I sent this", *without sending it*.
//
// It is a scanner and a bracket matcher, not a parser. It finds the four
// mistakes a language model actually makes — an unbalanced bracket, an
// unterminated string, an unquoted label-matcher value and a malformed
// duration — and it extracts the metric names and functions an expression
// refers to so they can be checked against a real cluster. It never claims an
// expression is valid PromQL; it claims it is not obviously broken, which is
// exactly what a 200-token check before a 40,000-token query is worth.

// promQLFunctions is the function set Prometheus 3.x exposes. An identifier
// applied as a function and absent from this list produces a suggestion, never
// an invalidity: this list will fall behind upstream, and a false "invalid"
// would be worse than a missing hint.
var promQLFunctions = map[string]bool{
	"abs": true, "absent": true, "absent_over_time": true, "acos": true, "acosh": true,
	"asin": true, "asinh": true, "atan": true, "atanh": true, "avg_over_time": true,
	"ceil": true, "changes": true, "clamp": true, "clamp_max": true, "clamp_min": true,
	"cos": true, "cosh": true, "count_over_time": true, "day_of_month": true,
	"day_of_week": true, "day_of_year": true, "days_in_month": true, "deg": true,
	"delta": true, "deriv": true, "double_exponential_smoothing": true, "exp": true,
	"floor": true, "histogram_avg": true, "histogram_count": true,
	"histogram_fraction": true, "histogram_quantile": true, "histogram_stddev": true,
	"histogram_stdvar": true, "histogram_sum": true, "holt_winters": true, "hour": true,
	"idelta": true, "increase": true, "info": true, "irate": true, "label_join": true,
	"label_replace": true, "last_over_time": true, "ln": true, "log10": true, "log2": true,
	"mad_over_time": true, "max_over_time": true, "min_over_time": true, "minute": true,
	"month": true, "pi": true, "predict_linear": true, "present_over_time": true,
	"quantile_over_time": true, "rad": true, "rate": true, "resets": true, "round": true,
	"scalar": true, "sgn": true, "sin": true, "sinh": true, "sort": true,
	"sort_by_label": true, "sort_by_label_desc": true, "sort_desc": true, "sqrt": true,
	"stddev_over_time": true, "stdvar_over_time": true, "sum_over_time": true, "tan": true,
	"tanh": true, "time": true, "timestamp": true, "vector": true, "year": true,
}

// promQLAggregations is the aggregation operator set.
var promQLAggregations = map[string]bool{
	"sum": true, "min": true, "max": true, "avg": true, "group": true, "stddev": true,
	"stdvar": true, "count": true, "count_values": true, "bottomk": true, "topk": true,
	"quantile": true, "limitk": true, "limit_ratio": true,
}

// promQLGrouping are the keywords whose following parenthesised list holds
// label names rather than an expression.
var promQLGrouping = map[string]bool{
	"by": true, "without": true, "on": true, "ignoring": true,
	"group_left": true, "group_right": true,
}

// promQLKeywords are the words that are neither metrics nor functions.
var promQLKeywords = map[string]bool{
	"offset": true, "bool": true, "and": true, "or": true,
	"unless": true, "start": true, "end": true, "atan2": true,
	"inf": true, "nan": true, "Inf": true, "NaN": true,
}

// counterSuffixes are the metric-name endings that conventionally mark a
// counter. A counter read without rate() or increase() is the single most
// common way to produce a confidently wrong graph.
var counterSuffixes = []string{"_total", "_count", "_sum", "_bucket"}

// promQLAnalysis is what [analyzePromQL] reports.
type promQLAnalysis struct {
	// Valid is false only for a structural fault this file is certain about.
	Valid bool
	// Message describes the fault, in the shape Prometheus itself would use.
	Message string
	// Position is the one-based character offset of the fault.
	Position int
	// Metrics are the metric names the expression refers to, sorted.
	Metrics []string
	// Functions and Aggregations are the operators used, sorted.
	Functions    []string
	Aggregations []string
	// RangeWindows are the bracketed durations, e.g. "5m".
	RangeWindows []string
	// Labels are the label names used in matchers and grouping, sorted.
	Labels []string
	// Selectors counts the series selectors.
	Selectors int
	// Subqueries counts the subquery expressions.
	Subqueries int
	// Suggestions are advisory notes: an unrecognised function, a counter read
	// raw, a range selector far below the scrape interval.
	Suggestions []string
}

// analyzePromQL scans an expression without evaluating it.
func analyzePromQL(q string) promQLAnalysis {
	a := promQLAnalysis{Valid: true}
	metrics := map[string]bool{}
	funcs := map[string]bool{}
	aggs := map[string]bool{}
	labels := map[string]bool{}
	var windows []string
	var suggest []string

	type openBracket struct {
		ch  byte
		pos int
		// labelCtx marks a parenthesised grouping list, as in sum by(job) (...),
		// whose identifiers are label names rather than metric names.
		labelCtx bool
	}
	var stack []openBracket
	// expectGrouping is set by a grouping keyword and consumed by the next "(".
	expectGrouping := false
	// braceDepth tracks label-matcher context, where the grammar is
	// name OP "value" and an unquoted value is the classic model error.
	braceDepth := 0
	// expectMatcherValue is set immediately after a matcher operator.
	expectMatcherValue := false
	// lastIdent remembers the previous identifier so a name followed by "("
	// can be classified as a function rather than a metric.
	var lastIdent string
	var lastIdentPos int

	fail := func(pos int, format string, args ...any) promQLAnalysis {
		a.Valid = false
		a.Message = fmt.Sprintf(format, args...)
		a.Position = pos
		a.Metrics = sortedKeys(metrics)
		a.Functions = sortedKeys(funcs)
		a.Aggregations = sortedKeys(aggs)
		a.Labels = sortedKeys(labels)
		a.RangeWindows = windows
		a.Suggestions = suggest
		return a
	}

	// inLabelContext reports whether an identifier here names a label rather
	// than a metric: inside a brace matcher, or inside a grouping list.
	inLabelContext := func() bool {
		if braceDepth > 0 {
			return true
		}
		return len(stack) > 0 && stack[len(stack)-1].labelCtx
	}

	flushIdent := func(next byte) {
		if lastIdent == "" {
			return
		}
		name := lastIdent
		lastIdent = ""
		switch {
		case promQLGrouping[name]:
			expectGrouping = true
		case promQLKeywords[name]:
		case promQLAggregations[name]:
			// Recognised unconditionally rather than only before "(": PromQL
			// writes sum by(job) (...) as often as sum(...), and a metric
			// actually named "sum" does not exist in practice.
			aggs[name] = true
		case next == '(':
			if promQLFunctions[name] {
				funcs[name] = true
				break
			}
			funcs[name] = true
			suggest = append(suggest, fmt.Sprintf(
				"%q is applied as a function but is not one this hub recognises; "+
					"check the spelling against the Prometheus function list.", name))
		case inLabelContext():
			labels[name] = true
		default:
			metrics[name] = true
			a.Selectors++
		}
		_ = lastIdentPos
	}

	i := 0
	for i < len(q) {
		ch := q[i]
		switch {
		case ch == '#':
			for i < len(q) && q[i] != '\n' {
				i++
			}
			continue

		case ch == '"' || ch == '\'' || ch == '`':
			flushIdent(ch)
			end, ok := scanString(q, i)
			if !ok {
				return fail(i+1, "parse error at char %d: unterminated string literal", i+1)
			}
			if braceDepth > 0 && expectMatcherValue {
				expectMatcherValue = false
			}
			i = end
			continue

		case isSpaceByte(ch):
			// Whitespace does not end an expression element: an identifier is
			// only classified once the next significant byte is known, so that
			// "sum by(job)" and "rate (x[5m])" read the same as their compact
			// spellings.
			i++
			continue

		case ch == '(' || ch == '[' || ch == '{':
			flushIdent(ch)
			if ch == '{' {
				braceDepth++
			}
			if ch == '[' {
				// A range or subquery window: read it so a malformed duration
				// is reported here rather than by Prometheus after a round trip.
				end := strings.IndexByte(q[i:], ']')
				if end < 0 {
					return fail(i+1, "parse error at char %d: unclosed range selector \"[\"", i+1)
				}
				body := q[i+1 : i+end]
				if strings.Contains(body, ":") {
					a.Subqueries++
				}
				for _, part := range strings.Split(body, ":") {
					part = strings.TrimSpace(part)
					if part == "" {
						continue
					}
					if !validDuration(part) {
						return fail(i+2,
							"parse error at char %d: %q is not a valid duration; "+
								"use a form such as 5m, 1h30m or 1d", i+2, part)
					}
					windows = append(windows, part)
				}
				i += end + 1
				continue
			}
			stack = append(stack, openBracket{ch: ch, pos: i + 1, labelCtx: expectGrouping})
			expectGrouping = false
			i++
			continue

		case ch == ')' || ch == '}':
			flushIdent(ch)
			want := byte('(')
			if ch == '}' {
				want = '{'
				braceDepth--
				expectMatcherValue = false
			}
			if len(stack) == 0 {
				return fail(i+1, "parse error at char %d: unexpected %q", i+1, string(ch))
			}
			top := stack[len(stack)-1]
			if top.ch != want {
				return fail(i+1,
					"parse error at char %d: unexpected %q, expected to close %q opened at char %d",
					i+1, string(ch), string(top.ch), top.pos)
			}
			stack = stack[:len(stack)-1]
			i++
			continue

		case ch == ']':
			return fail(i+1, "parse error at char %d: unexpected \"]\"", i+1)

		case isIdentStart(ch):
			j := i
			for j < len(q) && isIdentPart(q[j]) {
				j++
			}
			word := q[i:j]
			if expectMatcherValue {
				return fail(i+1,
					"parse error at char %d: unexpected %q in label matching, expected string; "+
						"label matcher values must be quoted, as in job=%q", i+1, word, word)
			}
			flushIdent(0)
			lastIdent, lastIdentPos = word, i+1
			i = j
			continue

		case braceDepth > 0 && (ch == '=' || ch == '!'):
			flushIdent(ch)
			// Consume "=", "!=", "=~", "!~"; anything else in a matcher
			// position is a fault Prometheus would reject too.
			j := i + 1
			if j < len(q) && (q[j] == '=' || q[j] == '~') {
				j++
			}
			expectMatcherValue = true
			i = j
			// Skip whitespace so the value check lands on the value itself.
			for i < len(q) && isSpaceByte(q[i]) {
				i++
			}
			continue

		default:
			flushIdent(ch)
			if ch == ',' {
				expectMatcherValue = false
			}
			i++
		}
	}
	flushIdent(0)

	if len(stack) > 0 {
		top := stack[len(stack)-1]
		return fail(top.pos, "parse error at char %d: unclosed %q", top.pos, string(top.ch))
	}
	if !utf8.ValidString(q) {
		return fail(1, "parse error at char 1: expression is not valid UTF-8")
	}

	a.Metrics = sortedKeys(metrics)
	a.Functions = sortedKeys(funcs)
	a.Aggregations = sortedKeys(aggs)
	a.Labels = sortedKeys(labels)
	a.RangeWindows = windows
	a.Suggestions = slices.Concat(suggest, counterAdvice(a.Metrics, a.Functions))
	return a
}

// counterAdvice warns about a counter read without a rate function.
func counterAdvice(metrics, funcs []string) []string {
	rated := slices.Contains(funcs, "rate") || slices.Contains(funcs, "irate") ||
		slices.Contains(funcs, "increase") || slices.Contains(funcs, "delta") ||
		slices.Contains(funcs, "idelta")
	if rated {
		return nil
	}
	var out []string
	for _, m := range metrics {
		for _, suf := range counterSuffixes {
			if strings.HasSuffix(m, suf) && suf == "_total" {
				out = append(out, fmt.Sprintf(
					"%q looks like a counter. Reading it raw gives a monotonically rising "+
						"line; wrap it as rate(%s[5m]) to get a per-second value.", m, m))
			}
		}
	}
	return out
}

// scanString returns the index just past a string literal starting at i, and
// whether it was terminated. Backquoted strings take no escapes, matching
// PromQL.
func scanString(q string, i int) (int, bool) {
	quote := q[i]
	j := i + 1
	for j < len(q) {
		if q[j] == '\\' && quote != '`' {
			j += 2
			continue
		}
		if q[j] == quote {
			return j + 1, true
		}
		j++
	}
	return j, false
}

// validDuration reports whether s is a Prometheus duration or a bare number of
// seconds, which is what a range selector accepts.
func validDuration(s string) bool {
	if s == "" {
		return false
	}
	i := 0
	seen := false
	for i < len(s) {
		start := i
		for i < len(s) && s[i] >= '0' && s[i] <= '9' {
			i++
		}
		if i == start {
			return false
		}
		if i >= len(s) {
			// A bare number is accepted by Prometheus as seconds.
			return start == 0
		}
		switch {
		case strings.HasPrefix(s[i:], "ms"):
			i += 2
		case s[i] == 's', s[i] == 'm', s[i] == 'h', s[i] == 'd', s[i] == 'w', s[i] == 'y':
			i++
		default:
			return false
		}
		seen = true
	}
	return seen
}

// isIdentStart reports whether ch may begin a PromQL identifier.
func isIdentStart(ch byte) bool {
	return ch == '_' || ch == ':' || (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z')
}

// isIdentPart reports whether ch may continue a PromQL identifier.
func isIdentPart(ch byte) bool { return isIdentStart(ch) || (ch >= '0' && ch <= '9') }

// isSpaceByte reports whether ch is ASCII whitespace.
func isSpaceByte(ch byte) bool { return unicode.IsSpace(rune(ch)) }

// sortedKeys returns a map's keys in sorted order.
func sortedKeys(m map[string]bool) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// nearestNames returns up to n entries of candidates closest to target by edit
// distance, so a mistyped metric name self-corrects in one turn.
func nearestNames(target string, candidates []string, n int) []string {
	if n <= 0 || len(candidates) == 0 {
		return nil
	}
	type scored struct {
		name string
		dist int
	}
	t := []rune(strings.ToLower(clipRunesTo(target, 128)))
	out := make([]scored, 0, len(candidates))
	for _, c := range candidates {
		d := editDistance(t, []rune(strings.ToLower(clipRunesTo(c, 128))))
		// Only offer a suggestion that is plausibly the same word.
		if d > 1+len(t)/3 {
			continue
		}
		out = append(out, scored{name: c, dist: d})
	}
	slices.SortFunc(out, func(a, b scored) int {
		if a.dist != b.dist {
			return a.dist - b.dist
		}
		return strings.Compare(a.name, b.name)
	})
	if len(out) > n {
		out = out[:n]
	}
	names := make([]string, len(out))
	for i, s := range out {
		names[i] = s.name
	}
	return names
}

// clipRunesTo returns the first max runes of s.
func clipRunesTo(s string, max int) string {
	rs := []rune(s)
	if len(rs) > max {
		rs = rs[:max]
	}
	return string(rs)
}

// editDistance is Levenshtein over a single working row.
func editDistance(a, b []rune) int {
	if len(a) < len(b) {
		a, b = b, a
	}
	if len(b) == 0 {
		return len(a)
	}
	row := make([]int, len(b)+1)
	for j := range row {
		row[j] = j
	}
	for i := 1; i <= len(a); i++ {
		prev := row[0]
		row[0] = i
		for j := 1; j <= len(b); j++ {
			cur := row[j]
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			row[j] = min(row[j]+1, row[j-1]+1, prev+cost)
			prev = cur
		}
	}
	return row[len(b)]
}
