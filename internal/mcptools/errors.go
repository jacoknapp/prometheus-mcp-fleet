// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package mcptools

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/render"
)

// Tool error codes. This is a closed, stable set: an agent is expected to
// branch on it, and a code that changes meaning between releases is worse than
// no code at all.
const (
	// CodeUnknownCluster reports a cluster the hub cannot route to. It is also
	// returned for a cluster the principal may not reach, so that a denial
	// cannot be used to enumerate the fleet.
	CodeUnknownCluster = "UNKNOWN_CLUSTER"
	// CodeSpokeUnreachable reports an enrolled cluster whose spoke currently
	// holds no tunnel.
	CodeSpokeUnreachable = "SPOKE_UNREACHABLE"
	// CodePromQLParse reports that Prometheus refused to parse the expression.
	CodePromQLParse = "PROMQL_PARSE"
	// CodePromQLExec reports that the expression parsed but failed to
	// evaluate.
	CodePromQLExec = "PROMQL_EXEC"
	// CodeQueryTimeout reports a deadline reached before a result arrived.
	CodeQueryTimeout = "QUERY_TIMEOUT"
	// CodeCanceled reports a call the caller abandoned.
	CodeCanceled = "CANCELED"
	// CodeRangeTooLarge reports a range query the hub refused to issue. It
	// always carries a corrected argument object.
	CodeRangeTooLarge = "RANGE_TOO_LARGE"
	// CodeBadMatcher reports a malformed series selector.
	CodeBadMatcher = "BAD_MATCHER"
	// CodeBadRegex reports a malformed RE2 pattern.
	CodeBadRegex = "BAD_REGEX"
	// CodeInvalidArgument reports an argument the hub rejected before any
	// upstream call.
	CodeInvalidArgument = "INVALID_ARGUMENT"
	// CodeInvalidTime reports an unparseable timestamp or duration.
	CodeInvalidTime = "INVALID_TIME"
	// CodeTSDBStatsUnavailable reports that the cluster's TSDB status endpoint
	// is not serving.
	CodeTSDBStatsUnavailable = "TSDB_STATS_UNAVAILABLE"
	// CodeResponseTooLarge reports a response truncated at the hub's byte
	// budget before it could be parsed.
	CodeResponseTooLarge = "RESPONSE_TOO_LARGE"
	// CodeRateLimited reports that this agent key has exceeded the call rate its
	// scope allows. It is distinct from CodeHubBusy: busy is the hub being out
	// of capacity and is nobody's fault, whereas this names the caller's own
	// limit and is fixed by slowing down or by widening the scope.
	CodeRateLimited = "RATE_LIMITED"
	// CodeHubBusy reports an exhausted concurrency or memory budget.
	CodeHubBusy = "HUB_BUSY"
	// CodeUpstreamError reports any other failure of the cluster's Prometheus
	// or of the tunnel to it.
	CodeUpstreamError = "UPSTREAM_ERROR"
	// CodeMalformedUpstream reports a response that was not the Prometheus API
	// envelope.
	CodeMalformedUpstream = "MALFORMED_UPSTREAM"
	// CodeNoClustersMatched reports a fan-out selector that matched nothing.
	CodeNoClustersMatched = "NO_CLUSTERS_MATCHED"
	// CodeAllClustersFailed reports a fan-out in which every cluster failed.
	CodeAllClustersFailed = "ALL_CLUSTERS_FAILED"
	// CodeNoSelectorTooBroad reports an untargeted fan-out across a fleet
	// larger than maxClusters.
	CodeNoSelectorTooBroad = "NO_SELECTOR_TOO_BROAD"
)

// ToolError is the body of a tool error result.
//
// Error text is a prompt, so it is written like one. Every field exists
// because a model reliably needs it: it has usually forgotten the arguments it
// sent (Input), it cannot locate a PromQL fault without a position (Caret), it
// will otherwise invent a recovery action (Hint), and it will retry a
// permanent failure forever without being told not to (Retryable).
type ToolError struct {
	// Code is one of the Code constants in this package.
	Code string `json:"code"`
	// Message is the human-readable explanation. When it originates upstream
	// it is Prometheus' own message, passed through so the agent sees what a
	// curl would have shown it.
	Message string `json:"message"`
	// Input echoes the offending arguments.
	Input map[string]any `json:"input,omitempty"`
	// Hint names a concrete next call.
	Hint string `json:"hint,omitempty"`
	// Retryable states whether repeating the call could succeed. It is a
	// pointer so that "not stated" is distinguishable from "no"; every error
	// this package builds sets it.
	Retryable *bool `json:"retryable,omitempty"`
	// DidYouMean carries the nearest cluster names for a CodeUnknownCluster.
	DidYouMean []string `json:"didYouMean,omitempty"`
	// Caret is a whitespace-and-caret line aligning under the offending
	// character of the echoed query.
	Caret string `json:"caret,omitempty"`
	// Corrected is a literal, copyable argument object that would have
	// worked. It is set by CodeRangeTooLarge.
	Corrected map[string]any `json:"corrected,omitempty"`
	// RetryAfterSeconds advises how long to wait before retrying.
	RetryAfterSeconds float64 `json:"retryAfterSeconds,omitempty"`
}

// Error implements error so a ToolError can travel through ordinary Go error
// plumbing inside this package. The string is never what reaches the agent:
// the structured value is.
func (e *ToolError) Error() string {
	if e == nil {
		return "<nil>"
	}
	return e.Code + ": " + e.Message
}

// WithInput attaches the echoed arguments and returns e.
func (e *ToolError) WithInput(kv map[string]any) *ToolError {
	e.Input = kv
	return e
}

// WithHint attaches a recovery hint and returns e.
func (e *ToolError) WithHint(format string, args ...any) *ToolError {
	e.Hint = fmt.Sprintf(format, args...)
	return e
}

var (
	retryableYes = true
	retryableNo  = false
)

// newError builds a ToolError with a sanitised message.
func newError(code, message string, retryable bool) *ToolError {
	e := &ToolError{Code: code, Message: render.ClipRunes(message, 600)}
	if retryable {
		e.Retryable = &retryableYes
	} else {
		e.Retryable = &retryableNo
	}
	return e
}

// promqlPositionRE matches the two position forms Prometheus uses in a parse
// error: "1:24: parse error: ..." and "parse error at char 34: ...".
var promqlPositionRE = regexp.MustCompile(`(?:^|\s)(?:(\d+):(\d+):|at char (\d+))`)

// promqlCaret builds a caret line pointing at the character Prometheus
// complained about, or the empty string when the message carries no position.
//
// Positions are one-based in both Prometheus forms. A position past the end of
// the query still produces a caret, pointing one past the last character,
// because "you stopped too early" is exactly what an unterminated selector
// means.
func promqlCaret(query, message string) string {
	m := promqlPositionRE.FindStringSubmatch(message)
	if m == nil {
		return ""
	}
	var col int
	switch {
	case m[2] != "":
		col, _ = strconv.Atoi(m[2])
	case m[3] != "":
		col, _ = strconv.Atoi(m[3])
	}
	if col <= 0 {
		return ""
	}
	if col > len(query)+1 {
		col = len(query) + 1
	}
	return strings.Repeat(" ", col-1) + "^"
}
