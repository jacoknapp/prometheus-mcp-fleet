// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package mcptools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/fleet"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/promapi"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/promproxy"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/render"
)

// callKind tells [Tools.fetch] how to classify an upstream "bad_data" error.
// Prometheus uses one error type for a malformed PromQL expression, a
// malformed series selector and a malformed regular expression, and the agent
// needs to be told which of the three it wrote.
type callKind int

const (
	// kindQuery is a PromQL evaluation.
	kindQuery callKind = iota
	// kindSelector is a matcher-driven metadata call.
	kindSelector
	// kindPlain is a call with no user-authored expression.
	kindPlain
)

// fetch performs one upstream call and decodes the Prometheus API envelope.
//
// A non-2xx status carrying a well-formed envelope is not an error here: that
// is how Prometheus reports a parse failure, and its message is the single
// most useful thing this hub can hand back. It becomes a [ToolError] with the
// upstream text passed through.
func (t *Tools) fetch(
	ctx context.Context, p *fleet.Principal, call promproxy.Call, kind callKind,
) (*render.APIResponse, *promproxy.Result, *ToolError) {
	res, err := t.prom.Do(ctx, p, call)
	if err != nil {
		return nil, res, t.mapProxyError(p, call, err)
	}
	env, derr := render.DecodeAPIResponse(res.Body)
	if derr != nil {
		return nil, res, newError(CodeMalformedUpstream,
			fmt.Sprintf("cluster %q returned a body that is not a Prometheus API response (HTTP %d)",
				call.ClusterID, res.Status), false).
			WithHint("This usually means something other than Prometheus is answering at the " +
				"spoke's configured URL. Call runtime_info to see what the cluster reports.")
	}
	if env.Failed() {
		return nil, res, classifyUpstream(call, env, res.Status, kind)
	}
	return env, res, nil
}

// mapProxyError turns a promproxy failure into the stable code an agent
// branches on.
func (t *Tools) mapProxyError(p *fleet.Principal, call promproxy.Call, err error) *ToolError {
	input := map[string]any{"cluster": call.ClusterID}

	var busy *promproxy.BusyError
	var notConn *promproxy.NotConnectedError
	switch {
	case errors.Is(err, promproxy.ErrForbidden):
		// The proxy refuses an unknown cluster and a denied cluster
		// identically. Reporting it as unknown keeps that property intact all
		// the way to the agent.
		return t.unknownCluster(p, call.ClusterID)

	case errors.As(err, &notConn):
		e := newError(CodeSpokeUnreachable, notConn.Error(), true).WithInput(input)
		e.Hint = "Call list_clusters to find a connected cluster, or retry once the spoke reconnects."
		return e

	case errors.As(err, &busy):
		e := newError(CodeHubBusy,
			fmt.Sprintf("the hub's %s budget is exhausted", busy.Budget), true).WithInput(input)
		e.RetryAfterSeconds = busy.RetryAfter.Seconds()
		e.Hint = fmt.Sprintf("Wait about %s and retry, or narrow the query so it costs less.",
			busy.RetryAfter)
		return e

	case errors.Is(err, promproxy.ErrTooLarge):
		e := newError(CodeResponseTooLarge,
			fmt.Sprintf("cluster %q returned more data than the hub will hold", call.ClusterID),
			false).WithInput(input)
		e.Hint = "Add label matchers, aggregate with sum by(...), or shorten the time range. " +
			"Call explain_promql first to check the expression is what you meant."
		return e

	case errors.Is(err, context.DeadlineExceeded):
		e := newError(CodeQueryTimeout,
			fmt.Sprintf("cluster %q did not answer within the timeout", call.ClusterID),
			true).WithInput(input)
		e.Hint = "Shorten the range, raise timeout (max 120s), or aggregate the expression."
		return e

	case errors.Is(err, context.Canceled):
		return newError(CodeCanceled, "the call was cancelled before a result arrived", false).
			WithInput(input)

	case errors.Is(err, promapi.ErrInvalidParam),
		errors.Is(err, promapi.ErrInvalidLabelName),
		errors.Is(err, promapi.ErrUnknownEndpoint):
		return newError(CodeInvalidArgument, err.Error(), false).WithInput(input)

	case errors.Is(err, promapi.ErrEndpointGated):
		e := newError(CodeInvalidArgument,
			"that Prometheus endpoint is disabled on this hub by configuration", false).
			WithInput(input)
		e.Hint = "Scrape configuration is withheld because it commonly embeds credentials. " +
			"Call targets or runtime_info instead."
		return e

	default:
		e := newError(CodeUpstreamError,
			fmt.Sprintf("cluster %q: %v", call.ClusterID, err), true).WithInput(input)
		e.Hint = "Retry once. If it persists, call list_clusters to check the cluster's state."
		return e
	}
}

// classifyUpstream turns a Prometheus error envelope into a tool error.
func classifyUpstream(
	call promproxy.Call, env *render.APIResponse, status int, kind callKind,
) *ToolError {
	msg := env.Error
	if msg == "" {
		msg = fmt.Sprintf("cluster %q reported an error (HTTP %d)", call.ClusterID, status)
	}
	input := map[string]any{"cluster": call.ClusterID}
	query := call.Form.Get("query")
	if query != "" {
		input["query"] = render.ClipRunes(query, 1024)
	}
	if m := call.Form["match[]"]; len(m) > 0 {
		input["matchers"] = m
	}

	switch env.ErrorType {
	case "timeout":
		e := newError(CodeQueryTimeout, msg, true).WithInput(input)
		e.Hint = "Shorten the range, raise timeout (max 120s), or aggregate the expression."
		return e
	case "canceled":
		return newError(CodeCanceled, msg, false).WithInput(input)
	case "execution":
		e := newError(CodePromQLExec, msg, false).WithInput(input)
		e.Caret = promqlCaret(query, msg)
		e.Hint = "The expression parsed but failed to evaluate. Check the metric exists with " +
			"search_metrics, then re-run."
		return e
	case "unavailable", "internal":
		e := newError(CodeUpstreamError, msg, true).WithInput(input)
		e.Hint = "The cluster's Prometheus reported an internal failure. Retry once."
		return e
	}

	// "bad_data", an empty errorType, or anything unrecognised: the request was
	// wrong, and which part of it was wrong depends on what the tool sent.
	switch kind {
	case kindQuery:
		if isParseError(msg) {
			e := newError(CodePromQLParse, msg, false).WithInput(input)
			e.Caret = promqlCaret(query, msg)
			e.Hint = "Fix the expression and validate it with explain_promql before querying; " +
				"a failed query_range is far more expensive than a check."
			return e
		}
		e := newError(CodePromQLExec, msg, false).WithInput(input)
		e.Caret = promqlCaret(query, msg)
		e.Hint = "Call explain_promql to validate the expression against this cluster."
		return e
	case kindSelector:
		e := newError(CodeBadMatcher, msg, false).WithInput(input)
		e.Hint = `A matcher is a full selector such as up{job="api"}, not a bare label. ` +
			"Call label_names and label_values to discover valid labels."
		return e
	default:
		return newError(CodeInvalidArgument, msg, false).WithInput(input)
	}
}

// isParseError reports whether Prometheus' message describes a syntax failure
// rather than a semantic one.
func isParseError(msg string) bool {
	l := strings.ToLower(msg)
	return strings.Contains(l, "parse error") ||
		strings.Contains(l, "invalid parameter") && strings.Contains(l, "query") ||
		strings.Contains(l, "unexpected")
}

// decodeData unmarshals the envelope's data member into v.
func decodeData(env *render.APIResponse, cluster string, v any) *ToolError {
	if len(env.Data) == 0 {
		return nil
	}
	if err := json.Unmarshal(env.Data, v); err != nil {
		return newError(CodeMalformedUpstream,
			fmt.Sprintf("cluster %q returned a payload this hub could not read: %v", cluster, err),
			false)
	}
	return nil
}

// effectiveTimeout clamps a caller's timeout to the hub's ceiling.
func effectiveTimeout(want, def time.Duration) time.Duration {
	if want <= 0 {
		want = def
	}
	return min(want, MaxQueryTimeout)
}

// tokenCeilingTruncation reports a passthrough payload the hub refused to
// carry. Format "json" bypasses the columnar encoder, so the ceiling is
// enforced on the raw bytes instead; a clipped JSON document would be
// unparseable, so the payload is dropped and the reason stated.
func tokenCeilingTruncation(total, ceiling int) *render.Truncation {
	return &render.Truncation{
		Returned: 0,
		Total:    total,
		Reason:   render.ReasonTokenCeiling,
		Hint: fmt.Sprintf(
			"The upstream response is about %d estimated tokens, above the hub ceiling of %d. "+
				"Re-run with format \"compact\", which is ten to fifty times smaller, or narrow "+
				"the query.", total, ceiling),
	}
}

// rawMessage carries an upstream payload through format "json" without
// re-encoding it. It is typed as any at the output boundary so the inferred
// output schema accepts arbitrary JSON; a []byte field would be advertised as
// a base64 string and then fail its own validation.
func rawMessage(b []byte) any { return json.RawMessage(b) }
