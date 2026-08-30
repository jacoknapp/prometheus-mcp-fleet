// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package mcptools

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"time"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/fleet"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/mcpsurface"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/render"
)

// DidYouMeanCount is how many nearest cluster names a [CodeUnknownCluster]
// error offers. Five is enough that a plausible typo is nearly always covered
// and few enough that the list stays cheap to read.
const DidYouMeanCount = 5

// clusterIDRE is the cluster identity grammar, enforced at enrollment and
// re-checked here so a malformed name is refused before it reaches a registry
// lookup or a log line.
var clusterIDRE = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)

// toolOut is satisfied by every tool output type through its embedded
// [Envelope]. It lets [run] attach an error to a result without knowing the
// result's shape.
type toolOut interface {
	setError(*ToolError)
}

// setError implements [toolOut]. Attaching an error clears the untrusted
// notice: an error body is text this project authored, and labelling it as
// remote data would be a lie that trains the model to ignore the notice.
func (e *Envelope) setError(te *ToolError) {
	e.Error = te
	e.Untrusted = ""
}

// run wraps a tool implementation with the checks and instrumentation every
// tool shares.
//
// The order is deliberate. An unauthenticated or out-of-scope call is refused
// as a protocol error before any argument is examined, so a caller that may
// not use a tool never learns whether its arguments would have been valid.
// zero builds the result an error is attached to, because the SDK marshals the
// returned value against the output schema and a typed nil would arrive at the
// client as JSON null with the error lost.
func run[In any, Out toolOut](
	tl *Tools, name string, zero func() Out,
	fn func(ctx context.Context, p *fleet.Principal, in In) (Out, *ToolError),
) mcpsurface.ToolFunc[In, Out] {
	return func(ctx context.Context, req *mcpsurface.Request, in In) (Out, mcpsurface.Result, error) {
		start := tl.now()
		p := req.Principal()
		if p == nil {
			var none Out
			return none, mcpsurface.ErrorResult, mcpsurface.ProtocolError(
				mcpsurface.CodeUnauthenticated,
				"tool %q requires an authenticated principal", name)
		}
		if !p.Scope.AllowsTool(name) {
			tl.log.Warn("mcptools: tool denied by scope",
				"principal", p.String(), "tool", name)
			tl.metrics.ToolCall(name, "FORBIDDEN")
			tl.metrics.ToolDuration(name, tl.now().Sub(start))
			var none Out
			return none, mcpsurface.ErrorResult, mcpsurface.ProtocolError(
				mcpsurface.CodeForbidden,
				"tool %q is not permitted by this credential's scope", name)
		}

		out, terr := fn(ctx, p, in)
		result := "ok"
		if terr != nil {
			result = terr.Code
			out = zero()
			out.setError(terr)
		}
		tl.metrics.ToolCall(name, result)
		tl.metrics.ToolDuration(name, tl.now().Sub(start))
		if terr != nil {
			return out, mcpsurface.ErrorResult, nil
		}
		return out, mcpsurface.OKResult, nil
	}
}

// resolveCluster maps a caller-supplied cluster name onto a registry entry.
//
// A cluster the principal may not see is reported exactly as one that does not
// exist, and the did-you-mean list is drawn only from clusters the principal
// can already see, so neither the error nor its suggestions can be used to
// enumerate the fleet.
func (t *Tools) resolveCluster(p *fleet.Principal, id string) (fleet.Cluster, *ToolError) {
	if id == "" {
		return fleet.Cluster{}, newError(CodeInvalidArgument,
			"cluster is required", false).
			WithHint("Call list_clusters to see the clusters this credential can reach.")
	}
	if !clusterIDRE.MatchString(id) {
		return fleet.Cluster{}, t.unknownCluster(p, id).
			WithHint("A cluster name is lower-case letters, digits and hyphens, " +
				"at most 63 characters. Call list_clusters for the exact names.")
	}
	c, ok := t.clusters.Cluster(id)
	if !ok || !p.Scope.AllowsCluster(c.ID, c.Labels) {
		return fleet.Cluster{}, t.unknownCluster(p, id)
	}
	return c, nil
}

// unknownCluster builds the [CodeUnknownCluster] error, including up to
// [DidYouMeanCount] visible neighbours by edit distance.
func (t *Tools) unknownCluster(p *fleet.Principal, id string) *ToolError {
	e := newError(CodeUnknownCluster,
		fmt.Sprintf("no cluster named %q is reachable by this credential",
			render.ClipRunes(id, 128)), false)
	e.Input = map[string]any{"cluster": render.ClipRunes(id, 128)}
	e.DidYouMean = t.didYouMean(p, id)
	if len(e.DidYouMean) > 0 {
		e.Hint = "Retry with one of didYouMean, or call list_clusters to see every cluster " +
			"this credential can reach."
	} else {
		e.Hint = "Call list_clusters to see every cluster this credential can reach."
	}
	return e
}

// didYouMean returns the nearest visible cluster names.
func (t *Tools) didYouMean(p *fleet.Principal, id string) []string {
	visible := t.clusters.Visible(p)
	if len(visible) == 0 {
		return nil
	}
	allowed := make(map[string]bool, len(visible))
	for _, c := range visible {
		allowed[c.ID] = true
	}
	// Ask for more than needed: Nearest ranges over the whole fleet and the
	// filter below may drop several of its answers.
	out := make([]string, 0, DidYouMeanCount)
	for _, cand := range t.clusters.Nearest(id, DidYouMeanCount*4) {
		if allowed[cand] {
			out = append(out, cand)
			if len(out) == DidYouMeanCount {
				break
			}
		}
	}
	return out
}

// requireConnected refuses a call to a cluster whose spoke currently holds no
// tunnel, reporting how long ago it was last seen: "was here thirty seconds
// ago" and "was here yesterday" call for entirely different next actions.
func requireConnected(c fleet.Cluster, now time.Time) *ToolError {
	if c.State == fleet.StateConnected || c.State == fleet.StateDegraded {
		return nil
	}
	msg := fmt.Sprintf("cluster %q is enrolled but its spoke is not connected", c.ID)
	if !c.LastSeen.IsZero() {
		msg += fmt.Sprintf("; last seen %s (%s ago)",
			c.LastSeen.UTC().Format(time.RFC3339), now.Sub(c.LastSeen).Truncate(time.Second))
	}
	e := newError(CodeSpokeUnreachable, msg, true)
	e.Input = map[string]any{"cluster": c.ID}
	e.Hint = "Call list_clusters to find a connected cluster, or retry once the spoke reconnects."
	return e
}

// factsAge reports how stale a cluster's published facts are.
func factsAge(c fleet.Cluster, now time.Time) time.Duration {
	if c.LastSeen.IsZero() {
		return 0
	}
	d := now.Sub(c.LastSeen)
	if d < 0 {
		return 0
	}
	return d
}

// clampInt bounds n to [lo, hi], substituting def for a non-positive n.
func clampInt(n, def, lo, hi int) int {
	if n <= 0 {
		n = def
	}
	return min(max(n, lo), hi)
}

// matchesSelector reports whether every key of sel is present and equal in
// labels. An empty selector matches everything.
func matchesSelector(labels, sel map[string]string) bool {
	for k, v := range sel {
		if labels[k] != v {
			return false
		}
	}
	return true
}

// dedupe returns s with duplicates removed, order preserved.
func dedupe(s []string) []string {
	if len(s) < 2 {
		return s
	}
	seen := make(map[string]bool, len(s))
	out := make([]string, 0, len(s))
	for _, v := range s {
		if seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

// includes reports whether want appears in list, treating an empty list as the
// caller's defaults having already been substituted.
func includes(list []string, want string) bool { return slices.Contains(list, want) }
