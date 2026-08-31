// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package mcptools

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/fleet"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/promproxy"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/render"
)

// Prometheus is the authorized, budgeted call surface the tools require.
// *promproxy.Proxy satisfies it. It is declared here rather than imported as a
// concrete type so the tools can be driven against a fake without standing up
// a registry and a tunnel.
//
// Implementations must be safe for concurrent use.
type Prometheus interface {
	// Do performs one allow-listed Prometheus call. It re-checks the
	// principal's cluster scope; the tool layer's own check is never the only
	// one.
	Do(ctx context.Context, principal *fleet.Principal, call promproxy.Call) (*promproxy.Result, error)
}

// Clusters is the registry surface the tools require. *registry.Registry
// satisfies it.
//
// Implementations must be safe for concurrent use.
type Clusters interface {
	// Visible returns the clusters the principal is authorized to reach,
	// ordered by ID.
	Visible(p *fleet.Principal) []fleet.Cluster
	// Cluster returns one cluster's entry. The second result is false for a
	// cluster the hub has never seen or has forgotten.
	Cluster(id string) (fleet.Cluster, bool)
	// Nearest returns up to n cluster IDs closest to id by edit distance.
	// Results are filtered against Visible before they reach an agent.
	Nearest(id string, n int) []string
}

// Metrics is the narrow instrumentation surface this package reports.
// Cardinality: tool is a closed enum of the registered tool names and result
// is one of the Code constants or "ok". No cluster identifier, PromQL text or
// label value is ever passed as a label value.
//
// Implementations must be safe for concurrent use and must not block.
type Metrics interface {
	// ToolCall counts one completed tool invocation.
	ToolCall(tool, result string)
	// ToolDuration observes the wall time of one tool invocation.
	ToolDuration(tool string, d time.Duration)
}

// NopMetrics implements [Metrics] and discards everything.
type NopMetrics struct{}

// ToolCall implements [Metrics].
func (NopMetrics) ToolCall(string, string) {}

// ToolDuration implements [Metrics].
func (NopMetrics) ToolDuration(string, time.Duration) {}

var _ Metrics = NopMetrics{}

// Defaults applied by [New] when the corresponding [Options] field is zero.
const (
	// DefaultFanoutConcurrency is how many clusters a fan-out queries at once.
	DefaultFanoutConcurrency = 8
	// MaxFanoutConcurrency is the ceiling a caller may raise concurrency to.
	MaxFanoutConcurrency = 32
	// DefaultFanoutDeadline bounds a whole fan-out.
	DefaultFanoutDeadline = 60 * time.Second
	// MaxFanoutDeadline is the ceiling a caller may raise the deadline to.
	MaxFanoutDeadline = 300 * time.Second
	// DefaultMaxClusters bounds how many clusters one fan-out touches.
	DefaultMaxClusters = 25
	// MaxClustersCeiling is the ceiling a caller may raise maxClusters to.
	MaxClustersCeiling = 100
	// DefaultMaxLookback is how far back in time a query may reach when the
	// principal sets no tighter limit.
	DefaultMaxLookback = 90 * 24 * time.Hour
	// DefaultQueryTimeout bounds one instant query.
	DefaultQueryTimeout = 30 * time.Second
	// DefaultRangeTimeout bounds one range query.
	DefaultRangeTimeout = 60 * time.Second
	// MaxQueryTimeout is the ceiling a caller may raise a query timeout to.
	MaxQueryTimeout = 120 * time.Second
	// StaleFactsAfter is how old a cluster's published facts may be before a
	// result marks them stale. It is five poll intervals, so a single missed
	// poll does not cry wolf.
	StaleFactsAfter = 5 * time.Minute
)

// Options configures [New]. Prometheus and Clusters are required; every other
// field has a documented default.
type Options struct {
	// Prometheus performs the upstream calls. Required.
	Prometheus Prometheus
	// Clusters resolves and lists the fleet. Required.
	Clusters Clusters
	// Logger receives tool-level events. Nil discards them. It never logs a
	// PromQL expression, a label value or a response body.
	Logger *slog.Logger
	// Metrics counts tool calls. Nil means [NopMetrics].
	Metrics Metrics
	// Clock supplies the current time, which is what "now-6h" is relative to.
	// Nil means time.Now.
	Clock func() time.Time
	// TokenCeiling is the estimated-token ceiling enforced on every result.
	// Zero means [render.DefaultTokenCeiling].
	TokenCeiling int
	// MaxLookback bounds how far back a query may reach. Zero means
	// [DefaultMaxLookback]. A principal's own limit tightens it further.
	MaxLookback time.Duration
	// FanoutConcurrency is the default fan-out concurrency. Zero means
	// [DefaultFanoutConcurrency].
	FanoutConcurrency int
}

// Tools is the registered MCP tool set. Create one with [New] and register it
// on a [mcpsurface.Server] with [Tools.Register]. It is safe for concurrent
// use.
type Tools struct {
	prom     Prometheus
	clusters Clusters
	log      *slog.Logger
	metrics  Metrics
	now      func() time.Time

	tokenCeiling      int
	maxLookback       time.Duration
	fanoutConcurrency int
}

// New returns a Tools configured by opts.
func New(opts Options) (*Tools, error) {
	if opts.Prometheus == nil {
		return nil, errors.New("mcptools: Options.Prometheus is required")
	}
	if opts.Clusters == nil {
		return nil, errors.New("mcptools: Options.Clusters is required")
	}
	t := &Tools{
		prom:              opts.Prometheus,
		clusters:          opts.Clusters,
		log:               opts.Logger,
		metrics:           opts.Metrics,
		now:               opts.Clock,
		tokenCeiling:      opts.TokenCeiling,
		maxLookback:       opts.MaxLookback,
		fanoutConcurrency: opts.FanoutConcurrency,
	}
	if t.log == nil {
		t.log = slog.New(slog.DiscardHandler)
	}
	if t.metrics == nil {
		t.metrics = NopMetrics{}
	}
	if t.now == nil {
		t.now = time.Now
	}
	if t.tokenCeiling == 0 {
		t.tokenCeiling = render.DefaultTokenCeiling
	}
	if t.maxLookback <= 0 {
		t.maxLookback = DefaultMaxLookback
	}
	if t.fanoutConcurrency <= 0 {
		t.fanoutConcurrency = DefaultFanoutConcurrency
	}
	if t.fanoutConcurrency > MaxFanoutConcurrency {
		t.fanoutConcurrency = MaxFanoutConcurrency
	}
	return t, nil
}

// Envelope is embedded in every tool output.
//
// Error and the payload are mutually exclusive: a result either describes the
// world or explains why it could not. Untrusted is set on every result that
// carries remote data and is the structural boundary between text this project
// authored and text a monitored cluster did.
type Envelope struct {
	// Error is set, and the result marked isError, when the tool has a fact
	// about the world to report rather than data.
	Error *ToolError `json:"error,omitempty"`
	// Untrusted is [render.UntrustedNotice] on any result carrying remote
	// data.
	Untrusted string `json:"_untrusted,omitempty"`
}

// untrusted returns an Envelope marking the result as carrying remote data.
func untrusted() Envelope { return Envelope{Untrusted: render.UntrustedNotice} }

// failed returns an Envelope carrying a tool error.
