// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package promproxy

import (
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"time"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/fleet"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/promapi"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/registry"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/tunnel"
)

// Defaults applied by [New] when the corresponding [Options] field is zero.
const (
	// DefaultTimeout bounds one upstream call.
	DefaultTimeout = 30 * time.Second
	// DefaultMaxTimeout is the ceiling a caller may raise the timeout to.
	DefaultMaxTimeout = 120 * time.Second
	// DefaultMaxResponseBytes caps a single response body.
	DefaultMaxResponseBytes = 32 << 20
	// DefaultGlobalResponseBudget caps the total response bytes the hub will
	// have reserved at any instant.
	DefaultGlobalResponseBudget = 256 << 20
	// DefaultMaxInflightPerCluster caps simultaneous calls to one cluster.
	DefaultMaxInflightPerCluster = 8
	// DefaultFanoutConcurrency is used when [Proxy.Fanout] is given a
	// non-positive concurrency.
	DefaultFanoutConcurrency = 8
)

// errBudgetTooLarge reports a reservation larger than the whole global budget.
// It is an internal invariant failure: [New] rejects a configuration where a
// single response cap exceeds the global budget, and per-call caps are clamped
// to it.
var errBudgetTooLarge = errors.New("promproxy: reservation exceeds the global response budget")

// Options configures a [Proxy]. Registry is required; every other field has a
// documented default.
type Options struct {
	// Registry resolves a cluster ID to a live tunnel and to the labels that
	// scope evaluation runs against. Required.
	Registry *registry.Registry
	// Logger receives denial and failure events. Nil discards them.
	Logger *slog.Logger
	// Metrics receives per-call instrumentation. Nil uses [NopMetrics].
	Metrics Metrics
	// DefaultTimeout bounds a call that does not ask for a timeout. Zero uses
	// [DefaultTimeout].
	DefaultTimeout time.Duration
	// MaxTimeout is the ceiling any call is clamped to, whatever the caller or
	// the principal's limits ask for. Zero uses [DefaultMaxTimeout].
	MaxTimeout time.Duration
	// MaxResponseBytes caps one response body after decompression. Zero uses
	// [DefaultMaxResponseBytes].
	MaxResponseBytes int64
	// GlobalResponseBudget caps the response bytes reserved hub-wide at any
	// instant. Zero uses [DefaultGlobalResponseBudget]. It must be at least
	// MaxResponseBytes, or a single maximum-size call could never be admitted.
	GlobalResponseBudget int64
	// MaxInflightPerCluster caps simultaneous calls to one cluster. Zero uses
	// [DefaultMaxInflightPerCluster].
	MaxInflightPerCluster int
	// EnableStatusConfig un-gates /api/v1/status/config. It is off by default
	// because scrape configurations routinely embed bearer tokens and
	// basic-auth credentials in plain text.
	EnableStatusConfig bool
	// Clock supplies the current time. Nil uses [time.Now].
	Clock func() time.Time
}

// Proxy performs authorized, budgeted Prometheus calls against the fleet.
// Create one with [New]; share it across every request.
type Proxy struct {
	reg     *registry.Registry
	log     *slog.Logger
	metrics Metrics
	now     func() time.Time

	defaultTimeout   time.Duration
	maxTimeout       time.Duration
	maxResponseBytes int64
	maxInflight      int
	enableConfig     bool

	inflight *inflightSem
	bytes    *byteSem
}

// New returns a Proxy configured by opts.
func New(opts Options) (*Proxy, error) {
	if opts.Registry == nil {
		return nil, errors.New("promproxy: registry is required")
	}
	if opts.DefaultTimeout < 0 || opts.MaxTimeout < 0 {
		return nil, errors.New("promproxy: timeouts must not be negative")
	}
	if opts.MaxResponseBytes < 0 || opts.GlobalResponseBudget < 0 {
		return nil, errors.New("promproxy: byte budgets must not be negative")
	}
	if opts.MaxInflightPerCluster < 0 {
		return nil, errors.New("promproxy: max in-flight per cluster must not be negative")
	}
	p := &Proxy{
		reg:              opts.Registry,
		log:              opts.Logger,
		metrics:          opts.Metrics,
		now:              opts.Clock,
		defaultTimeout:   opts.DefaultTimeout,
		maxTimeout:       opts.MaxTimeout,
		maxResponseBytes: opts.MaxResponseBytes,
		maxInflight:      opts.MaxInflightPerCluster,
		enableConfig:     opts.EnableStatusConfig,
		inflight:         newInflightSem(),
	}
	if p.log == nil {
		p.log = slog.New(slog.DiscardHandler)
	}
	if p.metrics == nil {
		p.metrics = NopMetrics{}
	}
	if p.now == nil {
		p.now = time.Now
	}
	if p.defaultTimeout == 0 {
		p.defaultTimeout = DefaultTimeout
	}
	if p.maxTimeout == 0 {
		p.maxTimeout = DefaultMaxTimeout
	}
	if p.maxResponseBytes == 0 {
		p.maxResponseBytes = DefaultMaxResponseBytes
	}
	if p.maxInflight == 0 {
		p.maxInflight = DefaultMaxInflightPerCluster
	}
	budget := opts.GlobalResponseBudget
	if budget == 0 {
		budget = DefaultGlobalResponseBudget
	}
	if budget < p.maxResponseBytes {
		return nil, fmt.Errorf(
			"promproxy: global response budget %d is smaller than the per-response cap %d",
			budget, p.maxResponseBytes)
	}
	if p.defaultTimeout > p.maxTimeout {
		return nil, fmt.Errorf("promproxy: default timeout %s exceeds max timeout %s",
			p.defaultTimeout, p.maxTimeout)
	}
	p.bytes = newByteSem(budget)
	return p, nil
}

// Call is one Prometheus request. There is deliberately no path field: the
// upstream path is derived from Endpoint through internal/promapi, which is
// what makes SSRF and path traversal structurally impossible rather than
// filtered.
type Call struct {
	// ClusterID names the target cluster.
	ClusterID string
	// Endpoint selects the allow-listed operation.
	Endpoint promapi.Endpoint
	// LabelName is the path parameter of [promapi.EndpointLabelValues] and
	// must be empty for every other endpoint.
	LabelName string
	// Form carries the query parameters. It is validated against the
	// endpoint's parameter table and is never mutated.
	Form url.Values
	// Timeout requests a deadline. Zero uses the proxy default; any value is
	// clamped to the proxy maximum and to the principal's limit.
	Timeout time.Duration
	// MaxBytes requests a response cap. Zero uses the proxy default; any value
	// is clamped down the same way.
	MaxBytes int64
	// RequestID correlates hub and spoke logs for one tool call. It is never
	// used as a metric label.
	RequestID string
}

// Result is one completed round trip. A non-2xx Status is a result, not an
// error: Prometheus validates PromQL and its 400 body carries the message an
// agent needs.
type Result struct {
	// Body is the response body, decompressed. When Truncated is true it is
	// the first MaxBytes of the body and is not valid JSON.
	Body []byte
	// Status is the upstream HTTP status code.
	Status int
	// Warnings are the spoke's per-request warnings, if any.
	Warnings []string
	// Truncated reports that the byte cap was hit and Body is incomplete.
	Truncated bool
	// Latency is the wall time of the call, including budget waiting.
	Latency time.Duration
	// Bytes is len(Body), the decompressed size the hub actually holds.
	Bytes int64
}

// Do performs one authorized, budgeted call.
//
// It returns [ErrForbidden] when the principal's scope does not permit the
// cluster — identically for a cluster that does not exist, so a denial cannot
// confirm existence. A principal that would have been permitted instead
// receives [registry.ErrUnknownCluster] for a cluster the hub has never seen,
// or a [NotConnectedError] carrying LastSeen for one whose spoke is currently
// gone. Both also satisfy errors.Is(err, [tunnel.ErrNotConnected]), so a caller
// that only asks "can I route to this cluster" tests one sentinel.
//
// When the response hits the byte cap, Do returns a non-nil Result with
// Truncated set *and* an error wrapping [ErrTooLarge]. The partial body is
// returned so a caller can report how far it got; it must not be parsed.
//
// ctx is honoured throughout and is propagated into [tunnel.Session.Do], so
// cancelling it aborts the query inside the remote cluster rather than merely
// abandoning the response.
func (p *Proxy) Do(ctx context.Context, principal *fleet.Principal, call Call) (*Result, error) {
	start := p.now()

	route, path, err := p.authorizeAndBuild(principal, call)
	if err != nil {
		p.observe(call, start, codeFor(err))
		return nil, err
	}

	sess, err := p.session(call.ClusterID)
	if err != nil {
		p.observe(call, start, codeFor(err))
		return nil, err
	}

	limits := limitsOf(principal)
	timeout := p.effectiveTimeout(limits, call.Timeout)
	maxBytes := p.effectiveMaxBytes(limits, call.MaxBytes)
	inflight := p.effectiveInflight(limits)

	if !p.inflight.acquire(call.ClusterID, inflight) {
		err := &BusyError{
			ClusterID:  call.ClusterID,
			Budget:     "cluster-inflight",
			Limit:      int64(inflight),
			RetryAfter: ClusterBusyRetryAfter,
		}
		p.log.WarnContext(ctx, "promproxy: cluster in-flight budget exhausted",
			"cluster", call.ClusterID, "endpoint", string(call.Endpoint), "limit", inflight)
		p.observe(call, start, CodeBusy)
		return nil, err
	}
	p.metrics.ProxyInflight(call.ClusterID, 1)
	defer func() {
		p.inflight.release(call.ClusterID)
		p.metrics.ProxyInflight(call.ClusterID, -1)
	}()

	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Reserve the worst case before the call, and count the wait against the
	// call's own deadline so a saturated hub fails fast rather than piling up.
	if err := p.bytes.acquire(cctx, maxBytes); err != nil {
		if ctx.Err() != nil {
			werr := fmt.Errorf("cluster %s %s: %w", call.ClusterID, call.Endpoint, ctx.Err())
			p.observe(call, start, CodeTimeout)
			return nil, werr
		}
		busy := &BusyError{
			ClusterID:  call.ClusterID,
			Budget:     "hub-response-bytes",
			Limit:      p.bytes.capacity,
			RetryAfter: HubBusyRetryAfter,
		}
		p.log.WarnContext(ctx, "promproxy: hub response budget exhausted",
			"cluster", call.ClusterID, "endpoint", string(call.Endpoint), "want_bytes", maxBytes)
		p.observe(call, start, CodeBusy)
		return nil, busy
	}
	defer p.bytes.release(maxBytes)

	req := &tunnel.Request{
		Method:           route.Method,
		Path:             path,
		Form:             []byte(call.Form.Encode()),
		MaxResponseBytes: maxBytes,
		// Ask for compressed bytes: the tunnel is the expensive hop. The cap
		// below is applied to the inflated size as well, so a gzip bomb buys
		// an attacker nothing.
		AcceptGzip: true,
		RequestID:  call.RequestID,
	}

	resp, err := sess.Do(cctx, req)
	if err != nil {
		wrapped := p.wrapCallError(call, err)
		p.observe(call, start, codeFor(wrapped))
		return nil, wrapped
	}
	if resp.Body != nil {
		defer func() { _ = resp.Body.Close() }()
	}

	body, truncated, rerr := readCapped(resp, maxBytes)
	if rerr != nil {
		wrapped := p.wrapCallError(call, rerr)
		p.observe(call, start, codeFor(wrapped))
		return nil, wrapped
	}

	res := &Result{
		Body:      body,
		Status:    resp.StatusCode,
		Truncated: truncated,
		Latency:   p.now().Sub(start),
		Bytes:     int64(len(body)),
	}
	if !truncated && resp.Trailer != nil {
		tr := resp.Trailer()
		res.Warnings = tr.Warnings
		res.Truncated = res.Truncated || tr.Truncated
		if tr.Err != nil {
			wrapped := p.wrapCallError(call, tr.Err)
			p.observe(call, start, codeFor(wrapped))
			return nil, wrapped
		}
	}
	p.metrics.ProxyResponseBytes(res.Bytes)

	if res.Truncated {
		err := fmt.Errorf("cluster %s %s: %w: read %d bytes",
			call.ClusterID, call.Endpoint, ErrTooLarge, res.Bytes)
		p.observe(call, start, CodeTooLarge)
		return res, err
	}
	p.observe(call, start, statusCode(res.Status))
	return res, nil
}

// authorizeAndBuild runs the authorization and validation steps in the order
// the security model requires: scope first, so a caller that may not reach a
// cluster never learns whether its arguments were valid either.
func (p *Proxy) authorizeAndBuild(
	principal *fleet.Principal, call Call,
) (promapi.Route, string, error) {
	if call.ClusterID == "" {
		return promapi.Route{}, "", fmt.Errorf("%w: cluster id is required", promapi.ErrInvalidParam)
	}
	// A cluster the hub does not know contributes no labels, so a scope with a
	// label selector denies it exactly as it would deny a real cluster whose
	// labels do not match. Known and unknown therefore produce byte-identical
	// denials.
	cluster, known := p.reg.Cluster(call.ClusterID)
	if !allows(principal, call.ClusterID, cluster.Labels) {
		p.log.Warn("promproxy: denied",
			"principal", principal.String(), "cluster", call.ClusterID,
			"endpoint", string(call.Endpoint))
		return promapi.Route{}, "", fmt.Errorf("cluster %s: %w", call.ClusterID, ErrForbidden)
	}
	if !known {
		return promapi.Route{}, "", unknownCluster(call.ClusterID)
	}

	route, err := promapi.Get(call.Endpoint)
	if err != nil {
		return promapi.Route{}, "", err
	}
	path, err := promapi.BuildPath(call.Endpoint, call.LabelName)
	if err != nil {
		return promapi.Route{}, "", err
	}
	if err := promapi.Validate(call.Endpoint, call.Form, p.enableConfig); err != nil {
		return promapi.Route{}, "", err
	}
	return route, path, nil
}

// session resolves the live tunnel, converting the registry's not-connected
// error into one that carries the last contact time.
func (p *Proxy) session(clusterID string) (tunnel.Session, error) {
	sess, err := p.reg.Session(clusterID)
	if err == nil {
		return sess, nil
	}
	if errors.Is(err, registry.ErrUnknownCluster) {
		return nil, unknownCluster(clusterID)
	}
	nc := &NotConnectedError{ClusterID: clusterID}
	if c, ok := p.reg.Cluster(clusterID); ok {
		nc.LastSeen = c.LastSeen
		if !c.LastSeen.IsZero() {
			nc.Since = p.now().Sub(c.LastSeen)
		}
	}
	return nil, nc
}

// unknownCluster reports a cluster the registry holds no entry for.
//
// It carries both sentinels [registry.Registry.Session] joins, and for the same
// reason: a caller that only asks "can I route to this cluster" tests
// [tunnel.ErrNotConnected] and must not have to know that an unknown cluster is
// a special case of it, while a caller building an UNKNOWN_CLUSTER tool error
// with did-you-mean suggestions tests [registry.ErrUnknownCluster]. Both of
// Do's unknown-cluster paths route through here so that the sentinel set does
// not depend on which of the two registry lookups happened to notice first.
func unknownCluster(clusterID string) error {
	return fmt.Errorf("cluster %s: %w", clusterID,
		errors.Join(registry.ErrUnknownCluster, tunnel.ErrNotConnected))
}

// wrapCallError maps a transport or upstream failure onto a sentinel.
func (p *Proxy) wrapCallError(call Call, err error) error {
	switch {
	case errors.Is(err, tunnel.ErrNotConnected):
		nc := &NotConnectedError{ClusterID: call.ClusterID}
		if c, ok := p.reg.Cluster(call.ClusterID); ok {
			nc.LastSeen = c.LastSeen
			if !c.LastSeen.IsZero() {
				nc.Since = p.now().Sub(c.LastSeen)
			}
		}
		return nc
	case errors.Is(err, tunnel.ErrResponseTooLarge):
		return fmt.Errorf("cluster %s %s: %w: %w",
			call.ClusterID, call.Endpoint, ErrTooLarge, err)
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return fmt.Errorf("cluster %s %s: %w", call.ClusterID, call.Endpoint, err)
	default:
		return fmt.Errorf("cluster %s %s: %w: %w",
			call.ClusterID, call.Endpoint, ErrUpstream, err)
	}
}

// observe records the metrics for one completed call.
func (p *Proxy) observe(call Call, start time.Time, code string) {
	d := p.now().Sub(start)
	p.metrics.ProxyRequest(call.ClusterID, call.Endpoint, code)
	p.metrics.ProxyDuration(call.ClusterID, call.Endpoint, d)
}

// allows evaluates the principal's cluster scope. A nil principal or a nil
// scope authorizes nothing: fleet.Scope is deny-by-default and the proxy does
// not add an exception to that.
func allows(p *fleet.Principal, id string, labels map[string]string) bool {
	if p == nil {
		return false
	}
	return p.Scope.AllowsCluster(id, labels)
}

// limitsOf returns the principal's limits, or the zero value when it has no
// scope. Zero means "use the hub default" for every field.
func limitsOf(p *fleet.Principal) fleet.Limits {
	if p == nil || p.Scope == nil {
		return fleet.Limits{}
	}
	return p.Scope.Limits
}

// effectiveTimeout takes the most restrictive of the caller's request, the
// hub's ceiling and the principal's limit. A scope can only ever tighten.
func (p *Proxy) effectiveTimeout(lim fleet.Limits, want time.Duration) time.Duration {
	t := want
	if t <= 0 {
		t = p.defaultTimeout
	}
	t = min(t, p.maxTimeout)
	if l := time.Duration(lim.Timeout); l > 0 {
		t = min(t, l)
	}
	return t
}

// effectiveMaxBytes takes the most restrictive of the caller's request, the
// hub's cap and the principal's limit.
func (p *Proxy) effectiveMaxBytes(lim fleet.Limits, want int64) int64 {
	b := want
	if b <= 0 {
		b = p.maxResponseBytes
	}
	b = min(b, p.maxResponseBytes)
	if lim.MaxResponseBytes > 0 {
		b = min(b, lim.MaxResponseBytes)
	}
	return b
}

// effectiveInflight takes the more restrictive of the hub's per-cluster
// ceiling and the principal's limit.
func (p *Proxy) effectiveInflight(lim fleet.Limits) int {
	n := p.maxInflight
	if lim.MaxConcurrentPerCluster > 0 {
		n = min(n, lim.MaxConcurrentPerCluster)
	}
	return n
}

// capReader reads at most a fixed number of bytes and records whether it hit
// that limit. io.LimitReader alone cannot tell a truncated gzip stream from a
// corrupt one, and the difference decides whether the caller sees ErrTooLarge
// or ErrUpstream.
type capReader struct {
	r         io.Reader
	remaining int64
	hit       bool
}

// Read implements io.Reader.
func (c *capReader) Read(p []byte) (int, error) {
	if c.remaining <= 0 {
		c.hit = true
		return 0, io.EOF
	}
	if int64(len(p)) > c.remaining {
		p = p[:c.remaining]
	}
	n, err := c.r.Read(p)
	c.remaining -= int64(n)
	return n, err
}

// readCapped reads a response body under a hard cap, inflating gzip as it
// goes. The cap is applied to the compressed stream *and* to the decompressed
// output, so a body that expands a thousandfold is cut at the same ceiling as
// a plain one.
func readCapped(resp *tunnel.Response, maxBytes int64) (body []byte, truncated bool, err error) {
	if resp.Body == nil {
		return nil, false, nil
	}
	// Reading one byte past the cap is what distinguishes "exactly at the
	// limit" from "truncated".
	cr := &capReader{r: resp.Body, remaining: maxBytes + 1}
	var r io.Reader = cr
	if resp.ContentEncoding == "gzip" {
		zr, zerr := gzip.NewReader(r)
		if zerr != nil {
			if cr.hit {
				return nil, true, nil
			}
			return nil, false, fmt.Errorf("gzip: %w", zerr)
		}
		defer func() { _ = zr.Close() }()
		r = io.LimitReader(zr, maxBytes+1)
	}
	b, rerr := io.ReadAll(r)
	if int64(len(b)) > maxBytes {
		return b[:maxBytes], true, nil
	}
	if rerr != nil {
		// A compressed stream cut at the cap makes the inflater report a
		// corrupt trailer; that is the cap working, not a failure.
		if cr.hit || errors.Is(rerr, tunnel.ErrResponseTooLarge) {
			return b, true, nil
		}
		return nil, false, rerr
	}
	return b, false, nil
}

// codeFor maps an error to its closed-enum metric code.
func codeFor(err error) string {
	switch {
	case err == nil:
		return CodeOK
	case errors.Is(err, ErrForbidden):
		return CodeForbidden
	case errors.Is(err, ErrBusy):
		return CodeBusy
	case errors.Is(err, ErrTooLarge):
		return CodeTooLarge
	case errors.Is(err, registry.ErrUnknownCluster), errors.Is(err, tunnel.ErrNotConnected):
		return CodeUnavailable
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return CodeTimeout
	case errors.Is(err, promapi.ErrInvalidParam), errors.Is(err, promapi.ErrUnknownEndpoint),
		errors.Is(err, promapi.ErrEndpointGated), errors.Is(err, promapi.ErrInvalidLabelName):
		return CodeInvalid
	default:
		return CodeUpstream
	}
}

// statusCode maps an upstream HTTP status onto its closed-enum metric code.
func statusCode(status int) string {
	switch {
	case status >= 200 && status < 300:
		return CodeOK
	case status >= 400 && status < 500:
		return CodeClientError
	case status >= 500:
		return CodeServerError
	default:
		return CodeUpstream
	}
}
