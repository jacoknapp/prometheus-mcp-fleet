// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package promclient

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/promapi"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/tunnel"
)

// Errors returned by this package. Callers branch on them with errors.Is.
var (
	// ErrNotAllowed reports that a request was refused by the spoke's own
	// allow-list re-validation, regardless of what the hub asked for.
	ErrNotAllowed = errors.New("promclient: request is not in the allow-list")
	// ErrUpstream reports that the call to the local Prometheus could not be
	// completed: dial failure, TLS failure, timeout, or a malformed reply.
	// A non-2xx HTTP status is not an ErrUpstream — it is a legitimate answer
	// and is passed through to the hub verbatim.
	ErrUpstream = errors.New("promclient: upstream request failed")
	// ErrTooLarge reports that the response exceeded Config.MaxResponseBytes
	// and was aborted mid-transfer. It wraps [tunnel.ErrResponseTooLarge] so
	// the hub can recognise it after it crosses the tunnel.
	ErrTooLarge = fmt.Errorf("promclient: response exceeded the byte cap: %w", tunnel.ErrResponseTooLarge)
)

// Tunable constants. They are exported because the spoke's readiness probe and
// the hub's timeout budgeting both need to reason about them.
const (
	// HopMargin is subtracted from the remaining context deadline before the
	// upstream call is made.
	//
	// Why: the hub propagates its deadline down the tunnel as a gRPC timeout.
	// If the spoke gave the whole of it to Prometheus, the upstream call and
	// the tunnel would expire at the same instant and the hub would observe a
	// truncated stream with no explanation. Reserving 250ms guarantees the
	// spoke loses the race, notices, and returns a structured error that the
	// hub can turn into a proper TIMEOUT tool error.
	HopMargin = 250 * time.Millisecond

	// DefaultTimeout is the ceiling on one upstream call when Config.Timeout
	// is zero. The context deadline is the usual bound; see Config.Timeout.
	DefaultTimeout = 30 * time.Second

	// DefaultMaxResponseBytes bounds one upstream response body when
	// Config.MaxResponseBytes is zero. It matches the hub's default.
	DefaultMaxResponseBytes = 32 << 20

	// DefaultUserAgent identifies the spoke to the local Prometheus.
	DefaultUserAgent = "prometheus-mcp-fleet-spoke"

	// warningsPeekLimit bounds how much of a response body may be buffered in
	// order to read its "warnings" member. Anything larger is not inspected:
	// this package must never hold a whole 32 MiB response in memory just to
	// report metadata.
	warningsPeekLimit = 128 << 10

	// maxJSONHelperBytes bounds the typed helpers (GetJSON, InstantQuery,
	// LabelValues). Those responses are consumed in process, so they get a
	// tighter cap than the streamed tunnel path.
	maxJSONHelperBytes = 8 << 20
)

// Config configures a [Client]. Only BaseURL is required.
type Config struct {
	// BaseURL is the root of the Prometheus HTTP API, for example
	// "http://prometheus-operated.monitoring.svc:9090". A path prefix
	// ("http://gateway/prom") and a query prefix are both preserved.
	BaseURL string
	// Timeout is the ceiling on one upstream call. Defaults to
	// [DefaultTimeout]. The context deadline the hub forwards down the tunnel
	// is the usual bound; this only matters when that deadline is absent or
	// longer, so it should sit above the hub's largest per-call timeout.
	Timeout time.Duration
	// BearerTokenFile is read on every request, not once at startup, because
	// Kubernetes rotates projected service account tokens in place and a
	// cached token starts returning 401 an hour later.
	BearerTokenFile string
	// TLSCAFile is a PEM bundle used to verify the upstream server. Empty
	// means the system pool.
	TLSCAFile string
	// TLSInsecure disables verification of the upstream certificate.
	TLSInsecure bool
	// MaxResponseBytes bounds one response body. Defaults to
	// [DefaultMaxResponseBytes].
	MaxResponseBytes int64
	// AllowStatusConfig enables [promapi.EndpointConfig], which is gated off
	// by default because scrape configurations embed credentials.
	AllowStatusConfig bool
	// UserAgent is sent on every request. Defaults to [DefaultUserAgent].
	UserAgent string
	// Logger receives request-level debug records. Defaults to a discarding
	// logger. Response bodies and Authorization headers are never logged.
	Logger *slog.Logger
	// Clock supplies the current time for latency accounting and deadline
	// budgeting. Defaults to time.Now. A test that injects a clock which does
	// not track wall time must not also set a context deadline.
	Clock func() time.Time
	// Metrics receives one record per upstream round trip. Defaults to
	// [NopMetrics].
	Metrics Metrics
}

// Client is the spoke's connection to one Prometheus-compatible server.
type Client struct {
	base              *url.URL
	httpc             *http.Client
	timeout           time.Duration
	bearerTokenFile   string
	maxResponseBytes  int64
	allowStatusConfig bool
	userAgent         string
	log               *slog.Logger
	now               func() time.Time
	metrics           Metrics
}

// New validates cfg and returns a ready client. It performs no I/O beyond
// reading Config.TLSCAFile, so it never blocks on an unreachable Prometheus.
func New(cfg Config) (*Client, error) {
	if strings.TrimSpace(cfg.BaseURL) == "" {
		return nil, errors.New("promclient: BaseURL is required")
	}
	base, err := url.Parse(cfg.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("promclient: parse BaseURL: %w", err)
	}
	if base.Scheme != "http" && base.Scheme != "https" {
		return nil, fmt.Errorf("promclient: BaseURL scheme %q must be http or https", base.Scheme)
	}
	if base.Host == "" {
		return nil, fmt.Errorf("promclient: BaseURL %q has no host", cfg.BaseURL)
	}
	base.Fragment, base.RawFragment = "", ""
	if cfg.MaxResponseBytes < 0 {
		return nil, fmt.Errorf("promclient: MaxResponseBytes %d must not be negative", cfg.MaxResponseBytes)
	}
	if cfg.Timeout < 0 {
		return nil, fmt.Errorf("promclient: Timeout %s must not be negative", cfg.Timeout)
	}

	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: cfg.TLSInsecure} //nolint:gosec // operator opt-in
	if cfg.TLSCAFile != "" {
		pem, err := os.ReadFile(cfg.TLSCAFile)
		if err != nil {
			return nil, fmt.Errorf("promclient: read TLSCAFile: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("promclient: TLSCAFile %q contains no certificate", cfg.TLSCAFile)
		}
		tlsCfg.RootCAs = pool
	}

	c := &Client{
		base:              base,
		timeout:           cmpOrDefault(cfg.Timeout, DefaultTimeout),
		bearerTokenFile:   cfg.BearerTokenFile,
		maxResponseBytes:  cmpOrDefault(cfg.MaxResponseBytes, int64(DefaultMaxResponseBytes)),
		allowStatusConfig: cfg.AllowStatusConfig,
		userAgent:         cmpOrDefault(cfg.UserAgent, DefaultUserAgent),
		log:               cfg.Logger,
		now:               cfg.Clock,
		metrics:           cfg.Metrics,
	}
	if c.metrics == nil {
		c.metrics = NopMetrics{}
	}
	if c.log == nil {
		c.log = slog.New(slog.DiscardHandler)
	}
	if c.now == nil {
		c.now = time.Now
	}
	c.httpc = &http.Client{
		// No global timeout: it would also bound body streaming, and the
		// per-request context already carries the real deadline.
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   10 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          32,
			MaxIdleConnsPerHost:   8,
			MaxConnsPerHost:       32,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: time.Second,
			ResponseHeaderTimeout: c.timeout,
			TLSClientConfig:       tlsCfg,
			// Transparent decompression must stay off. When the hub asks for
			// gzip we forward Prometheus' compressed bytes verbatim, and Go
			// would otherwise inflate them behind our back and strip
			// Content-Encoding, so the hub would receive plain JSON labelled
			// as gzip.
			DisableCompression: true,
		},
		// Redirects are refused: following one would let an upstream response
		// choose the next URL, which is precisely the SSRF property the
		// allow-list exists to remove.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return c, nil
}

// cmpOrDefault returns v unless it is the zero value, in which case it returns
// def.
func cmpOrDefault[T comparable](v, def T) T {
	var zero T
	if v == zero {
		return def
	}
	return v
}

// BaseURL returns the configured upstream root.
func (c *Client) BaseURL() string { return c.base.String() }

// MaxResponseBytes returns the effective response cap.
func (c *Client) MaxResponseBytes() int64 { return c.maxResponseBytes }

// Do implements the spoke half of [tunnel.Handler]. It re-validates req.Path
// against [promapi.Lookup] and req.Form against [promapi.Validate], refusing
// anything outside the allow-list with [ErrNotAllowed] even though the hub
// already performed the same check.
//
// A non-2xx upstream status is returned as a Response, not an error:
// Prometheus' own 400 with its PromQL parse message is the most useful thing
// an agent can receive, so it is passed through untouched.
//
// The caller must close Response.Body. Reading it may return [ErrTooLarge].
func (c *Client) Do(ctx context.Context, req *tunnel.Request) (*tunnel.Response, error) {
	if req == nil {
		return nil, fmt.Errorf("%w: nil request", ErrNotAllowed)
	}
	route, labelName, ok := promapi.Lookup(req.Method, req.Path)
	if !ok {
		return nil, fmt.Errorf("%w: %s %s", ErrNotAllowed, req.Method, req.Path)
	}
	form, err := url.ParseQuery(string(req.Form))
	if err != nil {
		return nil, fmt.Errorf("%w: parse form for %s: %w", ErrNotAllowed, route.Endpoint, err)
	}
	if err := promapi.Validate(route.Endpoint, form, c.allowStatusConfig); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNotAllowed, err)
	}

	limit := c.maxResponseBytes
	if req.MaxResponseBytes > 0 && req.MaxResponseBytes < limit {
		limit = req.MaxResponseBytes
	}

	//nolint:bodyclose // ownership passes to newLimitedBody below, which closes it; bodyclose cannot follow the handoff.
	resp, latency, cancel, err := c.roundTrip(ctx, route, labelName, form, req.AcceptGzip, req.RequestID)
	if err != nil {
		return nil, err
	}

	encoding := resp.Header.Get("Content-Encoding")
	body := newLimitedBody(resp.Body, limit, latency, cancel, encoding == "" && isJSONContentType(resp.Header.Get("Content-Type")))
	c.log.LogAttrs(ctx, slog.LevelDebug, "prometheus request",
		slog.String("endpoint", string(route.Endpoint)),
		slog.Int("status", resp.StatusCode),
		slog.Duration("upstream_latency", latency),
		slog.String("request_id", req.RequestID),
	)
	return &tunnel.Response{
		StatusCode:      resp.StatusCode,
		ContentType:     resp.Header.Get("Content-Type"),
		ContentEncoding: encoding,
		Body:            body,
		Trailer:         body.trailer,
	}, nil
}

// roundTrip performs one allow-listed call and returns the live response, the
// time to first byte of the header, and the cancel func that must be invoked
// when the body is closed.
func (c *Client) roundTrip(ctx context.Context, route promapi.Route, labelName string, form url.Values, acceptGzip bool, requestID string) (*http.Response, time.Duration, context.CancelFunc, error) {
	path, err := promapi.BuildPath(route.Endpoint, labelName)
	if err != nil {
		return nil, 0, nil, fmt.Errorf("%w: %w", ErrNotAllowed, err)
	}

	callCtx, cancel, err := c.upstreamContext(ctx)
	if err != nil {
		return nil, 0, nil, err
	}

	var (
		u    *url.URL
		body io.Reader
	)
	if strings.EqualFold(route.Method, http.MethodGet) {
		u = c.resolve(path, form)
	} else {
		u = c.resolve(path, nil)
		body = strings.NewReader(form.Encode())
	}

	httpReq, err := http.NewRequestWithContext(callCtx, route.Method, u.String(), body)
	if err != nil {
		cancel()
		return nil, 0, nil, fmt.Errorf("%w: build request: %w", ErrUpstream, err)
	}
	httpReq.Header.Set("User-Agent", c.userAgent)
	httpReq.Header.Set("Accept", "application/json")
	if body != nil {
		httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if acceptGzip {
		httpReq.Header.Set("Accept-Encoding", "gzip")
	}
	if requestID != "" {
		httpReq.Header.Set("X-Request-Id", requestID)
	}
	if err := c.setAuth(httpReq); err != nil {
		cancel()
		return nil, 0, nil, err
	}

	resp, latency, err := c.send(route.Endpoint, httpReq)
	if err != nil {
		cancel()
		return nil, 0, nil, fmt.Errorf("%w: %s: %w", ErrUpstream, route.Endpoint, err)
	}
	return resp, latency, cancel, nil
}

// send is the one place a request leaves for Prometheus, so it is the one
// place the request is counted and timed. Every path -- the tunnel's Do, the
// JSON helpers and the readiness probe -- funnels through it; instrumenting
// the callers instead is how the spoke's request metrics went unwritten for
// nine releases while the chart alerted on them.
func (c *Client) send(endpoint promapi.Endpoint, req *http.Request) (*http.Response, time.Duration, error) {
	start := c.now()
	resp, err := c.httpc.Do(req)
	latency := c.now().Sub(start)
	c.metrics.PromDuration(endpoint, latency)
	if err != nil {
		c.metrics.PromRequest(endpoint, errorCode(req.Context(), err))
		return nil, latency, err
	}
	c.metrics.PromRequest(endpoint, strconv.Itoa(resp.StatusCode))
	return resp, latency, nil
}

// errorCode maps a transport failure onto the closed set of non-status
// codes. Anything that is not a deadline or cancellation is CodeError: the
// distinction that matters to the alert is "Prometheus answered slowly or
// not at all" versus "Prometheus was never reached", and both are visible
// in the error text the hub receives.
func errorCode(ctx context.Context, err error) string {
	if ctx.Err() != nil {
		return CodeTimeout
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return CodeTimeout
	}
	return CodeError
}

// resolve builds the absolute upstream URL by assigning fields on a copy of
// the base URL. The path is never concatenated into a URL string: the only
// user-influenced component that reaches here is a label name that
// promapi.Lookup already constrained to [a-zA-Z_][a-zA-Z0-9_]*.
//
// A base of "http://h/prom" and a validated path of "/api/v1/query" produce
// "http://h/prom/api/v1/query"; a query string on the base is kept as a prefix
// of the request's own parameters.
func (c *Client) resolve(path string, form url.Values) *url.URL {
	u := *c.base
	u.Path = strings.TrimSuffix(c.base.Path, "/") + path
	// Clearing RawPath makes URL.String re-escape Path from scratch, which is
	// correct because Path is now a value we assembled rather than one we
	// parsed.
	u.RawPath = ""
	switch {
	case len(form) == 0:
		u.RawQuery = c.base.RawQuery
	case c.base.RawQuery == "":
		u.RawQuery = form.Encode()
	default:
		u.RawQuery = c.base.RawQuery + "&" + form.Encode()
	}
	return &u
}

// upstreamContext derives the call context, spending at most Config.Timeout
// and always leaving [HopMargin] of the caller's deadline unspent.
func (c *Client) upstreamContext(ctx context.Context) (context.Context, context.CancelFunc, error) {
	budget := c.timeout
	if deadline, ok := ctx.Deadline(); ok {
		remaining := deadline.Sub(c.now()) - HopMargin
		if remaining <= 0 {
			return nil, nil, fmt.Errorf("%w: only %s left, less than the %s hop margin: %w",
				ErrUpstream, deadline.Sub(c.now()), HopMargin, context.DeadlineExceeded)
		}
		if remaining < budget {
			budget = remaining
		}
	}
	callCtx, cancel := context.WithTimeout(ctx, budget)
	return callCtx, cancel, nil
}

// setAuth attaches the bearer token, re-reading the token file on every
// request so that a rotated projected token is picked up immediately.
func (c *Client) setAuth(req *http.Request) error {
	if c.bearerTokenFile == "" {
		return nil
	}
	raw, err := os.ReadFile(c.bearerTokenFile)
	if err != nil {
		return fmt.Errorf("%w: read bearer token file: %w", ErrUpstream, err)
	}
	token := strings.TrimSpace(string(raw))
	if token == "" {
		return fmt.Errorf("%w: bearer token file %q is empty", ErrUpstream, c.bearerTokenFile)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	return nil
}

// Ping reports whether the local Prometheus is reachable. It tries /-/healthy
// first, which is the cheapest endpoint Prometheus exposes, and falls back to
// /api/v1/status/buildinfo for the Prometheus-compatible servers that do not
// serve /-/healthy.
//
// Neither path is reachable from the tunnel: Ping is called by the spoke's
// readiness probe and by the facts collector, never by the hub.
func (c *Client) Ping(ctx context.Context) error {
	healthErr := c.probe(ctx, EndpointHealthy, "/-/healthy")
	if healthErr == nil {
		return nil
	}
	buildErr := c.probe(ctx, promapi.EndpointBuildInfo, "/api/v1/status/buildinfo")
	if buildErr == nil {
		return nil
	}
	return fmt.Errorf("%w: ping: %w", ErrUpstream, errors.Join(healthErr, buildErr))
}

// probe issues a bare GET and reports whether the status was 2xx. endpoint
// is only the label the call is counted under.
func (c *Client) probe(ctx context.Context, endpoint promapi.Endpoint, path string) error {
	callCtx, cancel, err := c.upstreamContext(ctx)
	if err != nil {
		return err
	}
	defer cancel()

	req, err := http.NewRequestWithContext(callCtx, http.MethodGet, c.resolve(path, nil).String(), nil)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	req.Header.Set("User-Agent", c.userAgent)
	if err := c.setAuth(req); err != nil {
		return err
	}
	resp, _, err := c.send(endpoint, req)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	// Drain a bounded amount so the connection can be reused.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("%s: status %d", path, resp.StatusCode)
	}
	return nil
}

// isJSONContentType reports whether a Content-Type names a JSON body.
func isJSONContentType(ct string) bool {
	mediaType, _, _ := strings.Cut(ct, ";")
	mediaType = strings.TrimSpace(strings.ToLower(mediaType))
	return mediaType == "application/json" || strings.HasSuffix(mediaType, "+json")
}
