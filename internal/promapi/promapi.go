// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

// Package promapi is the allow-list of Prometheus HTTP API calls this project
// is willing to make, and the only place that turns tool arguments into an
// upstream request.
//
// The security property it exists to provide: an AI agent never supplies a URL
// or a path. It names an MCP tool, the tool names an [Endpoint], and this
// package maps that endpoint to a hard-coded path template. There is no
// user-controlled URL anywhere in the request path, which removes SSRF and
// path traversal structurally rather than by filtering.
//
// Both sides of the tunnel use this package. The hub builds requests with it;
// the spoke independently re-validates the received path against it with
// [Lookup]. The hub's check is deliberately never the only one.
//
// This package is pure: no I/O, no logging, no global mutable state. All
// functions are safe for concurrent use.
package promapi

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Errors reported by validation. Callers branch on these with errors.Is.
var (
	// ErrUnknownEndpoint is returned for an endpoint that is not in the table.
	ErrUnknownEndpoint = errors.New("promapi: unknown endpoint")
	// ErrEndpointGated is returned for an endpoint that exists but is disabled
	// by configuration.
	ErrEndpointGated = errors.New("promapi: endpoint disabled by configuration")
	// ErrInvalidParam is returned when a parameter is absent, unknown, or fails
	// its kind check.
	ErrInvalidParam = errors.New("promapi: invalid parameter")
	// ErrInvalidLabelName is returned when a label name would not be safe to
	// place in a URL path.
	ErrInvalidLabelName = errors.New("promapi: invalid label name")
)

// Endpoint is the closed set of upstream operations. It doubles as the
// `endpoint` metric label, so it must never grow unbounded and must never
// carry user data.
type Endpoint string

// The supported endpoints. Anything not listed here cannot be reached.
const (
	// EndpointQuery evaluates PromQL at a single instant.
	EndpointQuery Endpoint = "query"
	// EndpointQueryRange evaluates PromQL over a time range.
	EndpointQueryRange Endpoint = "query_range"
	// EndpointSeries lists label sets matching a set of matchers.
	EndpointSeries Endpoint = "series"
	// EndpointLabels lists label names.
	EndpointLabels Endpoint = "labels"
	// EndpointLabelValues lists the values of one label.
	EndpointLabelValues Endpoint = "label_values"
	// EndpointMetadata returns metric type, help and unit.
	EndpointMetadata Endpoint = "metadata"
	// EndpointTargets returns scrape target health. Responses must be redacted
	// by the caller before they reach an agent; scrape URLs routinely embed
	// credentials in query parameters.
	EndpointTargets Endpoint = "targets"
	// EndpointRules returns recording and alerting rule groups.
	EndpointRules Endpoint = "rules"
	// EndpointAlerts returns currently active alerts.
	EndpointAlerts Endpoint = "alerts"
	// EndpointAlertmanagers reports the configured Alertmanager peers.
	EndpointAlertmanagers Endpoint = "alertmanagers"
	// EndpointTSDBStatus returns cardinality statistics.
	EndpointTSDBStatus Endpoint = "tsdb_status"
	// EndpointRuntimeInfo returns process runtime state.
	EndpointRuntimeInfo Endpoint = "runtime_info"
	// EndpointBuildInfo returns version and revision.
	EndpointBuildInfo Endpoint = "build_info"
	// EndpointFlags returns the server's command-line flags.
	EndpointFlags Endpoint = "flags"
	// EndpointConfig returns the full scrape configuration. It is gated off by
	// default: scrape configs routinely contain bearer tokens and basic-auth
	// credentials in plain text.
	EndpointConfig Endpoint = "config"
)

// ParamKind selects the validation applied to a parameter value.
type ParamKind int

const (
	// KindPromQL is a PromQL expression. It is length-bounded and screened for
	// control characters, but deliberately not parsed: see the package docs of
	// internal/promproxy for why upstream is our validator.
	KindPromQL ParamKind = iota
	// KindTime is an RFC 3339 timestamp or a Unix timestamp with optional
	// fractional seconds.
	KindTime
	// KindDuration is a Prometheus duration such as "5m" or "1h30m", or a
	// number of seconds.
	KindDuration
	// KindMatcher is a PromQL series selector such as `up{job="api"}`.
	KindMatcher
	// KindLabelName is a label name.
	KindLabelName
	// KindMetricName is a metric name.
	KindMetricName
	// KindInt is a non-negative integer.
	KindInt
	// KindEnum is one of Param.Enum.
	KindEnum
)

// Param describes one accepted query parameter.
type Param struct {
	// Name is the wire name of the parameter.
	Name string
	// Kind selects the validation rule.
	Kind ParamKind
	// Required fails validation when the parameter is absent.
	Required bool
	// Repeated permits the parameter to appear more than once.
	Repeated bool
	// Enum lists the permitted values when Kind is KindEnum.
	Enum []string
}

// Route is one allow-listed upstream call.
type Route struct {
	// Endpoint is the stable identifier used in tool code and metrics.
	Endpoint Endpoint
	// Method is the HTTP method used upstream. POST is preferred wherever
	// Prometheus accepts it so that long PromQL never meets a proxy's URI
	// length limit.
	Method string
	// PathTemplate is the upstream path. It contains at most one placeholder,
	// "{label}", which is substituted with a validated label name.
	PathTemplate string
	// Params is the closed set of accepted parameters.
	Params []Param
	// Gated marks a route that is refused unless the operator explicitly
	// enables it.
	Gated bool
	// Summary is a one-line description used in generated documentation.
	Summary string
}

// HasPathParam reports whether the route's path contains the {label}
// placeholder.
func (r Route) HasPathParam() bool { return strings.Contains(r.PathTemplate, "{label}") }

// commonSelectorParams are the matcher/time parameters shared by the metadata
// oriented endpoints.
var commonSelectorParams = []Param{
	{Name: "match[]", Kind: KindMatcher, Repeated: true},
	{Name: "start", Kind: KindTime},
	{Name: "end", Kind: KindTime},
	{Name: "limit", Kind: KindInt},
}

// routes is the complete allow-list. It is the single source of truth for what
// this project can ask a Prometheus server to do.
var routes = map[Endpoint]Route{
	EndpointQuery: {
		Endpoint: EndpointQuery, Method: "POST", PathTemplate: "/api/v1/query",
		Summary: "Evaluate a PromQL expression at a single instant.",
		Params: []Param{
			{Name: "query", Kind: KindPromQL, Required: true},
			{Name: "time", Kind: KindTime},
			{Name: "timeout", Kind: KindDuration},
			{Name: "limit", Kind: KindInt},
		},
	},
	EndpointQueryRange: {
		Endpoint: EndpointQueryRange, Method: "POST", PathTemplate: "/api/v1/query_range",
		Summary: "Evaluate a PromQL expression over a time range.",
		Params: []Param{
			{Name: "query", Kind: KindPromQL, Required: true},
			{Name: "start", Kind: KindTime, Required: true},
			{Name: "end", Kind: KindTime, Required: true},
			{Name: "step", Kind: KindDuration, Required: true},
			{Name: "timeout", Kind: KindDuration},
			{Name: "limit", Kind: KindInt},
		},
	},
	EndpointSeries: {
		Endpoint: EndpointSeries, Method: "POST", PathTemplate: "/api/v1/series",
		Summary: "List label sets matching a set of series selectors.",
		Params: []Param{
			{Name: "match[]", Kind: KindMatcher, Required: true, Repeated: true},
			{Name: "start", Kind: KindTime},
			{Name: "end", Kind: KindTime},
			{Name: "limit", Kind: KindInt},
		},
	},
	EndpointLabels: {
		Endpoint: EndpointLabels, Method: "POST", PathTemplate: "/api/v1/labels",
		Summary: "List label names present in the selected series.",
		Params:  commonSelectorParams,
	},
	EndpointLabelValues: {
		Endpoint: EndpointLabelValues, Method: "GET",
		PathTemplate: "/api/v1/label/{label}/values",
		Summary:      "List the values of one label.",
		Params:       commonSelectorParams,
	},
	EndpointMetadata: {
		Endpoint: EndpointMetadata, Method: "GET", PathTemplate: "/api/v1/metadata",
		Summary: "Return metric type, help text and unit.",
		Params: []Param{
			{Name: "metric", Kind: KindMetricName},
			{Name: "limit", Kind: KindInt},
			{Name: "limit_per_metric", Kind: KindInt},
		},
	},
	EndpointTargets: {
		Endpoint: EndpointTargets, Method: "GET", PathTemplate: "/api/v1/targets",
		Summary: "Report scrape target health. Responses must be redacted before reaching an agent.",
		Params: []Param{
			{Name: "state", Kind: KindEnum, Enum: []string{"active", "dropped", "any"}},
			{Name: "scrapePool", Kind: KindLabelName},
		},
	},
	EndpointRules: {
		Endpoint: EndpointRules, Method: "GET", PathTemplate: "/api/v1/rules",
		Summary: "Return recording and alerting rule groups.",
		Params: []Param{
			{Name: "type", Kind: KindEnum, Enum: []string{"alert", "record"}},
			{Name: "rule_name[]", Kind: KindMetricName, Repeated: true},
			{Name: "rule_group[]", Kind: KindMetricName, Repeated: true},
			{Name: "file[]", Kind: KindMetricName, Repeated: true},
			{Name: "exclude_alerts", Kind: KindEnum, Enum: []string{"true", "false"}},
		},
	},
	EndpointAlerts: {
		Endpoint: EndpointAlerts, Method: "GET", PathTemplate: "/api/v1/alerts",
		Summary: "Return currently active alerts.",
	},
	EndpointAlertmanagers: {
		Endpoint: EndpointAlertmanagers, Method: "GET", PathTemplate: "/api/v1/alertmanagers",
		Summary: "Report the configured Alertmanager peers.",
	},
	EndpointTSDBStatus: {
		Endpoint: EndpointTSDBStatus, Method: "GET", PathTemplate: "/api/v1/status/tsdb",
		Summary: "Return head-block cardinality statistics.",
		Params:  []Param{{Name: "limit", Kind: KindInt}},
	},
	EndpointRuntimeInfo: {
		Endpoint: EndpointRuntimeInfo, Method: "GET", PathTemplate: "/api/v1/status/runtimeinfo",
		Summary: "Return process runtime state.",
	},
	EndpointBuildInfo: {
		Endpoint: EndpointBuildInfo, Method: "GET", PathTemplate: "/api/v1/status/buildinfo",
		Summary: "Return server version and revision.",
	},
	EndpointFlags: {
		Endpoint: EndpointFlags, Method: "GET", PathTemplate: "/api/v1/status/flags",
		Summary: "Return the server's command-line flags.",
	},
	EndpointConfig: {
		Endpoint: EndpointConfig, Method: "GET", PathTemplate: "/api/v1/status/config",
		Gated:   true,
		Summary: "Return the full scrape configuration. Gated: scrape configs commonly embed credentials.",
	},
}

// Endpoints returns every endpoint in the allow-list, in a stable order.
func Endpoints() []Endpoint {
	out := make([]Endpoint, 0, len(routes))
	for e := range routes {
		out = append(out, e)
	}
	slices.Sort(out)
	return out
}

// Get returns the route for an endpoint.
func Get(e Endpoint) (Route, error) {
	r, ok := routes[e]
	if !ok {
		return Route{}, fmt.Errorf("%w: %q", ErrUnknownEndpoint, e)
	}
	return r, nil
}

// labelNameRE is the Prometheus label name grammar. Because the label name is
// the only user-influenced component of any path we ever build, this is a
// security boundary and not merely a validation nicety.
var labelNameRE = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

// metricNameRE is the Prometheus metric name grammar. It additionally permits
// ':' which recording rules use.
var metricNameRE = regexp.MustCompile(`^[a-zA-Z_:][a-zA-Z0-9_:]*$`)

// MaxLabelNameBytes bounds the label name, which is the only user-influenced
// component of any path this package builds. Prometheus itself imposes no such
// limit, but an unbounded path segment is a needless amplification vector and
// no real label name approaches this.
const MaxLabelNameBytes = 128

// ValidateLabelName reports whether name is a syntactically valid, bounded
// label name that is safe to place in a URL path.
func ValidateLabelName(name string) error {
	if len(name) > MaxLabelNameBytes {
		return fmt.Errorf("%w: %d bytes, limit %d", ErrInvalidLabelName, len(name), MaxLabelNameBytes)
	}
	if !labelNameRE.MatchString(name) {
		return fmt.Errorf("%w: %q", ErrInvalidLabelName, name)
	}
	return nil
}

// Size limits. These bound the request we are willing to construct; they are
// not a substitute for the upstream server's own limits.
const (
	// MaxPromQLBytes bounds a single PromQL expression.
	MaxPromQLBytes = 8192
	// MaxParamBytes bounds any other single parameter value.
	MaxParamBytes = 2048
	// MaxRepeatedParams bounds how many times a repeated parameter may appear.
	MaxRepeatedParams = 64
)

// BuildPath renders a route's path. labelName is used only by
// [EndpointLabelValues] and must be empty for every other endpoint.
func BuildPath(e Endpoint, labelName string) (string, error) {
	r, err := Get(e)
	if err != nil {
		return "", err
	}
	if !r.HasPathParam() {
		if labelName != "" {
			return "", fmt.Errorf("%w: endpoint %q takes no label name", ErrInvalidParam, e)
		}
		return r.PathTemplate, nil
	}
	if err := ValidateLabelName(labelName); err != nil {
		return "", err
	}
	// labelName has already been constrained to [a-zA-Z0-9_], so PathEscape is
	// belt-and-braces rather than the control.
	return strings.Replace(r.PathTemplate, "{label}", url.PathEscape(labelName), 1), nil
}

// Validate checks form against the route's parameter table. It rejects unknown
// parameters outright rather than dropping them, so that a caller which
// misspells a parameter learns about it instead of silently getting an
// unfiltered query.
func Validate(e Endpoint, form url.Values, gatedEnabled bool) error {
	r, err := Get(e)
	if err != nil {
		return err
	}
	if r.Gated && !gatedEnabled {
		return fmt.Errorf("%w: %q", ErrEndpointGated, e)
	}
	byName := make(map[string]Param, len(r.Params))
	for _, p := range r.Params {
		byName[p.Name] = p
	}
	for name, values := range form {
		p, ok := byName[name]
		if !ok {
			return fmt.Errorf("%w: %q is not accepted by endpoint %q", ErrInvalidParam, name, e)
		}
		if !p.Repeated && len(values) > 1 {
			return fmt.Errorf("%w: %q may appear only once", ErrInvalidParam, name)
		}
		if len(values) > MaxRepeatedParams {
			return fmt.Errorf("%w: %q repeated %d times, limit %d",
				ErrInvalidParam, name, len(values), MaxRepeatedParams)
		}
		for _, v := range values {
			if err := validateValue(p, v); err != nil {
				return fmt.Errorf("%w: %q: %s", ErrInvalidParam, name, err)
			}
		}
	}
	for _, p := range r.Params {
		if p.Required && len(form[p.Name]) == 0 {
			return fmt.Errorf("%w: %q is required by endpoint %q", ErrInvalidParam, p.Name, e)
		}
	}
	return nil
}

// validateValue applies the kind-specific rule to a single value.
func validateValue(p Param, v string) error {
	limit := MaxParamBytes
	if p.Kind == KindPromQL {
		limit = MaxPromQLBytes
	}
	if len(v) > limit {
		return fmt.Errorf("value is %d bytes, limit %d", len(v), limit)
	}
	if i := strings.IndexFunc(v, isForbiddenRune); i >= 0 {
		return fmt.Errorf("contains a control character at byte %d", i)
	}
	switch p.Kind {
	case KindPromQL, KindMatcher:
		if strings.TrimSpace(v) == "" {
			return errors.New("must not be empty")
		}
	case KindTime:
		return validateTime(v)
	case KindDuration:
		return validateDuration(v)
	case KindLabelName:
		if !labelNameRE.MatchString(v) {
			return errors.New("is not a valid label name")
		}
	case KindMetricName:
		if !metricNameRE.MatchString(v) {
			return errors.New("is not a valid metric or rule name")
		}
	case KindInt:
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 0 {
			return errors.New("must be a non-negative integer")
		}
	case KindEnum:
		if !slices.Contains(p.Enum, v) {
			return fmt.Errorf("must be one of %s", strings.Join(p.Enum, ", "))
		}
	}
	return nil
}

// isForbiddenRune reports whether r must never appear in a parameter value.
// C0 and C1 control characters are excluded because they have no legitimate
// use here and are the raw material for log injection and terminal escapes.
func isForbiddenRune(r rune) bool {
	return r < 0x20 || (r >= 0x7f && r <= 0x9f)
}

// validateTime accepts an RFC 3339 timestamp or a Unix timestamp with optional
// fractional seconds, matching what the Prometheus API accepts.
func validateTime(v string) error {
	if _, err := time.Parse(time.RFC3339, v); err == nil {
		return nil
	}
	if _, err := strconv.ParseFloat(v, 64); err == nil {
		return nil
	}
	return errors.New("must be an RFC 3339 timestamp or a Unix timestamp")
}

// promDurationRE matches the Prometheus duration grammar, e.g. "1h30m", "5m",
// "500ms", "1w".
var promDurationRE = regexp.MustCompile(`^(([0-9]+)y)?(([0-9]+)w)?(([0-9]+)d)?(([0-9]+)h)?(([0-9]+)m)?(([0-9]+)s)?(([0-9]+)ms)?$`)

// validateDuration accepts a Prometheus duration or a plain number of seconds.
func validateDuration(v string) error {
	if v == "" {
		return errors.New("must not be empty")
	}
	if n, err := strconv.ParseFloat(v, 64); err == nil {
		if n <= 0 {
			return errors.New("must be positive")
		}
		return nil
	}
	if promDurationRE.MatchString(v) {
		return nil
	}
	return errors.New(`must be a duration such as "5m" or a number of seconds`)
}

// Lookup resolves a concrete request path back to its route. The spoke uses it
// to re-validate what the hub sent: a path that does not resolve here is
// refused regardless of what the hub claimed. Returned labelName is the
// captured path parameter, if any.
func Lookup(method, path string) (r Route, labelName string, ok bool) {
	// Reject relative, doubled and escaped components before matching.
	//
	// Percent-encoding is refused outright rather than decoded. Every path this
	// package can legitimately build consists of ASCII letters, digits, '_' and
	// '/', so a '%' can only ever be an attempt to make two different request
	// strings resolve to the same route. Decoding first and validating after is
	// how filter bypasses happen; requiring the canonical form means the
	// spoke's re-validation is byte-equivalent to the hub's construction, which
	// is the property Lookup exists to provide.
	if path == "" || path[0] != '/' || strings.Contains(path, "..") ||
		strings.Contains(path, "//") || strings.ContainsAny(path, "\\\x00%") {
		return Route{}, "", false
	}
	for _, route := range routes {
		if !strings.EqualFold(route.Method, method) {
			continue
		}
		if !route.HasPathParam() {
			if route.PathTemplate == path {
				return route, "", true
			}
			continue
		}
		prefix, suffix, _ := strings.Cut(route.PathTemplate, "{label}")
		// len(path) must exceed prefix+suffix, or the two would overlap and the
		// slice below would be inverted. "/api/v1/label/values" is exactly that
		// case: it satisfies both HasPrefix and HasSuffix while leaving no room
		// for a label segment.
		if len(path) <= len(prefix)+len(suffix) ||
			!strings.HasPrefix(path, prefix) || !strings.HasSuffix(path, suffix) {
			continue
		}
		mid := path[len(prefix) : len(path)-len(suffix)]
		if ValidateLabelName(mid) != nil {
			continue
		}
		return route, mid, true
	}
	return Route{}, "", false
}
