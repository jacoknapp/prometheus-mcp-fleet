// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package promclient

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/promapi"
)

// Sample is one element of an instant-query result: a label set and its value.
type Sample struct {
	// Labels is the sample's label set, including __name__ when present.
	Labels map[string]string
	// Value is the sample value. NaN and infinities are preserved as returned
	// by Prometheus.
	Value float64
}

// Vector is the result of an instant query.
type Vector []Sample

// GetJSON performs one allow-listed call and decodes the response body into
// out.
//
// It is a convenience for in-process callers such as internal/clusterfacts and
// is not reachable from the tunnel: the hub's traffic always goes through
// [Client.Do], which streams instead of decoding. The route's own HTTP method
// is used, so an endpoint declared POST in [promapi] is still POSTed here.
//
// Endpoints with a path parameter are refused; use [Client.LabelValues].
func (c *Client) GetJSON(ctx context.Context, e promapi.Endpoint, form url.Values, out any) error {
	_, err := c.GetJSONHeaders(ctx, e, form, out)
	return err
}

// GetJSONHeaders behaves like [Client.GetJSON] and additionally returns the
// upstream response headers. The facts collector uses the Server header as one
// input to flavor detection.
func (c *Client) GetJSONHeaders(ctx context.Context, e promapi.Endpoint, form url.Values, out any) (http.Header, error) {
	route, err := promapi.Get(e)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNotAllowed, err)
	}
	if route.HasPathParam() {
		return nil, fmt.Errorf("%w: endpoint %q takes a path parameter, use LabelValues", ErrNotAllowed, e)
	}
	if form == nil {
		form = url.Values{}
	}
	if err := promapi.Validate(e, form, c.allowStatusConfig); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNotAllowed, err)
	}
	return c.fetch(ctx, route, "", form, out)
}

// LabelValues returns the distinct values of one label, the equivalent of
// PromQL's label_values(). It exists as its own method because
// [promapi.EndpointLabelValues] carries the label name in the path rather than
// in the form, and the path is the one component this project refuses to let a
// caller assemble.
func (c *Client) LabelValues(ctx context.Context, label string) ([]string, error) {
	if err := promapi.ValidateLabelName(label); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNotAllowed, err)
	}
	route, _ := promapi.Get(promapi.EndpointLabelValues)
	var env struct {
		envelope
		Data []string `json:"data"`
	}
	if _, err := c.fetch(ctx, route, label, url.Values{}, &env); err != nil {
		return nil, err
	}
	if err := env.err(string(route.Endpoint)); err != nil {
		return nil, err
	}
	return env.Data, nil
}

// InstantQuery evaluates expr at the current server time and returns the
// resulting vector. A scalar result is returned as a single unlabelled sample;
// a matrix result is refused, because a caller that wants a range should use
// the range endpoint rather than silently collapsing one.
//
// It is a small typed helper for facts collection and is not reachable from
// the tunnel.
func (c *Client) InstantQuery(ctx context.Context, expr string) (Vector, error) {
	form := url.Values{"query": []string{expr}}
	var env struct {
		envelope
		Data struct {
			ResultType string          `json:"resultType"`
			Result     json.RawMessage `json:"result"`
		} `json:"data"`
	}
	if err := c.GetJSON(ctx, promapi.EndpointQuery, form, &env); err != nil {
		return nil, err
	}
	if err := env.err("query"); err != nil {
		return nil, err
	}
	switch env.Data.ResultType {
	case "vector":
		var raw []struct {
			Metric map[string]string `json:"metric"`
			Value  [2]json.RawMessage
		}
		if err := json.Unmarshal(env.Data.Result, &raw); err != nil {
			return nil, fmt.Errorf("%w: decode vector: %w", ErrUpstream, err)
		}
		out := make(Vector, 0, len(raw))
		for _, r := range raw {
			v, err := decodeSampleValue(r.Value[1])
			if err != nil {
				return nil, err
			}
			out = append(out, Sample{Labels: r.Metric, Value: v})
		}
		return out, nil
	case "scalar":
		var raw [2]json.RawMessage
		if err := json.Unmarshal(env.Data.Result, &raw); err != nil {
			return nil, fmt.Errorf("%w: decode scalar: %w", ErrUpstream, err)
		}
		v, err := decodeSampleValue(raw[1])
		if err != nil {
			return nil, err
		}
		return Vector{{Labels: map[string]string{}, Value: v}}, nil
	default:
		return nil, fmt.Errorf("%w: resultType %q is not an instant vector", ErrUpstream, env.Data.ResultType)
	}
}

// decodeSampleValue parses the string-encoded second element of a Prometheus
// sample pair.
func decodeSampleValue(raw json.RawMessage) (float64, error) {
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return 0, fmt.Errorf("%w: sample value is not a string: %w", ErrUpstream, err)
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, fmt.Errorf("%w: sample value %q: %w", ErrUpstream, s, err)
	}
	if math.IsNaN(v) {
		return math.NaN(), nil
	}
	return v, nil
}

// envelope is the status part of every Prometheus API reply. Embedding it lets
// each helper declare only the "data" shape it cares about.
type envelope struct {
	Status    string `json:"status"`
	ErrorType string `json:"errorType"`
	Error     string `json:"error"`
}

// err converts an error envelope into a Go error.
func (e envelope) err(what string) error {
	if e.Status == "" || e.Status == "success" {
		return nil
	}
	return fmt.Errorf("%w: %s: %s: %s", ErrUpstream, what, e.ErrorType, e.Error)
}

// fetch performs the call and decodes the body. It applies the same deadline
// budgeting and byte capping as the streaming path, with a tighter cap because
// the body is materialised in memory.
func (c *Client) fetch(ctx context.Context, route promapi.Route, labelName string, form url.Values, out any) (http.Header, error) {
	resp, _, cancel, err := c.roundTrip(ctx, route, labelName, form, false, "")
	if err != nil {
		return nil, err
	}
	defer cancel()
	defer func() { _ = resp.Body.Close() }()

	limit := int64(maxJSONHelperBytes)
	if c.maxResponseBytes < limit {
		limit = c.maxResponseBytes
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return resp.Header, fmt.Errorf("%w: %s: read body: %w", ErrUpstream, route.Endpoint, err)
	}
	if int64(len(body)) > limit {
		return resp.Header, fmt.Errorf("%w: %s: %w", ErrUpstream, route.Endpoint, ErrTooLarge)
	}
	if resp.StatusCode/100 != 2 {
		return resp.Header, fmt.Errorf("%w: %s: status %d: %s",
			ErrUpstream, route.Endpoint, resp.StatusCode, snippet(body))
	}
	if out == nil {
		return resp.Header, nil
	}
	if err := json.Unmarshal(body, out); err != nil {
		return resp.Header, fmt.Errorf("%w: %s: decode body: %w", ErrUpstream, route.Endpoint, err)
	}
	return resp.Header, nil
}

// snippet clips an upstream error body to something safe to place in an error
// string: bounded in length and free of control characters.
func snippet(body []byte) string {
	const max = 256
	s := string(body)
	if len(s) > max {
		s = s[:max] + "...[clipped]"
	}
	return strings.Map(func(r rune) rune {
		if r < 0x20 || (r >= 0x7f && r <= 0x9f) {
			return ' '
		}
		return r
	}, s)
}
