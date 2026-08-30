// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package render

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
)

// ErrMalformedUpstream reports a response body that is not the Prometheus API
// envelope. It is distinct from an upstream error status: a 400 carrying a
// PromQL parse message is a well-formed response this package decodes happily.
var ErrMalformedUpstream = errors.New("render: malformed Prometheus response")

// APIResponse is the Prometheus HTTP API envelope. Data is left raw because
// its shape depends on the endpoint and, for format "json", the hub passes it
// through without ever parsing it.
type APIResponse struct {
	// Status is "success" or "error".
	Status string `json:"status"`
	// Data is the endpoint-specific payload.
	Data json.RawMessage `json:"data,omitempty"`
	// ErrorType is Prometheus' machine-readable error class, for example
	// "bad_data" or "execution".
	ErrorType string `json:"errorType,omitempty"`
	// Error is Prometheus' own message. It is passed through to the agent
	// because Prometheus is this project's PromQL validator: see
	// docs/adr/0006-no-promql-parsing-in-process.md.
	Error string `json:"error,omitempty"`
	// Warnings are non-fatal notes from the query engine.
	Warnings []string `json:"warnings,omitempty"`
	// Infos are informational notes from newer Prometheus releases.
	Infos []string `json:"infos,omitempty"`
}

// Failed reports whether the envelope carries an error rather than data.
func (r *APIResponse) Failed() bool { return r == nil || r.Status != "success" }

// DecodeAPIResponse parses the Prometheus API envelope.
func DecodeAPIResponse(body []byte) (*APIResponse, error) {
	if len(body) == 0 {
		return nil, fmt.Errorf("%w: empty body", ErrMalformedUpstream)
	}
	var r APIResponse
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformedUpstream, err)
	}
	if r.Status == "" {
		return nil, fmt.Errorf("%w: no status field", ErrMalformedUpstream)
	}
	return &r, nil
}

// QueryData is the payload of /api/v1/query and /api/v1/query_range.
type QueryData struct {
	// ResultType is "matrix", "vector", "scalar" or "string".
	ResultType string `json:"resultType"`
	// Result is the type-specific body.
	Result json.RawMessage `json:"result"`
	// Stats is the optional query statistics block.
	Stats json.RawMessage `json:"stats,omitempty"`
}

// DecodeQueryData parses the data member of a query response.
func DecodeQueryData(data json.RawMessage) (*QueryData, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("%w: query response has no data", ErrMalformedUpstream)
	}
	var q QueryData
	if err := json.Unmarshal(data, &q); err != nil {
		return nil, fmt.Errorf("%w: query data: %w", ErrMalformedUpstream, err)
	}
	return &q, nil
}

// Point is one sample. Prometheus encodes it as [unixSeconds, "value"], with
// the value a string so that NaN and ±Inf survive JSON.
type Point struct {
	// T is the sample timestamp in Unix seconds, possibly fractional.
	T float64
	// V is the sample value. NaN is used for Prometheus' own "NaN".
	V float64
}

// UnmarshalJSON implements json.Unmarshaler for the [ts, "value"] pair form.
func (p *Point) UnmarshalJSON(b []byte) error {
	var raw []json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return fmt.Errorf("%w: sample: %w", ErrMalformedUpstream, err)
	}
	if len(raw) < 2 {
		return fmt.Errorf("%w: sample has %d members, want 2", ErrMalformedUpstream, len(raw))
	}
	if err := json.Unmarshal(raw[0], &p.T); err != nil {
		return fmt.Errorf("%w: sample timestamp: %w", ErrMalformedUpstream, err)
	}
	var s string
	if err := json.Unmarshal(raw[1], &s); err != nil {
		// Some Prometheus-compatible servers emit a bare number.
		if err2 := json.Unmarshal(raw[1], &p.V); err2 != nil {
			return fmt.Errorf("%w: sample value: %w", ErrMalformedUpstream, err)
		}
		return nil
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return fmt.Errorf("%w: sample value %q: %w", ErrMalformedUpstream, s, err)
	}
	p.V = v
	return nil
}

// MarshalJSON implements json.Marshaler, reproducing the upstream pair form.
func (p Point) MarshalJSON() ([]byte, error) {
	return json.Marshal([]any{p.T, strconv.FormatFloat(p.V, 'f', -1, 64)})
}

// SeriesStream is one matrix series: a label set and its samples.
type SeriesStream struct {
	// Metric is the label set, including __name__ when present.
	Metric map[string]string `json:"metric"`
	// Values are the samples, ordered by timestamp.
	Values []Point `json:"values"`
}

// Matrix is the result of a range query.
type Matrix []SeriesStream

// DecodeMatrix parses a matrix result body.
func DecodeMatrix(result json.RawMessage) (Matrix, error) {
	if len(result) == 0 {
		return nil, nil
	}
	var m Matrix
	if err := json.Unmarshal(result, &m); err != nil {
		return nil, fmt.Errorf("%w: matrix: %w", ErrMalformedUpstream, err)
	}
	return m, nil
}

// VectorSample is one instant-vector element.
type VectorSample struct {
	// Metric is the label set, including __name__ when present.
	Metric map[string]string `json:"metric"`
	// Value is the single sample.
	Value Point `json:"value"`
}

// Vector is the result of an instant query.
type Vector []VectorSample

// DecodeVector parses a vector result body.
func DecodeVector(result json.RawMessage) (Vector, error) {
	if len(result) == 0 {
		return nil, nil
	}
	var v Vector
	if err := json.Unmarshal(result, &v); err != nil {
		return nil, fmt.Errorf("%w: vector: %w", ErrMalformedUpstream, err)
	}
	return v, nil
}

// DecodeScalar parses a scalar result body, which is a single [ts, "value"]
// pair.
func DecodeScalar(result json.RawMessage) (Point, error) {
	var p Point
	if len(result) == 0 {
		return p, fmt.Errorf("%w: scalar has no value", ErrMalformedUpstream)
	}
	if err := json.Unmarshal(result, &p); err != nil {
		return p, err
	}
	return p, nil
}

// jsonNumber renders a float for a compact result. NaN and infinities have no
// JSON representation, so they become null — the same encoding as a gap, which
// is what they mean to a consumer plotting or aggregating the series.
func jsonNumber(v float64) *float64 {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return nil
	}
	// Round to a stable, short representation. Prometheus values routinely
	// carry seventeen significant digits of float noise, and every one of them
	// costs a token for information no agent can use.
	return &v
}
