// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package render

import (
	"encoding/json"
	"errors"
	"math"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

// TestDecodeAPIResponse covers the Prometheus envelope, including the error
// envelope this package decodes happily: a 400 carrying a PromQL parse message
// is a well-formed response, not a malformed one.
func TestDecodeAPIResponse(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		body       string
		want       *APIResponse
		wantFailed bool
		wantErr    bool
	}{
		{
			name: "a success envelope",
			body: `{"status":"success","data":{"resultType":"vector","result":[]},` +
				`"warnings":["a warning"],"infos":["an info"]}`,
			want: &APIResponse{
				Status:   "success",
				Data:     json.RawMessage(`{"resultType":"vector","result":[]}`),
				Warnings: []string{"a warning"},
				Infos:    []string{"an info"},
			},
		},
		{
			name: "an error envelope decodes rather than failing",
			body: `{"status":"error","errorType":"bad_data","error":"parse error at char 3"}`,
			want: &APIResponse{
				Status:    "error",
				ErrorType: "bad_data",
				Error:     "parse error at char 3",
			},
			wantFailed: true,
		},
		{name: "an empty body", body: "", wantErr: true},
		{name: "not JSON at all", body: "<html>502</html>", wantErr: true},
		{name: "JSON with no status field", body: `{"data":{}}`, wantErr: true},
		{name: "a JSON array", body: `[1,2,3]`, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := DecodeAPIResponse([]byte(tc.body))
			if tc.wantErr {
				if !errors.Is(err, ErrMalformedUpstream) {
					t.Fatalf("err = %v, want ErrMalformedUpstream", err)
				}
				if got != nil {
					t.Errorf("a failed decode returned %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("DecodeAPIResponse: %v", err)
			}
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("envelope (-want +got):\n%s", diff)
			}
			if got.Failed() != tc.wantFailed {
				t.Errorf("Failed() = %v, want %v", got.Failed(), tc.wantFailed)
			}
		})
	}

	// A nil envelope is a failure, so a caller that forgot to check the decode
	// error still cannot mistake it for data.
	var nilResp *APIResponse
	if !nilResp.Failed() {
		t.Error("(*APIResponse)(nil).Failed() = false")
	}
}

// TestDecodeQueryData covers the data member of a query response.
func TestDecodeQueryData(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		data    string
		want    *QueryData
		wantErr bool
	}{
		{
			name: "a matrix payload",
			data: `{"resultType":"matrix","result":[],"stats":{"timings":{}}}`,
			want: &QueryData{
				ResultType: "matrix",
				Result:     json.RawMessage(`[]`),
				Stats:      json.RawMessage(`{"timings":{}}`),
			},
		},
		{
			name: "no stats block",
			data: `{"resultType":"vector","result":[]}`,
			want: &QueryData{ResultType: "vector", Result: json.RawMessage(`[]`)},
		},
		{name: "absent data", data: "", wantErr: true},
		{name: "not an object", data: `"scalar"`, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := DecodeQueryData(json.RawMessage(tc.data))
			if tc.wantErr {
				if !errors.Is(err, ErrMalformedUpstream) {
					t.Fatalf("err = %v, want ErrMalformedUpstream", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("DecodeQueryData: %v", err)
			}
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("query data (-want +got):\n%s", diff)
			}
		})
	}
}

// TestPointUnmarshalJSON covers the [ts, "value"] pair form, including the
// bare-number variant some Prometheus-compatible servers emit and the string
// specials that only exist because Prometheus encodes values as strings.
func TestPointUnmarshalJSON(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		in      string
		wantT   float64
		wantV   float64
		wantNaN bool
		wantInf int
		wantErr bool
	}{
		{name: "the ordinary pair", in: `[1756400000,"0.4321"]`, wantT: 1756400000, wantV: 0.4321},
		{name: "a fractional timestamp", in: `[1756400000.5,"1"]`, wantT: 1756400000.5, wantV: 1},
		{name: "a negative value", in: `[1,"-2.5"]`, wantT: 1, wantV: -2.5},
		{name: "scientific notation", in: `[1,"1.5e3"]`, wantT: 1, wantV: 1500},
		{name: "NaN survives because the value is a string", in: `[1,"NaN"]`, wantT: 1, wantNaN: true},
		{name: "positive infinity", in: `[1,"+Inf"]`, wantT: 1, wantInf: 1},
		{name: "negative infinity", in: `[1,"-Inf"]`, wantT: 1, wantInf: -1},
		{name: "a bare number from a compatible server", in: `[1,2.5]`, wantT: 1, wantV: 2.5},
		{name: "not an array", in: `{"t":1}`, wantErr: true},
		{name: "too few members", in: `[1]`, wantErr: true},
		{name: "an empty array", in: `[]`, wantErr: true},
		{name: "a non-numeric timestamp", in: `["soon","1"]`, wantErr: true},
		{name: "a value that is neither string nor number", in: `[1,{"v":1}]`, wantErr: true},
		{name: "a string that is not a float", in: `[1,"twelve"]`, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var p Point
			err := json.Unmarshal([]byte(tc.in), &p)
			if tc.wantErr {
				if !errors.Is(err, ErrMalformedUpstream) {
					t.Fatalf("err = %v, want ErrMalformedUpstream", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unmarshal %s: %v", tc.in, err)
			}
			if p.T != tc.wantT {
				t.Errorf("T = %v, want %v", p.T, tc.wantT)
			}
			switch {
			case tc.wantNaN:
				if !math.IsNaN(p.V) {
					t.Errorf("V = %v, want NaN", p.V)
				}
			case tc.wantInf != 0:
				if !math.IsInf(p.V, tc.wantInf) {
					t.Errorf("V = %v, want %+d infinity", p.V, tc.wantInf)
				}
			default:
				if p.V != tc.wantV {
					t.Errorf("V = %v, want %v", p.V, tc.wantV)
				}
			}
		})
	}
}

// TestPointMarshalJSON covers the round trip back to the upstream pair form,
// which is what format "json" passes through.
func TestPointMarshalJSON(t *testing.T) {
	t.Parallel()
	for _, in := range []string{
		`[1756400000,"0.4321"]`, `[1,"-2.5"]`, `[1.5,"0"]`,
	} {
		var p Point
		if err := json.Unmarshal([]byte(in), &p); err != nil {
			t.Fatalf("unmarshal %s: %v", in, err)
		}
		out, err := json.Marshal(p)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if string(out) != in {
			t.Errorf("round trip of %s gave %s", in, out)
		}
	}
}

// TestDecodeMatrix covers a range result body.
func TestDecodeMatrix(t *testing.T) {
	t.Parallel()
	got, err := DecodeMatrix(json.RawMessage(
		`[{"metric":{"__name__":"up","job":"api"},"values":[[1,"1"],[2,"0"]]},` +
			`{"metric":{},"values":[]}]`))
	if err != nil {
		t.Fatalf("DecodeMatrix: %v", err)
	}
	want := Matrix{
		{
			Metric: map[string]string{"__name__": "up", "job": "api"},
			Values: []Point{{T: 1, V: 1}, {T: 2, V: 0}},
		},
		{Metric: map[string]string{}, Values: []Point{}},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("matrix (-want +got):\n%s", diff)
	}

	empty, err := DecodeMatrix(nil)
	if err != nil || empty != nil {
		t.Errorf("DecodeMatrix(nil) = %v, %v; want nil, nil", empty, err)
	}
	if _, err := DecodeMatrix(json.RawMessage(`{"not":"a matrix"}`)); !errors.Is(
		err, ErrMalformedUpstream) {
		t.Errorf("err = %v, want ErrMalformedUpstream", err)
	}
	// A malformed sample inside a well-formed matrix still fails loudly.
	if _, err := DecodeMatrix(json.RawMessage(
		`[{"metric":{},"values":[[1]]}]`)); !errors.Is(err, ErrMalformedUpstream) {
		t.Errorf("err = %v, want ErrMalformedUpstream", err)
	}
}

// TestDecodeVector covers an instant result body.
func TestDecodeVector(t *testing.T) {
	t.Parallel()
	got, err := DecodeVector(json.RawMessage(
		`[{"metric":{"__name__":"up"},"value":[1756400000,"1"]}]`))
	if err != nil {
		t.Fatalf("DecodeVector: %v", err)
	}
	want := Vector{{
		Metric: map[string]string{"__name__": "up"},
		Value:  Point{T: 1756400000, V: 1},
	}}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("vector (-want +got):\n%s", diff)
	}

	empty, err := DecodeVector(nil)
	if err != nil || empty != nil {
		t.Errorf("DecodeVector(nil) = %v, %v; want nil, nil", empty, err)
	}
	if _, err := DecodeVector(json.RawMessage(`"nope"`)); !errors.Is(
		err, ErrMalformedUpstream) {
		t.Errorf("err = %v, want ErrMalformedUpstream", err)
	}
}

// TestDecodeScalar covers the single-pair scalar body.
func TestDecodeScalar(t *testing.T) {
	t.Parallel()
	got, err := DecodeScalar(json.RawMessage(`[1756400000,"42"]`))
	if err != nil {
		t.Fatalf("DecodeScalar: %v", err)
	}
	if diff := cmp.Diff(Point{T: 1756400000, V: 42}, got,
		cmpopts.EquateApprox(0, 1e-9)); diff != "" {
		t.Errorf("scalar (-want +got):\n%s", diff)
	}

	if _, err := DecodeScalar(nil); !errors.Is(err, ErrMalformedUpstream) {
		t.Errorf("err = %v, want ErrMalformedUpstream", err)
	}
	if _, err := DecodeScalar(json.RawMessage(`[1]`)); !errors.Is(
		err, ErrMalformedUpstream) {
		t.Errorf("err = %v, want ErrMalformedUpstream", err)
	}
}

// TestJSONNumber covers the value encoder. NaN and the infinities have no JSON
// representation, so they become null, which is the same encoding as a gap and
// means the same thing to anything plotting or aggregating the series.
func TestJSONNumber(t *testing.T) {
	t.Parallel()
	for _, v := range []float64{math.NaN(), math.Inf(1), math.Inf(-1)} {
		if got := jsonNumber(v); got != nil {
			t.Errorf("jsonNumber(%v) = %v, want nil", v, *got)
		}
	}
	for _, v := range []float64{0, -1, 1e300, 1e-300} {
		got := jsonNumber(v)
		if got == nil || *got != v {
			t.Errorf("jsonNumber(%v) = %v", v, got)
		}
	}
}

// TestDecodeChainFromARealEnvelope walks a whole upstream body the way the
// hub does, which is the only place the decoders are used together.
func TestDecodeChainFromARealEnvelope(t *testing.T) {
	t.Parallel()
	body := []byte(`{"status":"success","data":{"resultType":"matrix","result":[` +
		`{"metric":{"__name__":"up","job":"api","instance":"a"},` +
		`"values":[[1756400000,"1"],[1756400015,"NaN"]]}]},"warnings":["slow"]}`)

	env, err := DecodeAPIResponse(body)
	if err != nil {
		t.Fatalf("DecodeAPIResponse: %v", err)
	}
	if env.Failed() {
		t.Fatalf("envelope reported failure: %+v", env)
	}
	q, err := DecodeQueryData(env.Data)
	if err != nil {
		t.Fatalf("DecodeQueryData: %v", err)
	}
	if q.ResultType != "matrix" {
		t.Fatalf("resultType = %q", q.ResultType)
	}
	m, err := DecodeMatrix(q.Result)
	if err != nil {
		t.Fatalf("DecodeMatrix: %v", err)
	}
	if len(m) != 1 || len(m[0].Values) != 2 {
		t.Fatalf("matrix = %+v", m)
	}
	if !math.IsNaN(m[0].Values[1].V) {
		t.Errorf("the NaN sample decoded as %v", m[0].Values[1].V)
	}
	if diff := cmp.Diff([]string{"slow"}, env.Warnings); diff != "" {
		t.Errorf("warnings (-want +got):\n%s", diff)
	}
}
