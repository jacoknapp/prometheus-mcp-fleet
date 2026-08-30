// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package render

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

// baseTime is the fixed instant every encoding test is written against.
var baseTime = time.Date(2026, 8, 29, 6, 0, 0, 0, time.UTC)

// TestEncodeRangeColumnar covers the shape the whole package exists to
// produce: timestamps once, values as bare numbers, shared labels factored.
func TestEncodeRangeColumnar(t *testing.T) {
	t.Parallel()
	start := baseTime
	end := start.Add(4 * time.Minute)
	m := Matrix{
		{
			Metric: map[string]string{"__name__": "up", "job": "api", "instance": "a"},
			Values: points(start, time.Minute, 1, 2, 3, 4, 5),
		},
		{
			Metric: map[string]string{"__name__": "up", "job": "api", "instance": "b"},
			Values: points(start, time.Minute, 9, 8, 7, 6, 5),
		},
	}
	got := EncodeRange(RangeInput{
		Matrix: m, Start: start, End: end, Step: time.Minute,
		Downsampled: Downsampled{RequestedStep: "auto", AppliedStep: "1m", Reason: "max_points"},
	}, Options{})

	if got.Start != start.Unix() || got.StepSeconds != 60 || got.Points != 5 {
		t.Errorf("start=%d step=%v points=%d", got.Start, got.StepSeconds, got.Points)
	}
	if got.SeriesTotal != 2 || got.Truncated != nil {
		t.Errorf("seriesTotal=%d truncated=%+v", got.SeriesTotal, got.Truncated)
	}
	// job and __name__ are common to both series and are paid for once.
	want := map[string]string{"__name__": "up", "job": "api"}
	if diff := cmp.Diff(want, got.SharedLabels); diff != "" {
		t.Errorf("sharedLabels (-want +got):\n%s", diff)
	}
	// Ranked by descending maximum: instance b (max 9) comes first.
	if got.Series[0].Labels["instance"] != "b" {
		t.Errorf("series are not ranked by max: %+v", got.Series)
	}
	if got.Series[0].Max == nil || *got.Series[0].Max != 9 {
		t.Errorf("max = %v", got.Series[0].Max)
	}
	encoded, err := json.Marshal(got.Series[0].Values)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != "[9,8,7,6,5]" {
		t.Errorf("values = %s, want bare numbers", encoded)
	}
	if got.Downsampled.AppliedStep != "1m" {
		t.Errorf("downsampled = %+v", got.Downsampled)
	}
}

// TestEncodeRangeGapsAndNonFinite proves a gap and a NaN both encode as null,
// which is what they mean to anything plotting or aggregating the series.
func TestEncodeRangeGapsAndNonFinite(t *testing.T) {
	t.Parallel()
	start := baseTime
	m := Matrix{{
		Metric: map[string]string{"job": "api"},
		Values: []Point{
			{T: float64(start.Unix()), V: 1},
			// index 1 missing entirely
			{T: float64(start.Add(2 * time.Minute).Unix()), V: math.NaN()},
			{T: float64(start.Add(3 * time.Minute).Unix()), V: math.Inf(1)},
			{T: float64(start.Add(4 * time.Minute).Unix()), V: 5},
		},
	}}
	got := EncodeRange(RangeInput{
		Matrix: m, Start: start, End: start.Add(4 * time.Minute), Step: time.Minute,
	}, Options{})
	encoded, err := json.Marshal(got.Series[0].Values)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != "[1,null,null,null,5]" {
		t.Errorf("values = %s", encoded)
	}
	if got.Series[0].Max == nil || *got.Series[0].Max != 5 {
		t.Errorf("max = %v, want the largest finite value", got.Series[0].Max)
	}
}

// TestEncodeRangeIgnoresOutOfWindowSamples proves a sample outside the
// requested window is dropped rather than shifting every later index, which
// would silently misalign the whole series.
func TestEncodeRangeIgnoresOutOfWindowSamples(t *testing.T) {
	t.Parallel()
	start := baseTime
	m := Matrix{{
		Metric: map[string]string{"job": "api"},
		Values: []Point{
			{T: float64(start.Add(-time.Hour).Unix()), V: 99},
			{T: float64(start.Unix()), V: 1},
			{T: float64(start.Add(time.Minute).Unix()), V: 2},
			{T: float64(start.Add(time.Hour).Unix()), V: 99},
		},
	}}
	got := EncodeRange(RangeInput{
		Matrix: m, Start: start, End: start.Add(time.Minute), Step: time.Minute,
	}, Options{})
	encoded, err := json.Marshal(got.Series[0].Values)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != "[1,2]" {
		t.Errorf("values = %s, want the out-of-window samples dropped", encoded)
	}
}

// TestEncodeRangeRoundsValues covers the deliberate precision loss.
func TestEncodeRangeRoundsValues(t *testing.T) {
	t.Parallel()
	m := Matrix{{
		Metric: map[string]string{"job": "api"},
		Values: []Point{{T: float64(baseTime.Unix()), V: 0.43210987654321005}},
	}}
	got := EncodeRange(RangeInput{
		Matrix: m, Start: baseTime, End: baseTime, Step: time.Minute,
	}, Options{})
	encoded, err := json.Marshal(got.Series[0].Values)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != "[0.43211]" {
		t.Errorf("values = %s, want six significant digits", encoded)
	}
}

// TestEncodeRangeAllNonFiniteSeriesSortLast proves a series with no finite
// value never displaces one that has data.
func TestEncodeRangeAllNonFiniteSeriesSortLast(t *testing.T) {
	t.Parallel()
	m := Matrix{
		{Metric: map[string]string{"i": "nan"}, Values: []Point{
			{T: float64(baseTime.Unix()), V: math.NaN()}}},
		{Metric: map[string]string{"i": "real"}, Values: []Point{
			{T: float64(baseTime.Unix()), V: 0.001}}},
	}
	got := EncodeRange(RangeInput{
		Matrix: m, Start: baseTime, End: baseTime, Step: time.Minute,
	}, Options{MaxSeries: 1})
	// One survivor, so every label factors into sharedLabels.
	if got.SharedLabels["i"] != "real" {
		t.Errorf("an all-NaN series outranked one with data: shared=%v series=%+v",
			got.SharedLabels, got.Series)
	}
	if got.Truncated == nil || got.Truncated.Selection != "top_1_by_max" {
		t.Errorf("truncated = %+v", got.Truncated)
	}
}

func TestRankByMaxCoversBothFiniteBoundariesAndTies(t *testing.T) {
	t.Parallel()
	real := SeriesStream{Metric: map[string]string{"id": "real"}, Values: []Point{{V: 1}}}
	nan := SeriesStream{Metric: map[string]string{"id": "nan"}, Values: []Point{{V: math.NaN()}}}
	for _, in := range []Matrix{{nan, real}, {real, nan}} {
		got := rankByMax(in)
		if !got[0].ok || got[0].s.Metric["id"] != "real" {
			t.Errorf("rankByMax(%v) = %+v, want finite series first", in, got)
		}
	}
	tied := rankByMax(Matrix{
		{Metric: map[string]string{"id": "z"}, Values: []Point{{V: 2}}},
		{Metric: map[string]string{"id": "a"}, Values: []Point{{V: 2}}},
	})
	if got := tied[0].s.Metric["id"]; got != "a" {
		t.Errorf("equal maxima sorted first %q, want stable label key a", got)
	}
}

func TestEncodingHelpersHandleEmptyLabelsAndWarnings(t *testing.T) {
	t.Parallel()
	rows := vectorRows([]VectorSample{{Value: Point{V: 1}}}, nil)
	if rows[0][1] == nil {
		t.Error("vectorRows emitted a nil labels object; the compact row schema requires an object")
	}
	shared, unchanged := factorShared([]RangeSeries{})
	if shared != nil || unchanged == nil || len(unchanged) != 0 {
		t.Errorf("factorShared(empty) = %v, %#v; want nil and a non-nil empty slice", shared, unchanged)
	}
	if got := sanitizeAll([]string{"\x00", "\x7f"}); got != nil {
		t.Errorf("sanitizeAll(forbidden-only) = %q, want nil", got)
	}
}

func TestEncodeInstantBreaksValueTiesByLabels(t *testing.T) {
	t.Parallel()
	got := EncodeInstant(InstantInput{ResultType: "vector", Vector: Vector{
		{Metric: map[string]string{"id": "z"}, Value: Point{V: 1}},
		{Metric: map[string]string{"id": "a"}, Value: Point{V: 1}},
	}}, Options{})
	if got.Rows[0][1].(map[string]string)["id"] != "a" {
		t.Errorf("equal-valued rows were not ordered by labels: %+v", got.Rows)
	}
}

// TestEncodeRangeEmpty covers the no-data case.
func TestEncodeRangeEmpty(t *testing.T) {
	t.Parallel()
	got := EncodeRange(RangeInput{
		Start: baseTime, End: baseTime.Add(time.Hour), Step: time.Minute,
	}, Options{})
	if got == nil {
		t.Fatal("EncodeRange returned nil")
	}
	if len(got.Series) != 0 || got.SeriesTotal != 0 || got.Truncated != nil {
		t.Errorf("got = %+v", got)
	}
	if got.Points != 61 {
		t.Errorf("points = %d, want 61", got.Points)
	}
}

// TestEncodeRangeDegenerateBounds covers an inverted or zero-step request,
// which must not panic or produce a negative point count.
func TestEncodeRangeDegenerateBounds(t *testing.T) {
	t.Parallel()
	got := EncodeRange(RangeInput{
		Matrix: Matrix{{Metric: map[string]string{"a": "b"},
			Values: []Point{{T: float64(baseTime.Unix()), V: 1}}}},
		Start: baseTime.Add(time.Hour), End: baseTime, Step: 0,
	}, Options{})
	if got.Points != 0 || got.StepSeconds != 1 {
		t.Errorf("points=%d step=%v", got.Points, got.StepSeconds)
	}
}

// TestEncodeRangeSeriesTotalHint covers an upstream-truncated matrix.
func TestEncodeRangeSeriesTotalHint(t *testing.T) {
	t.Parallel()
	got := EncodeRange(RangeInput{
		Matrix: Matrix{{Metric: map[string]string{"a": "b"},
			Values: []Point{{T: float64(baseTime.Unix()), V: 1}}}},
		Start: baseTime, End: baseTime, Step: time.Minute, SeriesTotalHint: 900,
	}, Options{})
	if got.SeriesTotal != 900 {
		t.Errorf("seriesTotal = %d, want the upstream total", got.SeriesTotal)
	}
}

// TestEncodeRangeTokenCeiling proves the ceiling beats an explicit maxSeries.
func TestEncodeRangeTokenCeiling(t *testing.T) {
	t.Parallel()
	m := make(Matrix, 0, 100)
	for i := range 100 {
		m = append(m, SeriesStream{
			Metric: map[string]string{
				"__name__": "x", "pod": fmt.Sprintf("workload-%04d-abcdef", i)},
			Values: points(baseTime, time.Minute, seq(60, float64(i))...),
		})
	}
	got := EncodeRange(RangeInput{
		Matrix: m, Start: baseTime, End: baseTime.Add(59 * time.Minute), Step: time.Minute,
	}, Options{MaxSeries: 100, TokenCeiling: 1500})
	if got.Truncated == nil || got.Truncated.Reason != ReasonTokenCeiling {
		t.Fatalf("truncated = %+v", got.Truncated)
	}
	if got.Truncated.Total != 100 {
		t.Errorf("total = %d, want the honest 100", got.Truncated.Total)
	}
	if got.Truncated.Selection == "" {
		t.Error("the ceiling truncation did not name its selection")
	}
	if EstimateTokens(got) > 3000 {
		t.Errorf("result is %d estimated tokens against a 1500 ceiling",
			EstimateTokens(got))
	}
}

// TestEncodeInstant covers the instant encoding and its ranking.
func TestEncodeInstant(t *testing.T) {
	t.Parallel()
	got := EncodeInstant(InstantInput{
		ResultType: "vector",
		At:         baseTime,
		Vector: Vector{
			{Metric: map[string]string{"__name__": "up", "job": "api", "i": "1"},
				Value: Point{V: 0}},
			{Metric: map[string]string{"__name__": "up", "job": "api", "i": "2"},
				Value: Point{V: 1}},
		},
		Warnings: []string{"a warning"},
	}, Options{})

	if diff := cmp.Diff(InstantColumns, got.Columns); diff != "" {
		t.Errorf("columns (-want +got):\n%s", diff)
	}
	if got.Total != 2 || got.ResultType != "vector" || got.Time != baseTime.Unix() {
		t.Errorf("got = %+v", got)
	}
	// Descending by value: i=2 first.
	if got.Rows[0][1].(map[string]string)["i"] != "2" {
		t.Errorf("rows are not ranked: %+v", got.Rows)
	}
	if got.Rows[0][0] != "up" {
		t.Errorf("__name__ is not in its own column: %+v", got.Rows[0])
	}
	if diff := cmp.Diff(map[string]string{"job": "api"}, got.SharedLabels); diff != "" {
		t.Errorf("sharedLabels (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff([]string{"a warning"}, got.Warnings); diff != "" {
		t.Errorf("warnings (-want +got):\n%s", diff)
	}
}

// TestEncodeInstantScalarAndString covers the non-vector results.
func TestEncodeInstantScalarAndString(t *testing.T) {
	t.Parallel()
	s := EncodeInstant(InstantInput{
		ResultType: "scalar", At: baseTime, Scalar: &Point{V: 42.5},
	}, Options{})
	if s.Total != 1 {
		t.Fatalf("total = %d", s.Total)
	}
	b, err := json.Marshal(s.Rows[0][2])
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "42.5" {
		t.Errorf("scalar = %s", b)
	}

	str := EncodeInstant(InstantInput{
		ResultType: "string", At: baseTime, StringValue: "hello\x00",
	}, Options{})
	if str.Rows[0][2] != "hello" {
		t.Errorf("string = %v, want it sanitised", str.Rows[0][2])
	}
}

// TestEncodeInstantEmpty covers a vector with no samples.
func TestEncodeInstantEmpty(t *testing.T) {
	t.Parallel()
	got := EncodeInstant(InstantInput{ResultType: "vector", At: baseTime}, Options{})
	if got == nil || got.Total != 0 || len(got.Rows) != 0 || got.SharedLabels != nil {
		t.Errorf("got = %+v", got)
	}
}

// TestEncodeInstantTruncation covers the limit and the ceiling.
func TestEncodeInstantTruncation(t *testing.T) {
	t.Parallel()
	v := make(Vector, 0, 50)
	for i := range 50 {
		v = append(v, VectorSample{
			Metric: map[string]string{"__name__": "x", "pod": fmt.Sprintf("p-%03d", i)},
			Value:  Point{V: float64(i)},
		})
	}
	limited := EncodeInstant(InstantInput{ResultType: "vector", Vector: v, At: baseTime},
		Options{MaxItems: 10})
	if len(limited.Rows) != 10 || limited.Truncated == nil {
		t.Fatalf("rows=%d truncated=%+v", len(limited.Rows), limited.Truncated)
	}
	if limited.Truncated.Reason != ReasonLimit ||
		limited.Truncated.Selection != "top_10_by_max" {
		t.Errorf("truncated = %+v", limited.Truncated)
	}
	if limited.Truncated.Total != 50 {
		t.Errorf("total = %d", limited.Truncated.Total)
	}

	ceiled := EncodeInstant(InstantInput{ResultType: "vector", Vector: v, At: baseTime},
		Options{MaxItems: 1000, TokenCeiling: 200})
	if ceiled.Truncated == nil || ceiled.Truncated.Reason != ReasonTokenCeiling {
		t.Fatalf("truncated = %+v", ceiled.Truncated)
	}
	if ceiled.Truncated.Total != 50 {
		t.Errorf("the honest total was lost: %+v", ceiled.Truncated)
	}
}

// TestEncodeInstantSingleSampleHasNoSharedLabels proves the factoring is not
// applied where it would be a pure loss.
func TestEncodeInstantSingleSampleHasNoSharedLabels(t *testing.T) {
	t.Parallel()
	got := EncodeInstant(InstantInput{
		ResultType: "vector", At: baseTime,
		Vector: Vector{{Metric: map[string]string{"__name__": "up", "job": "a"},
			Value: Point{V: 1}}},
	}, Options{})
	if got.SharedLabels != nil {
		t.Errorf("sharedLabels = %v, want none for a single row", got.SharedLabels)
	}
	if got.Rows[0][1].(map[string]string)["job"] != "a" {
		t.Errorf("the label was lost: %+v", got.Rows[0])
	}
}

// points builds a series of samples at a fixed spacing.
func points(start time.Time, step time.Duration, values ...float64) []Point {
	out := make([]Point, 0, len(values))
	for i, v := range values {
		out = append(out, Point{T: float64(start.Add(time.Duration(i) * step).Unix()), V: v})
	}
	return out
}

// seq builds n values rising to max, so a series' maximum is predictable.
func seq(n int, max float64) []float64 {
	out := make([]float64, n)
	for i := range n {
		out[i] = max * float64(i) / float64(max2(n-1, 1))
	}
	return out
}

// max2 is the two-argument maximum, named to avoid shadowing the builtin in a
// file that also uses it.
func max2(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// TestTable covers the fixed-width renderer, including the cell sanitisation
// that stops a monitored cluster forging extra rows.
func TestTable(t *testing.T) {
	t.Parallel()
	got := Table([]string{"JOB", "STATE"}, [][]string{
		{"api", "up"},
		{"a-much-longer-job", "down"},
	})
	lines := strings.Split(strings.TrimRight(got, "\n"), "\n")
	if len(lines) != 4 {
		t.Fatalf("got %d lines:\n%s", len(lines), got)
	}
	if !strings.HasPrefix(lines[0], "JOB") || !strings.Contains(lines[0], "STATE") {
		t.Errorf("header = %q", lines[0])
	}
	if !strings.HasPrefix(lines[1], "-----") {
		t.Errorf("separator = %q", lines[1])
	}
	// Every column starts at the same offset on every row.
	col := strings.Index(lines[0], "STATE")
	for _, l := range lines[2:] {
		if len(l) <= col {
			t.Fatalf("row is shorter than the column offset: %q", l)
		}
	}

	// A newline in a cell would let a cluster forge a row.
	forged := Table([]string{"A"}, [][]string{{"x\nFORGED  row"}})
	if strings.Count(strings.TrimRight(forged, "\n"), "\n") != 2 {
		t.Errorf("a cell newline forged a row:\n%s", forged)
	}

	if got := Table(nil, nil); got != "" {
		t.Errorf("empty table = %q", got)
	}
	// A row wider than the header still renders every cell.
	wide := Table([]string{"A"}, [][]string{{"1", "2", "3"}})
	if !strings.Contains(wide, "3") {
		t.Errorf("wide row lost a cell:\n%s", wide)
	}
	// A pathological cell is clipped so the column width stays sane.
	long := Table([]string{"A"}, [][]string{{strings.Repeat("x", 500)}})
	if !strings.Contains(long, ClipMarker) {
		t.Errorf("a pathological cell was not clipped:\n%s", long)
	}
}
