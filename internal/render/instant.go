// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package render

import (
	"cmp"
	"fmt"
	"slices"
	"time"
)

// InstantColumns are the fixed columns of an instant query result. They are
// declared once per result rather than repeated as object keys on every row,
// which is where the saving over the upstream shape comes from.
var InstantColumns = []string{"__name__", "labels", "value"}

// Row is one row of a columnar result. Its members line up positionally with
// the result's Columns.
type Row []any

// InstantResult is the columnar encoding of an instant query.
type InstantResult struct {
	// ResultType echoes Prometheus' own result type: "vector", "scalar" or
	// "string".
	ResultType string `json:"resultType"`
	// Time is the evaluation timestamp in Unix seconds.
	Time int64 `json:"time"`
	// Columns names the members of each row.
	Columns []string `json:"columns"`
	// Rows are the samples, ranked by descending value.
	Rows []Row `json:"rows"`
	// SharedLabels are the labels every returned row has in common.
	SharedLabels map[string]string `json:"sharedLabels,omitempty"`
	// Total is how many samples matched before truncation.
	Total int `json:"total"`
	// Truncated is non-nil when rows were dropped.
	Truncated *Truncation `json:"truncated,omitempty"`
	// Warnings are the query engine's own non-fatal notes.
	Warnings []string `json:"warnings,omitempty"`
}

// InstantInput is the input to [EncodeInstant].
type InstantInput struct {
	// Vector is the decoded upstream result, empty for a scalar or string
	// result.
	Vector Vector
	// Scalar is the decoded scalar result.
	Scalar *Point
	// StringValue is the decoded string result.
	StringValue string
	// ResultType is Prometheus' own result type.
	ResultType string
	// At is the evaluation time.
	At time.Time
	// Warnings are the upstream warnings.
	Warnings []string
}

// EncodeInstant builds the columnar representation of an instant query.
//
// Rows are ranked by descending value so that a truncated result keeps the
// samples an operator is most likely to be looking for, and the ranking is
// reported through [Truncation.Selection] rather than left implicit. It never
// returns nil.
func EncodeInstant(in InstantInput, opts Options) *InstantResult {
	opts = opts.WithDefaults()
	res := &InstantResult{
		ResultType: Sanitize(in.ResultType),
		Time:       in.At.Unix(),
		Columns:    InstantColumns,
		Rows:       []Row{},
		Warnings:   sanitizeAll(in.Warnings),
	}

	switch {
	case in.Scalar != nil:
		res.Total = 1
		res.Rows = []Row{{"", map[string]string{}, jsonNumber(round(in.Scalar.V))}}
		return res
	case in.ResultType == "string":
		res.Total = 1
		res.Rows = []Row{{"", map[string]string{}, ClipBytes(in.StringValue, MaxLabelValueBytes)}}
		return res
	}

	samples := slices.Clone(in.Vector)
	slices.SortStableFunc(samples, func(a, b VectorSample) int {
		if a.Value.V != b.Value.V {
			return cmp.Compare(b.Value.V, a.Value.V)
		}
		return cmp.Compare(labelKey(a.Metric), labelKey(b.Metric))
	})
	res.Total = len(samples)

	kept, trunc := TruncateItems(samples, opts.MaxItems,
		fmt.Sprintf("%d samples matched. Add label matchers or aggregate with sum by(...) "+
			"to narrow the result; raising limit past %d will hit the hub token ceiling.",
			len(samples), opts.MaxItems))
	if trunc != nil {
		trunc.Selection = SelectionTopNByMax(len(kept))
	}

	build := func(sel []VectorSample) any { return vectorRows(sel, nil) }
	fitted, hit := FitTokens(kept, opts.TokenCeiling, build)
	if hit {
		trunc = trunc.Escalate(len(fitted), ReasonTokenCeiling,
			fmt.Sprintf("The hub caps a result at about %d estimated tokens regardless of "+
				"the requested limit. Narrow the query or aggregate.", opts.TokenCeiling))
		trunc.Total = res.Total
		trunc.Selection = SelectionTopNByMax(len(fitted))
	}

	shared := sharedVectorLabels(fitted)
	res.SharedLabels = shared
	res.Rows = vectorRows(fitted, shared)
	res.Truncated = trunc
	return res
}

// vectorRows projects samples onto [InstantColumns], omitting shared labels.
func vectorRows(samples []VectorSample, shared map[string]string) []Row {
	rows := make([]Row, 0, len(samples))
	for _, s := range samples {
		labels := Labels(s.Metric)
		name := labels["__name__"]
		delete(labels, "__name__")
		for k := range shared {
			delete(labels, k)
		}
		if labels == nil {
			labels = map[string]string{}
		}
		rows = append(rows, Row{name, labels, jsonNumber(round(s.Value.V))})
	}
	return rows
}

// sharedVectorLabels returns the labels every sample has in common, ignoring
// __name__ which is carried in its own column.
func sharedVectorLabels(samples []VectorSample) map[string]string {
	if len(samples) < 2 {
		return nil
	}
	shared := Labels(samples[0].Metric)
	delete(shared, "__name__")
	for _, s := range samples[1:] {
		other := Labels(s.Metric)
		for k, v := range shared {
			if other[k] != v {
				delete(shared, k)
			}
		}
		if len(shared) == 0 {
			return nil
		}
	}
	if len(shared) == 0 {
		return nil
	}
	return shared
}
