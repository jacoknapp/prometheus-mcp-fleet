// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package mcpsurface

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/jsonschema-go/jsonschema"
)

// constrainedIn exercises every property kind [Constraint] can narrow.
type constrainedIn struct {
	Format  string   `json:"format"`
	Limit   int      `json:"limit,omitempty"`
	Name    string   `json:"name,omitempty"`
	Metrics []string `json:"metrics,omitempty"`
}

// TestApplyConstraints covers each narrowing a Constraint performs. These
// bounds are what stops a model asking for a result that would destroy its own
// context, so each one is asserted against the JSON a client actually receives.
func TestApplyConstraints(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		cs       map[string]Constraint
		property string
		want     map[string]any
	}{
		{
			name:     "an enum with a default",
			cs:       map[string]Constraint{"format": {Enum: []string{"compact", "json", "table"}, Default: "compact"}},
			property: "format",
			want: map[string]any{
				"type":    "string",
				"enum":    []any{"compact", "json", "table"},
				"default": "compact",
			},
		},
		{
			name: "an inclusive numeric range",
			cs: map[string]Constraint{"limit": {
				Description: "how many rows to return",
				Min:         Ptr(1.0), Max: Ptr(500.0), Default: 100,
			}},
			property: "limit",
			want: map[string]any{
				"type":        "integer",
				"description": "how many rows to return",
				"minimum":     float64(1),
				"maximum":     float64(500),
				"default":     float64(100),
			},
		},
		{
			name:     "a string bound and pattern",
			cs:       map[string]Constraint{"name": {MaxLength: Ptr(63), Pattern: `^[a-z0-9-]+$`}},
			property: "name",
			want: map[string]any{
				"type":      "string",
				"maxLength": float64(63),
				"pattern":   `^[a-z0-9-]+$`,
			},
		},
		{
			name: "array bounds with an element constraint",
			cs: map[string]Constraint{"metrics": {
				MinItems: Ptr(1), MaxItems: Ptr(20),
				Examples: []any{[]any{"up"}},
				Items:    &Constraint{MaxLength: Ptr(255), Pattern: `^[a-zA-Z_:]`},
			}},
			property: "metrics",
			want: map[string]any{
				// A Go slice is nil-able, so the inferred type is a union.
				"type":     []any{"null", "array"},
				"minItems": float64(1),
				"maxItems": float64(20),
				"examples": []any{[]any{"up"}},
				"items": map[string]any{
					"type":      "string",
					"maxLength": float64(255),
					"pattern":   `^[a-zA-Z_:]`,
				},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			schema, err := inputSchema[constrainedIn](Tool{Name: "t", Constraints: tc.cs})
			if err != nil {
				t.Fatalf("inputSchema: %v", err)
			}
			b, err := json.Marshal(schema)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			var decoded struct {
				Properties map[string]map[string]any `json:"properties"`
			}
			if err := json.Unmarshal(b, &decoded); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if diff := cmp.Diff(tc.want, decoded.Properties[tc.property]); diff != "" {
				t.Errorf("property %q (-want +got):\n%s", tc.property, diff)
			}
		})
	}
}

// TestApplyConstraintsErrors covers the registration-time refusals. A
// constraint that cannot be applied is a guardrail that would otherwise stop
// being enforced silently.
func TestApplyConstraintsErrors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		cs      map[string]Constraint
		wantMsg []string
	}{
		{
			name:    "a property that does not exist",
			cs:      map[string]Constraint{"nope": {Pattern: "^x$"}},
			wantMsg: []string{"unknown property", `"nope"`},
		},
		{
			name:    "an item constraint on a property that is not an array",
			cs:      map[string]Constraint{"format": {Items: &Constraint{MaxLength: Ptr(1)}}},
			wantMsg: []string{`"format"`, "not an array"},
		},
		{
			name:    "a default that cannot be marshalled",
			cs:      map[string]Constraint{"limit": {Default: make(chan int)}},
			wantMsg: []string{`"limit"`, "default"},
		},
		{
			name: "a bad element constraint is reported with its path",
			cs: map[string]Constraint{
				"metrics": {Items: &Constraint{Default: make(chan int)}},
			},
			wantMsg: []string{`"metrics"`, "items", "default"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := inputSchema[constrainedIn](Tool{Name: "t", Constraints: tc.cs})
			if err == nil {
				t.Fatal("the constraint was accepted")
			}
			for _, want := range tc.wantMsg {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not mention %q", err, want)
				}
			}
		})
	}
}

// TestNoConstraintsIsANoOp proves the empty case leaves the inferred schema
// exactly as the SDK produced it.
func TestNoConstraintsIsANoOp(t *testing.T) {
	t.Parallel()
	bare, err := inputSchema[constrainedIn](Tool{Name: "t"})
	if err != nil {
		t.Fatalf("inputSchema: %v", err)
	}
	empty, err := inputSchema[constrainedIn](Tool{Name: "t", Constraints: map[string]Constraint{}})
	if err != nil {
		t.Fatalf("inputSchema: %v", err)
	}
	a, _ := json.Marshal(bare)
	b, _ := json.Marshal(empty)
	if diff := cmp.Diff(string(a), string(b)); diff != "" {
		t.Errorf("an empty constraint map changed the schema (-nil +empty):\n%s", diff)
	}
	// The zero Constraint applies nothing either.
	zero, err := inputSchema[constrainedIn](Tool{
		Name: "t", Constraints: map[string]Constraint{"format": {}},
	})
	if err != nil {
		t.Fatalf("inputSchema: %v", err)
	}
	c, _ := json.Marshal(zero)
	if diff := cmp.Diff(string(a), string(c)); diff != "" {
		t.Errorf("a zero Constraint changed the schema (-nil +zero):\n%s", diff)
	}
}

// TestApplyConstraintZeroValueLeavesSliceFieldsNil pins that applying a
// Constraint whose Enum (or Examples) is unset never gives the schema's Enum
// (or Examples) an empty-but-non-nil value.
//
// jsonschema.Schema documents nil and []any{} as meaningfully different:
// nil means no constraint, but an empty slice vacuously rejects every
// instance. TestNoConstraintsIsANoOp already pins the zero-Constraint case
// through JSON, but Enum and Examples both marshal with "omitempty", which
// drops an empty slice exactly like a nil one -- so that round trip cannot
// tell a correct "left untouched" apart from a version that ran
// s.Enum = make([]any, len(c.Enum)) (or the Examples assignment)
// unconditionally, regardless of len(c.Enum)/len(c.Examples). This asserts
// the pre-marshal struct field directly, where the two are distinguishable.
func TestApplyConstraintZeroValueLeavesSliceFieldsNil(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		get  func(*jsonschema.Schema) []any
	}{
		{name: "enum", get: func(s *jsonschema.Schema) []any { return s.Enum }},
		{name: "examples", get: func(s *jsonschema.Schema) []any { return s.Examples }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s := &jsonschema.Schema{Type: "string"}
			// Description is set so this exercises the same applyConstraint
			// call a real, non-empty Constraint that simply doesn't mention
			// this field makes -- not an early return for an all-zero value.
			if err := applyConstraint(s, Constraint{Description: "unrelated"}); err != nil {
				t.Fatalf("applyConstraint: %v", err)
			}
			if got := tc.get(s); got != nil {
				t.Errorf("%s = %#v, want nil", tc.name, got)
			}
		})
	}
}

// uninferrableIn has a field the schema inferrer cannot describe.
type uninferrableIn struct {
	Ch chan int `json:"ch"`
}

// TestInputSchemaInferenceFailure covers the other registration-time panic
// path: a Go type the SDK cannot turn into a schema.
func TestInputSchemaInferenceFailure(t *testing.T) {
	t.Parallel()
	if _, err := inputSchema[uninferrableIn](Tool{Name: "t"}); err == nil {
		t.Fatal("a channel field produced a schema")
	} else if !strings.Contains(err.Error(), "infer input schema") {
		t.Errorf("error = %v, want it to name the inference step", err)
	}

	s := newTestServer(t, nil)
	defer func() {
		if r := recover(); r == nil {
			t.Error("AddTool accepted a type with no inferrable schema")
		}
	}()
	AddTool(s, Tool{Name: "bad", Description: "d"},
		func(context.Context, *Request, uninferrableIn) (echoOut, Result, error) {
			return echoOut{}, OKResult, nil
		})
}
