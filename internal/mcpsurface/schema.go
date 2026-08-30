// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package mcpsurface

import (
	"encoding/json"
	"fmt"

	"github.com/google/jsonschema-go/jsonschema"
)

// Constraint narrows one property of an input schema the SDK inferred from a
// Go struct.
//
// A Go type cannot say "one of these four strings", "between 1 and 500" or
// "defaults to 100". Those bounds are not decoration: they are what stops a
// model asking for a result that would destroy its own context, and they are
// the part of the schema a client shows the model when it is choosing
// arguments. They are therefore declared alongside the tool and applied to the
// inferred schema before it is ever advertised.
//
// The zero value applies nothing.
type Constraint struct {
	// Description overrides the property description inferred from the
	// jsonschema struct tag. It is normally left empty.
	Description string
	// Enum restricts a string property to a closed set.
	Enum []string
	// Min and Max bound a numeric property inclusively.
	Min, Max *float64
	// MaxLength bounds a string property.
	MaxLength *int
	// MinItems and MaxItems bound an array property.
	MinItems, MaxItems *int
	// Pattern is an RE2 pattern a string property must match.
	Pattern string
	// Default is advertised as the property's default and applied by the SDK
	// when the caller omits the property. It must validate against the
	// property's own schema or registration fails.
	Default any
	// Examples are advertised verbatim. One good example is worth more to a
	// model than three sentences of prose.
	Examples []any
	// Items applies to the element schema of an array property.
	Items *Constraint
}

// Ptr returns a pointer to v. It exists so a [Constraint] literal can set Min,
// Max, MaxLength and friends inline.
func Ptr[T any](v T) *T { return &v }

// applyConstraints narrows the properties of an inferred object schema.
//
// An unknown property name is an error rather than a silent no-op: a
// constraint that names a field that was renamed is a bound that quietly
// stopped being enforced, which is the worst possible outcome for a guardrail.
func applyConstraints(s *jsonschema.Schema, cs map[string]Constraint) error {
	if len(cs) == 0 {
		return nil
	}
	for name, c := range cs {
		prop, ok := s.Properties[name]
		if !ok {
			return fmt.Errorf("constraint names unknown property %q", name)
		}
		if err := applyConstraint(prop, c); err != nil {
			return fmt.Errorf("property %q: %w", name, err)
		}
	}
	return nil
}

// applyConstraint narrows one property schema.
func applyConstraint(s *jsonschema.Schema, c Constraint) error {
	if c.Description != "" {
		s.Description = c.Description
	}
	if len(c.Enum) > 0 {
		s.Enum = make([]any, len(c.Enum))
		for i, v := range c.Enum {
			s.Enum[i] = v
		}
	}
	if c.Min != nil {
		s.Minimum = c.Min
	}
	if c.Max != nil {
		s.Maximum = c.Max
	}
	if c.MaxLength != nil {
		s.MaxLength = c.MaxLength
	}
	if c.MinItems != nil {
		s.MinItems = c.MinItems
	}
	if c.MaxItems != nil {
		s.MaxItems = c.MaxItems
	}
	if c.Pattern != "" {
		s.Pattern = c.Pattern
	}
	if len(c.Examples) > 0 {
		s.Examples = c.Examples
	}
	if c.Default != nil {
		b, err := json.Marshal(c.Default)
		if err != nil {
			return fmt.Errorf("default: %w", err)
		}
		s.Default = json.RawMessage(b)
	}
	if c.Items != nil {
		if s.Items == nil {
			return fmt.Errorf("item constraint on a property that is not an array")
		}
		if err := applyConstraint(s.Items, *c.Items); err != nil {
			return fmt.Errorf("items: %w", err)
		}
	}
	return nil
}

// inputSchema infers the schema for In and applies t's constraints.
func inputSchema[In any](t Tool) (*jsonschema.Schema, error) {
	s, err := jsonschema.For[In](nil)
	if err != nil {
		return nil, fmt.Errorf("infer input schema: %w", err)
	}
	if err := applyConstraints(s, t.Constraints); err != nil {
		return nil, err
	}
	return s, nil
}
