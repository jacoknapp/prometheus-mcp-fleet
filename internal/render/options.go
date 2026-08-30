// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package render

import (
	"errors"
	"fmt"
)

// Format selects the wire encoding of a tool result.
type Format string

const (
	// FormatCompact is the default columnar encoding described in
	// docs/adr/0012-token-efficient-tool-output.md.
	FormatCompact Format = "compact"
	// FormatJSON passes the upstream Prometheus shape through unchanged. It is
	// documented to callers as costing ten to fifty times more tokens and
	// exists so an operator debugging the hub against a raw curl sees the same
	// bytes.
	FormatJSON Format = "json"
	// FormatTable renders fixed-width text, which is the cheapest encoding for
	// wide, shallow results such as targets, alerts, rules and cluster lists.
	FormatTable Format = "table"
)

// ErrUnknownFormat reports a format string outside the closed set.
var ErrUnknownFormat = errors.New("render: unknown format")

// ParseFormat resolves a caller-supplied format string. The empty string
// resolves to [FormatCompact], because an agent that says nothing must get the
// encoding that cannot destroy its context.
func ParseFormat(s string) (Format, error) {
	switch Format(s) {
	case "":
		return FormatCompact, nil
	case FormatCompact:
		return FormatCompact, nil
	case FormatJSON:
		return FormatJSON, nil
	case FormatTable:
		return FormatTable, nil
	default:
		return "", fmt.Errorf("%w: %q (want compact, json or table)", ErrUnknownFormat, s)
	}
}

// String implements fmt.Stringer.
func (f Format) String() string { return string(f) }

// Defaults applied by [Options.WithDefaults].
const (
	// DefaultMaxSeries is how many series a single-cluster range result keeps
	// before top-N truncation.
	DefaultMaxSeries = 20
	// DefaultMaxPoints is the point budget a range result is stepped down to.
	DefaultMaxPoints = 120
	// DefaultMaxItems is the row budget for list-shaped results.
	DefaultMaxItems = 100
	// DefaultTokenCeiling is the hub-side estimated-token ceiling. Any result
	// above it is force-truncated regardless of the caller's limit, so an
	// agent cannot blow its own context in one call even by asking for it.
	DefaultTokenCeiling = 25000
	// BytesPerToken is the divisor [EstimateTokens] uses. It is an estimate:
	// real tokenisers vary with the alphabet and with how much of the payload
	// is punctuation, and JSON is punctuation-dense, so this understates
	// slightly for label-heavy output and overstates for long numeric arrays.
	BytesPerToken = 4
)

// Options bounds one encoding. The zero value is usable through
// [Options.WithDefaults]; every field is a ceiling the caller may lower but
// never a promise the encoder will reach.
type Options struct {
	// Format selects the wire encoding. Empty means [FormatCompact].
	Format Format
	// MaxSeries caps how many series survive truncation. Zero means
	// [DefaultMaxSeries].
	MaxSeries int
	// MaxPoints caps the samples per series and therefore drives step
	// selection. Zero means [DefaultMaxPoints].
	MaxPoints int
	// MaxItems caps rows in a list-shaped result. Zero means
	// [DefaultMaxItems].
	MaxItems int
	// TokenCeiling is the estimated-token ceiling enforced after encoding.
	// Zero means [DefaultTokenCeiling]; a negative value disables the ceiling
	// and is only appropriate in tests.
	TokenCeiling int
}

// WithDefaults returns a copy of o with every zero field replaced by its
// documented default.
func (o Options) WithDefaults() Options {
	if o.Format == "" {
		o.Format = FormatCompact
	}
	if o.MaxSeries <= 0 {
		o.MaxSeries = DefaultMaxSeries
	}
	if o.MaxPoints <= 0 {
		o.MaxPoints = DefaultMaxPoints
	}
	if o.MaxItems <= 0 {
		o.MaxItems = DefaultMaxItems
	}
	if o.TokenCeiling == 0 {
		o.TokenCeiling = DefaultTokenCeiling
	}
	return o
}
