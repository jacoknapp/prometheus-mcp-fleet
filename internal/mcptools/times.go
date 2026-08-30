// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package mcptools

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/render"
)

// ParseTime resolves a timestamp argument against now.
//
// Three forms are accepted, in this order:
//
//   - Relative: "now", "now-6h", "now+15m", or the bare offset forms "-15m"
//     and "+1h". Language models get relative times right far more often than
//     absolute ones — an agent asked for "the last six hours" will confidently
//     produce a wrong RFC 3339 timestamp, and will not notice — so relative is
//     the form the tool descriptions lead with.
//   - RFC 3339, with or without fractional seconds.
//   - A Unix timestamp in seconds, integral or fractional, which is what the
//     Prometheus API itself accepts and what an agent copying from a raw curl
//     will paste.
//
// The empty string returns the zero time and no error; callers substitute
// their own default. Durations use the Prometheus grammar, so "1d" and "1w"
// work where Go's own parser would refuse them.
func ParseTime(s string, now time.Time) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, nil
	}
	if rel, ok, err := parseRelative(s, now); ok {
		return rel, err
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), nil
		}
	}
	if secs, err := strconv.ParseFloat(s, 64); err == nil {
		sec, frac := int64(secs), secs-float64(int64(secs))
		return time.Unix(sec, int64(frac*1e9)).UTC(), nil
	}
	return time.Time{}, fmt.Errorf(
		"%q is not a time: use a relative form such as \"now-6h\" or \"-15m\", "+
			"an RFC 3339 timestamp such as \"2026-08-29T12:00:00Z\", or a Unix timestamp", s)
}

// parseRelative handles the "now", "now±D" and bare "±D" forms. The second
// result reports whether s was a relative form at all, so the caller can fall
// through to the absolute parsers without swallowing a genuine error.
func parseRelative(s string, now time.Time) (time.Time, bool, error) {
	body := s
	switch {
	case s == "now":
		return now.UTC(), true, nil
	case strings.HasPrefix(s, "now"):
		body = strings.TrimSpace(s[len("now"):])
		if body == "" {
			return now.UTC(), true, nil
		}
	case strings.HasPrefix(s, "-"), strings.HasPrefix(s, "+"):
		// Bare offset.
	default:
		return time.Time{}, false, nil
	}
	sign := time.Duration(1)
	switch {
	case strings.HasPrefix(body, "-"):
		sign, body = -1, body[1:]
	case strings.HasPrefix(body, "+"):
		body = body[1:]
	default:
		return time.Time{}, true, fmt.Errorf(
			"%q is not a time: a relative time needs a sign, as in \"now-6h\"", s)
	}
	d, err := render.ParsePromDuration(strings.TrimSpace(body))
	if err != nil {
		return time.Time{}, true, fmt.Errorf(
			"%q is not a time: %q is not a duration such as \"6h\", \"15m\" or \"1d\"", s, body)
	}
	return now.Add(sign * d).UTC(), true, nil
}

// ParseDuration resolves a duration argument in the Prometheus grammar,
// returning zero for the empty string.
func ParseDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	d, err := render.ParsePromDuration(s)
	if err != nil {
		return 0, fmt.Errorf("%q is not a duration such as \"30s\", \"5m\" or \"1d\"", s)
	}
	if d <= 0 {
		return 0, fmt.Errorf("duration %q must be positive", s)
	}
	return d, nil
}

// formatUpstreamTime renders a time as the Unix-seconds form the Prometheus
// API accepts. Seconds rather than RFC 3339 because it round-trips exactly:
// an RFC 3339 rendering loses sub-millisecond precision on some servers and
// then a range boundary no longer aligns with the step grid.
func formatUpstreamTime(t time.Time) string {
	return strconv.FormatFloat(float64(t.UnixNano())/1e9, 'f', -1, 64)
}
