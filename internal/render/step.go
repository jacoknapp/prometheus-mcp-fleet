// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package render

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
)

// StepLadder is the set of steps a range query is snapped up to. Human-sensible
// values matter because an agent reasoning about "the last fifteen minutes"
// should see a step it can name, and because a step of 2m37s in a response is
// noise the model has to spend attention parsing.
var StepLadder = []time.Duration{
	15 * time.Second,
	30 * time.Second,
	time.Minute,
	5 * time.Minute,
	15 * time.Minute,
	time.Hour,
	6 * time.Hour,
	24 * time.Hour,
}

// Downsampled reports the step the hub actually applied and why. It is emitted
// on every range result, including the one where nothing changed, because an
// agent reasoning about a latency spike must know whether it is looking at raw
// or averaged data before it draws a conclusion — and "no field present" is
// not something a model reliably reads as "not downsampled".
type Downsampled struct {
	// RequestedStep is what the caller asked for, or "auto" when it left the
	// choice to the hub.
	RequestedStep string `json:"requestedStep"`
	// AppliedStep is the step the query actually ran at.
	AppliedStep string `json:"appliedStep"`
	// Reason names the constraint that decided it.
	Reason string `json:"reason"`
}

// Step selection reasons. Closed set.
const (
	// StepReasonRequested means the caller's step was used unchanged.
	StepReasonRequested = "requested_step_honoured"
	// StepReasonMaxPoints means the step was raised to keep the result inside
	// the point budget.
	StepReasonMaxPoints = "max_points"
	// StepReasonScrapeInterval means the step was raised to the cluster's
	// scrape interval, below which the extra points carry no information.
	StepReasonScrapeInterval = "scrape_interval_floor"
	// StepReasonLadder means the step was snapped up to the nearest ladder
	// value.
	StepReasonLadder = "snapped_to_ladder"
)

// StepRequest is the input to [SelectStep].
type StepRequest struct {
	// Start and End bound the query. End must not precede Start.
	Start, End time.Time
	// UserStep is the caller's requested step. Zero means "choose for me".
	UserStep time.Duration
	// ScrapeInterval is the cluster's reported global scrape interval. Zero
	// means unknown, in which case no floor is applied.
	ScrapeInterval time.Duration
	// MaxPoints is the point budget. Zero means [DefaultMaxPoints].
	MaxPoints int
}

// SelectStep chooses the step for a range query and reports what it did.
//
// The rule is step = max(userStep, ceil((end-start)/maxPoints)), snapped up to
// [StepLadder] and then floored at the cluster's scrape interval. The floor is
// applied last: asking for points closer together than the data was collected
// buys nothing but tokens, and Prometheus will happily interpolate them.
//
// The returned duration is always positive.
func SelectStep(r StepRequest) (time.Duration, Downsampled) {
	maxPoints := r.MaxPoints
	if maxPoints <= 0 {
		maxPoints = DefaultMaxPoints
	}
	span := r.End.Sub(r.Start)
	if span < 0 {
		span = 0
	}

	requested := "auto"
	if r.UserStep > 0 {
		requested = FormatDuration(r.UserStep)
	}

	step := r.UserStep
	reason := StepReasonRequested
	if step <= 0 {
		reason = StepReasonMaxPoints
	}

	// Point budget.
	if span > 0 {
		needed := time.Duration(math.Ceil(float64(span) / float64(maxPoints)))
		if needed > step {
			step = needed
			reason = StepReasonMaxPoints
		}
	}
	if step <= 0 {
		step = StepLadder[0]
		reason = StepReasonMaxPoints
	}

	// Ladder snap. A step the caller asked for that already sits on the ladder
	// is left alone; anything else moves up to the next rung, or to a whole
	// number of days beyond the top rung.
	if snapped := snapUp(step); snapped != step {
		step = snapped
		if reason == StepReasonRequested {
			reason = StepReasonLadder
		}
	}

	// Scrape-interval floor, applied after the snap so the floor wins.
	if r.ScrapeInterval > 0 && step < r.ScrapeInterval {
		step = r.ScrapeInterval
		reason = StepReasonScrapeInterval
	}

	return step, Downsampled{
		RequestedStep: requested,
		AppliedStep:   FormatDuration(step),
		Reason:        reason,
	}
}

// snapUp returns the smallest ladder value greater than or equal to d, or a
// whole number of days when d exceeds the top rung.
func snapUp(d time.Duration) time.Duration {
	for _, rung := range StepLadder {
		if d <= rung {
			return rung
		}
	}
	day := 24 * time.Hour
	n := (d + day - 1) / day
	return n * day
}

// FormatDuration renders d in Prometheus duration syntax ("15s", "5m", "1h",
// "1d"), which is what the tool schemas document and what an agent will copy
// back into its next call. Fractional seconds below one second render in
// milliseconds; anything that does not divide cleanly falls back to Go's own
// rendering, which Prometheus also accepts.
func FormatDuration(d time.Duration) string {
	if d <= 0 {
		return "0s"
	}
	units := []struct {
		size   time.Duration
		suffix string
	}{
		{24 * time.Hour, "d"},
		{time.Hour, "h"},
		{time.Minute, "m"},
		{time.Second, "s"},
		{time.Millisecond, "ms"},
	}
	for _, u := range units {
		if d >= u.size && d%u.size == 0 {
			return strconv.FormatInt(int64(d/u.size), 10) + u.suffix
		}
	}
	return strings.TrimSuffix(d.String(), "0s")
}

// ParsePromDuration parses a Prometheus duration such as "5m", "1h30m" or
// "1d", or a plain number of seconds. It is the inverse of [FormatDuration]
// for every value that function emits.
func ParsePromDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("render: empty duration")
	}
	if secs, err := strconv.ParseFloat(s, 64); err == nil {
		if math.IsNaN(secs) || math.IsInf(secs, 0) {
			return 0, fmt.Errorf("render: duration %q is not finite", s)
		}
		return time.Duration(secs * float64(time.Second)), nil
	}
	var total time.Duration
	rest := s
	for rest != "" {
		i := 0
		for i < len(rest) && rest[i] >= '0' && rest[i] <= '9' {
			i++
		}
		if i == 0 {
			return 0, fmt.Errorf("render: %q is not a duration", s)
		}
		n, err := strconv.Atoi(rest[:i])
		if err != nil {
			return 0, fmt.Errorf("render: %q is not a duration", s)
		}
		rest = rest[i:]
		var unit time.Duration
		switch {
		case strings.HasPrefix(rest, "ms"):
			unit, rest = time.Millisecond, rest[2:]
		case strings.HasPrefix(rest, "s"):
			unit, rest = time.Second, rest[1:]
		case strings.HasPrefix(rest, "m"):
			unit, rest = time.Minute, rest[1:]
		case strings.HasPrefix(rest, "h"):
			unit, rest = time.Hour, rest[1:]
		case strings.HasPrefix(rest, "d"):
			unit, rest = 24*time.Hour, rest[1:]
		case strings.HasPrefix(rest, "w"):
			unit, rest = 7*24*time.Hour, rest[1:]
		case strings.HasPrefix(rest, "y"):
			unit, rest = 365*24*time.Hour, rest[1:]
		default:
			return 0, fmt.Errorf("render: %q is not a duration", s)
		}
		total += time.Duration(n) * unit
	}
	return total, nil
}
