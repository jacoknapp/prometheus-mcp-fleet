// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package spoke

import (
	"context"
	"errors"
	"math/rand/v2"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/tunnel/grpctun"
)

// prometheusRegistry is the small slice of the Prometheus registry this package
// needs. Naming it locally keeps the composition root honest about what it
// actually uses.
type prometheusRegistry = *prometheus.Registry

// jitter returns d scaled by a random factor in [0.9, 1.1). It exists so that
// periodic work across a fleet does not converge on the same instant.
func jitter(d time.Duration) time.Duration {
	if d <= 0 {
		return d
	}
	return time.Duration(float64(d) * (0.9 + rand.Float64()*0.2)) //nolint:gosec // jitter, not a secret
}

// fullJitter returns a backoff delay of rand(0, min(max, base*2^attempt)).
//
// Full jitter rather than exponential-with-jitter: with ~100 spokes retrying
// against a hub that has just restarted, anything that preserves a common
// component reconverges the fleet into a burst. Full jitter spreads them
// uniformly across the window, which is the whole point.
func fullJitter(base, max time.Duration, attempt int) time.Duration {
	if base <= 0 {
		base = 500 * time.Millisecond
	}
	if max <= 0 || max < base {
		max = 30 * time.Second
	}
	window := base
	for range attempt {
		window *= 2
		if window >= max {
			window = max
			break
		}
	}
	return time.Duration(rand.Int64N(int64(window)) + int64(base)/4) //nolint:gosec // backoff, not a secret
}

// sleepCtx waits for d and reports whether it completed rather than being
// cancelled.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// classify reduces a dial error to one of a closed set of metric label values.
// The set is closed deliberately: an unbounded reason label on a reconnect
// counter is exactly the cardinality mistake this project exists to avoid.
//
// The transport already classifies its own failures — that is what
// grpctun.Reason is — so a *grpctun.DialError is believed outright. The string
// matching below is the fallback for the few errors that come from somewhere
// else, and it is not where new cases should be added.
func classify(err error) string {
	var de *grpctun.DialError
	if errors.As(err, &de) && de.Reason != "" {
		return string(de.Reason)
	}

	switch {
	case err == nil:
		return "closed"
	case errors.Is(err, context.Canceled):
		return "context-cancelled"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	}

	msg := err.Error()
	switch {
	case strings.Contains(msg, "certificate"), strings.Contains(msg, "tls:"),
		strings.Contains(msg, "x509"):
		return "tls-handshake"
	case strings.Contains(msg, "connection refused"),
		strings.Contains(msg, "no such host"),
		strings.Contains(msg, "i/o timeout"):
		return "dial"
	case strings.Contains(msg, "EOF"), strings.Contains(msg, "connection reset"):
		return "conn-closed"
	case strings.Contains(msg, "shutdown"), strings.Contains(msg, "draining"):
		return "server-shutdown"
	default:
		return "other"
	}
}
