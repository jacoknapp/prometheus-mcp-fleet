// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package promproxy

import (
	"errors"
	"fmt"
	"time"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/tunnel"
)

// Sentinels every failure from this package maps onto. Callers branch on these
// with errors.Is, and internal/mcptools turns them into stable machine codes.
var (
	// ErrForbidden reports that the principal's scope does not permit the
	// call. It is returned identically for a cluster that does not exist, so
	// that a denial cannot be used to enumerate the fleet.
	ErrForbidden = errors.New("promproxy: forbidden")
	// ErrTooLarge reports that a response hit the byte cap and was truncated.
	// The [Result] is still returned alongside it, holding the bytes read so
	// far; that body is not valid JSON.
	ErrTooLarge = errors.New("promproxy: response exceeded the byte budget")
	// ErrBusy reports that a concurrency or memory budget is exhausted. It is
	// always carried by a [BusyError], which names the budget and a retry
	// hint. Retrying is reasonable; retrying immediately is not.
	ErrBusy = errors.New("promproxy: busy")
	// ErrUpstream reports that the cluster's Prometheus, or the tunnel to it,
	// failed. A Prometheus HTTP error status is *not* an ErrUpstream: a 400
	// with a PromQL parse error is a successful round trip and is returned as
	// a [Result] so the caller can pass the server's own message through.
	ErrUpstream = errors.New("promproxy: upstream failure")
)

// Retry hints attached to a [BusyError]. They are advisory: the hub has no way
// to know when a slot will free, and a caller that ignores them is only
// rate-limited by the same semaphore again.
const (
	// ClusterBusyRetryAfter is suggested when a cluster's in-flight slots are
	// full. In-flight queries are bounded by the query timeout, so a slot
	// frees soon.
	ClusterBusyRetryAfter = 500 * time.Millisecond
	// HubBusyRetryAfter is suggested when the hub-wide response budget is
	// exhausted. This is a whole-hub condition, so back off harder.
	HubBusyRetryAfter = 2 * time.Second
)

// BusyError names which budget refused a call. Recover it with errors.As.
type BusyError struct {
	// ClusterID is the target cluster. It is set for both budgets, because
	// even a hub-wide refusal is most useful reported against the call that
	// hit it.
	ClusterID string
	// Budget is "cluster-inflight" or "hub-response-bytes".
	Budget string
	// Limit is the exhausted budget's configured ceiling: a count of in-flight
	// requests, or a number of bytes.
	Limit int64
	// RetryAfter is how long the caller should wait before retrying.
	RetryAfter time.Duration
}

// Error implements error.
func (e *BusyError) Error() string {
	return fmt.Sprintf("cluster %s: %s budget exhausted (limit %d), retry after %s",
		e.ClusterID, e.Budget, e.Limit, e.RetryAfter)
}

// Unwrap reports [ErrBusy].
func (e *BusyError) Unwrap() error { return ErrBusy }

// NotConnectedError reports a cluster the registry knows about but whose spoke
// currently holds no tunnel. It carries the last contact time because "was
// here 30 seconds ago" and "was here yesterday" call for entirely different
// next actions from an agent, and neither is the same as "no such cluster".
type NotConnectedError struct {
	// ClusterID is the cluster that could not be reached.
	ClusterID string
	// LastSeen is when the hub last had contact with the spoke. It is the zero
	// time when the hub never has.
	LastSeen time.Time
	// Since is how long ago LastSeen was, measured on the proxy's clock.
	Since time.Duration
}

// Error implements error.
func (e *NotConnectedError) Error() string {
	if e.LastSeen.IsZero() {
		return fmt.Sprintf(
			"cluster %s is enrolled but its spoke is not connected; never seen", e.ClusterID)
	}
	return fmt.Sprintf(
		"cluster %s is enrolled but its spoke is not connected; last seen %s (%s ago)",
		e.ClusterID, e.LastSeen.UTC().Format(time.RFC3339), e.Since.Truncate(time.Second))
}

// Unwrap reports both [tunnel.ErrNotConnected], for a caller asking "can I
// route to this cluster", and [ErrUpstream], for a caller asking "did this
// call fail beyond the hub". Both questions have the same answer here and a
// caller should not have to know which sentinel the routing layer chose.
func (e *NotConnectedError) Unwrap() []error {
	return []error{tunnel.ErrNotConnected, ErrUpstream}
}
