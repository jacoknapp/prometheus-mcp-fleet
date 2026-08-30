// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package promproxy

import (
	"context"
	"fmt"
	"sync"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/fleet"
)

// FanoutResult is one cluster's outcome inside a [Proxy.Fanout]. Exactly one of
// Result and Err is nil, except for a response cut at the byte cap, which
// carries both: the partial body and [ErrTooLarge].
type FanoutResult struct {
	// ClusterID is the cluster this outcome belongs to. It is always set, even
	// when the call never left the hub, so a caller can report a per-cluster
	// failure without correlating by index.
	ClusterID string
	// Result is the completed round trip, or nil when the call failed.
	Result *Result
	// Err is the failure, or nil. It carries the same sentinels [Proxy.Do]
	// returns, so a caller classifies each cluster's outcome the same way.
	Err error
}

// Fanout performs the same call against many clusters and returns one
// [FanoutResult] per input cluster, in the input's order.
//
// Failure is per cluster, never global. One cluster being forbidden, unknown,
// disconnected, busy or slow yields an Err in its own slot and changes nothing
// about the others — an agent asking "which of my 40 clusters is firing this
// alert" must not lose 39 answers because one spoke is down.
//
// Ordering is deterministic and independent of completion order: slot i always
// describes clusterIDs[i], so a caller can zip the results against its own
// input and a golden test is stable. Duplicate IDs are not collapsed; each
// occurrence is called and reported separately, because collapsing would make
// the result slice a different length from the input and silently break that
// correspondence.
//
// concurrency bounds how many clusters are in flight at once; a non-positive
// value uses [DefaultFanoutConcurrency]. The bound matters beyond politeness:
// each in-flight call reserves its worst-case size against the hub-wide byte
// budget, so an unbounded fan-out over a hundred clusters would exhaust that
// budget and start returning [ErrBusy] to unrelated callers.
//
// call.ClusterID is ignored and overwritten per cluster. call.Timeout is the
// per-cluster timeout, clamped by [Proxy.Do] exactly as it is for a single
// call; there is no separate whole-fan-out deadline here, because that belongs
// to ctx and the caller owns it.
//
// Cancelling ctx cancels every in-flight sub-call — the same context is passed
// down, so the query is aborted inside each remote cluster rather than merely
// abandoned — and clusters not yet started are reported with ctx's error rather
// than dialled.
func (p *Proxy) Fanout(
	ctx context.Context, principal *fleet.Principal, clusterIDs []string,
	call Call, concurrency int,
) []FanoutResult {
	if len(clusterIDs) == 0 {
		return nil
	}
	if concurrency <= 0 {
		concurrency = DefaultFanoutConcurrency
	}
	concurrency = min(concurrency, len(clusterIDs))

	out := make([]FanoutResult, len(clusterIDs))
	slots := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for i, id := range clusterIDs {
		if !acquireSlot(ctx, slots) {
			// The parent is gone. Report the clusters we have not started
			// against ctx rather than dialling them; the ones already running
			// observe the same cancellation and fill their own slots.
			err := ctx.Err()
			for j := i; j < len(clusterIDs); j++ {
				out[j] = FanoutResult{
					ClusterID: clusterIDs[j],
					Err: fmt.Errorf("cluster %s %s: %w",
						clusterIDs[j], call.Endpoint, err),
				}
			}
			wg.Wait()
			return out
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-slots }()
			sub := call
			sub.ClusterID = id
			res, err := p.Do(ctx, principal, sub)
			out[i] = FanoutResult{ClusterID: id, Result: res, Err: err}
		}()
	}
	wg.Wait()
	return out
}

// acquireSlot takes one concurrency slot, preferring ctx's cancellation over
// starting more work. The ctx.Err check is not redundant with the select: a
// select whose send and whose <-ctx.Done() are both ready picks between them at
// random, so without it a fan-out on an already-cancelled context would still
// dispatch a cluster or two.
func acquireSlot(ctx context.Context, slots chan struct{}) bool {
	if ctx.Err() != nil {
		return false
	}
	select {
	case slots <- struct{}{}:
		return true
	case <-ctx.Done():
		return false
	}
}
