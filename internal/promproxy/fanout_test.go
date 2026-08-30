// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package promproxy

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/fleet"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/promapi"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/registry"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/tunnel"
)

// resultIDs projects the cluster ids of a fan-out, which is what proves the
// ordering is the input's and not the completion order.
func resultIDs(rs []FanoutResult) []string {
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = r.ClusterID
	}
	return out
}

func TestFanoutOrderingIsDeterministic(t *testing.T) {
	t.Parallel()

	clusters := []string{"a", "b", "c", "d", "e", "f"}
	f := newFixture(t, Options{MaxInflightPerCluster: 4}, clusters...)

	// Answer in reverse order of the input so that completion order and input
	// order cannot be confused for one another.
	for i, id := range clusters {
		delay := time.Duration(len(clusters)-i) * 5 * time.Millisecond
		body := []byte(`{"cluster":"` + id + `"}`)
		f.session(t, id).doFn = func(ctx context.Context, _ int, _ *tunnel.Request) (*tunnel.Response, error) {
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			return jsonResponse(200, body), nil
		}
	}

	got := f.proxy.Fanout(context.Background(), allowAll(), clusters, queryCall(""), 6)

	if diff := cmp.Diff(clusters, resultIDs(got)); diff != "" {
		t.Errorf("fan-out order (-want +got):\n%s", diff)
	}
	for i, r := range got {
		if r.Err != nil {
			t.Errorf("cluster %s: %v", r.ClusterID, r.Err)
			continue
		}
		want := `{"cluster":"` + clusters[i] + `"}`
		if string(r.Result.Body) != want {
			t.Errorf("slot %d holds %s, want %s", i, r.Result.Body, want)
		}
	}
	for _, id := range clusters {
		f.budgetsAreClean(t, id)
	}
}

func TestFanoutPartialFailure(t *testing.T) {
	t.Parallel()

	f := newFixture(t, Options{}, "ok", "broken", "denied")
	f.session(t, "broken").doFn = func(context.Context, int, *tunnel.Request) (*tunnel.Response, error) {
		return nil, errBoom
	}

	p := allowAll()
	p.Scope.Clusters = fleet.ClusterScope{Allow: []string{"*"}, Deny: []string{"denied"}}

	ids := []string{"ok", "broken", "denied", "ghost"}
	got := f.proxy.Fanout(context.Background(), p, ids, queryCall(""), 4)

	if diff := cmp.Diff(ids, resultIDs(got)); diff != "" {
		t.Errorf("fan-out order (-want +got):\n%s", diff)
	}
	// One cluster failing must cost the caller nothing but that cluster.
	if got[0].Err != nil || got[0].Result == nil {
		t.Errorf("the healthy cluster returned %v / %v", got[0].Result, got[0].Err)
	}
	if !errors.Is(got[1].Err, ErrUpstream) || got[1].Result != nil {
		t.Errorf("broken: err = %v, result = %v, want ErrUpstream and no result", got[1].Err, got[1].Result)
	}
	if !errors.Is(got[2].Err, ErrForbidden) {
		t.Errorf("denied: err = %v, want ErrForbidden", got[2].Err)
	}
	if !errors.Is(got[3].Err, registry.ErrUnknownCluster) {
		t.Errorf("ghost: err = %v, want registry.ErrUnknownCluster", got[3].Err)
	}
	for _, id := range []string{"ok", "broken"} {
		f.budgetsAreClean(t, id)
	}
}

func TestFanoutBoundsConcurrency(t *testing.T) {
	t.Parallel()

	clusters := []string{"a", "b", "c", "d", "e", "f", "g", "h"}
	f := newFixture(t, Options{}, clusters...)

	var live, peak atomic.Int64
	for _, id := range clusters {
		f.session(t, id).doFn = func(ctx context.Context, _ int, _ *tunnel.Request) (*tunnel.Response, error) {
			n := live.Add(1)
			for {
				p := peak.Load()
				if n <= p || peak.CompareAndSwap(p, n) {
					break
				}
			}
			time.Sleep(20 * time.Millisecond)
			live.Add(-1)
			return jsonResponse(200, []byte(`{}`)), nil
		}
	}

	tests := []struct {
		name        string
		concurrency int
		wantPeak    int64
	}{
		{name: "explicit bound", concurrency: 3, wantPeak: 3},
		{name: "one at a time", concurrency: 1, wantPeak: 1},
		{name: "non-positive uses the default", concurrency: 0, wantPeak: DefaultFanoutConcurrency},
		{name: "bounded by the input size", concurrency: 100, wantPeak: int64(len(clusters))},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			peak.Store(0)
			got := f.proxy.Fanout(context.Background(), allowAll(), clusters, queryCall(""), tc.concurrency)
			for _, r := range got {
				if r.Err != nil {
					t.Fatalf("cluster %s: %v", r.ClusterID, r.Err)
				}
			}
			if p := peak.Load(); p > tc.wantPeak {
				t.Errorf("peak concurrency = %d, want at most %d", p, tc.wantPeak)
			}
		})
	}
}

// TestFanoutPerClusterTimeout: the timeout on the Call bounds each cluster on
// its own, so one hung spoke does not consume the whole fan-out's patience.
func TestFanoutPerClusterTimeout(t *testing.T) {
	t.Parallel()

	f := newFixture(t, Options{}, "fast", "hung")
	f.session(t, "hung").doFn = func(ctx context.Context, _ int, _ *tunnel.Request) (*tunnel.Response, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}

	call := queryCall("")
	call.Timeout = 100 * time.Millisecond

	start := time.Now()
	got := f.proxy.Fanout(context.Background(), allowAll(), []string{"fast", "hung"}, call, 2)
	elapsed := time.Since(start)

	if got[0].Err != nil {
		t.Errorf("fast: %v", got[0].Err)
	}
	if !errors.Is(got[1].Err, context.DeadlineExceeded) {
		t.Errorf("hung: err = %v, want context.DeadlineExceeded", got[1].Err)
	}
	if elapsed > 3*time.Second {
		t.Errorf("the fan-out took %s; the per-cluster timeout is not bounding it", elapsed)
	}
	if diff := cmp.Diff([]error{context.DeadlineExceeded}, f.session(t, "hung").contextErrors(),
		errorIs()); diff != "" {
		t.Errorf("the hung spoke's observed context error (-want +got):\n%s", diff)
	}
	f.budgetsAreClean(t, "fast")
	f.budgetsAreClean(t, "hung")
}

// errorIs compares errors by errors.Is, which is what the house style asserts
// on rather than message equality.
func errorIs() cmp.Option {
	return cmp.Comparer(func(a, b error) bool {
		return errors.Is(a, b) || errors.Is(b, a)
	})
}

func TestFanoutParentCancellationCancelsEverySubCall(t *testing.T) {
	t.Parallel()

	clusters := []string{"a", "b", "c", "d", "e", "f"}
	f := newFixture(t, Options{}, clusters...)

	entered := make(chan struct{}, len(clusters))
	for _, id := range clusters {
		f.session(t, id).doFn = func(ctx context.Context, _ int, _ *tunnel.Request) (*tunnel.Response, error) {
			entered <- struct{}{}
			<-ctx.Done()
			return nil, ctx.Err()
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan []FanoutResult, 1)
	go func() {
		done <- f.proxy.Fanout(ctx, allowAll(), clusters, queryCall(""), 2)
	}()

	// Wait until the bound is saturated, so there are both in-flight clusters
	// and clusters that were never started.
	for range 2 {
		select {
		case <-entered:
		case <-time.After(3 * time.Second):
			t.Fatal("the fan-out never reached the spokes")
		}
	}
	cancel()

	var got []FanoutResult
	select {
	case got = <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Fanout did not return after its parent was cancelled")
	}

	if diff := cmp.Diff(clusters, resultIDs(got)); diff != "" {
		t.Errorf("fan-out order (-want +got):\n%s", diff)
	}
	for _, r := range got {
		if !errors.Is(r.Err, context.Canceled) {
			t.Errorf("cluster %s: err = %v, want context.Canceled", r.ClusterID, r.Err)
		}
	}
	// The clusters that had a call in flight must have seen the cancellation,
	// not merely had their results discarded: the query has to stop inside the
	// remote cluster.
	cancelled := 0
	for _, id := range clusters {
		for _, err := range f.session(t, id).contextErrors() {
			if errors.Is(err, context.Canceled) {
				cancelled++
			}
		}
		f.budgetsAreClean(t, id)
	}
	if cancelled < 2 {
		t.Errorf("%d spokes observed cancellation, want at least the two in flight", cancelled)
	}
}

func TestFanoutEdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("no clusters", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, Options{}, "a")
		if got := f.proxy.Fanout(context.Background(), allowAll(), nil, queryCall(""), 4); got != nil {
			t.Errorf("Fanout(nil) = %v, want nil", got)
		}
		if got := f.proxy.Fanout(context.Background(), allowAll(), []string{}, queryCall(""), 4); got != nil {
			t.Errorf("Fanout(empty) = %v, want nil", got)
		}
	})

	t.Run("an already cancelled parent dispatches nothing", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, Options{}, "a", "b")
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		got := f.proxy.Fanout(ctx, allowAll(), []string{"a", "b"}, queryCall(""), 2)
		if diff := cmp.Diff([]string{"a", "b"}, resultIDs(got)); diff != "" {
			t.Errorf("fan-out order (-want +got):\n%s", diff)
		}
		for _, r := range got {
			if !errors.Is(r.Err, context.Canceled) {
				t.Errorf("cluster %s: err = %v, want context.Canceled", r.ClusterID, r.Err)
			}
		}
		for _, id := range []string{"a", "b"} {
			if calls := f.session(t, id).observed(); len(calls) != 0 {
				t.Errorf("cluster %s was dialled on a cancelled context: %v", id, calls)
			}
		}
	})

	t.Run("Call.ClusterID is overwritten per cluster", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, Options{}, "a", "b")
		call := queryCall("ignored-and-nonexistent")

		got := f.proxy.Fanout(context.Background(), allowAll(), []string{"a", "b"}, call, 2)
		for _, r := range got {
			if r.Err != nil {
				t.Errorf("cluster %s: %v", r.ClusterID, r.Err)
			}
		}
		if call.ClusterID != "ignored-and-nonexistent" {
			t.Errorf("the caller's Call was mutated: ClusterID = %q", call.ClusterID)
		}
	})

	t.Run("duplicate ids each get their own slot", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, Options{}, "a")
		ids := []string{"a", "a", "a"}

		got := f.proxy.Fanout(context.Background(), allowAll(), ids, queryCall(""), 2)
		if diff := cmp.Diff(ids, resultIDs(got)); diff != "" {
			t.Errorf("fan-out order (-want +got):\n%s", diff)
		}
		if n := len(f.session(t, "a").observed()); n != 3 {
			t.Errorf("the spoke saw %d calls, want one per occurrence", n)
		}
	})

	t.Run("the endpoint is carried into the per-cluster failure", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, Options{}, "a")
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		call := Call{Endpoint: promapi.EndpointQueryRange, Form: validForm(promapi.EndpointQueryRange)}
		got := f.proxy.Fanout(ctx, allowAll(), []string{"a"}, call, 1)
		if want := "cluster a query_range: context canceled"; got[0].Err.Error() != want {
			t.Errorf("err = %q, want %q", got[0].Err.Error(), want)
		}
	})
}
