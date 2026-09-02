// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package promproxy

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/fleet"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/promapi"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/registry"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/tunnel"
)

func TestNewValidatesOptions(t *testing.T) {
	t.Parallel()

	reg, err := registry.New(registry.Options{FactsPollInterval: time.Hour})
	if err != nil {
		t.Fatalf("registry.New: %v", err)
	}

	tests := []struct {
		name    string
		opts    Options
		wantErr string
		check   func(t *testing.T, p *Proxy)
	}{
		{name: "registry is required", opts: Options{}, wantErr: "registry is required"},
		{
			name: "defaults",
			opts: Options{Registry: reg},
			check: func(t *testing.T, p *Proxy) {
				want := Proxy{
					defaultTimeout:   DefaultTimeout,
					maxTimeout:       DefaultMaxTimeout,
					maxResponseBytes: DefaultMaxResponseBytes,
					maxInflight:      DefaultMaxInflightPerCluster,
				}
				if p.defaultTimeout != want.defaultTimeout || p.maxTimeout != want.maxTimeout ||
					p.maxResponseBytes != want.maxResponseBytes || p.maxInflight != want.maxInflight {
					t.Errorf("defaults = %s/%s/%d/%d", p.defaultTimeout, p.maxTimeout,
						p.maxResponseBytes, p.maxInflight)
				}
				if p.bytes.capacity != DefaultGlobalResponseBudget {
					t.Errorf("global budget = %d, want %d", p.bytes.capacity, DefaultGlobalResponseBudget)
				}
				if _, ok := p.metrics.(NopMetrics); !ok {
					t.Errorf("default metrics = %T, want NopMetrics", p.metrics)
				}
				if p.log == nil || p.now == nil {
					t.Error("New left a nil logger or clock")
				}
			},
		},
		{
			name:    "negative timeout",
			opts:    Options{Registry: reg, DefaultTimeout: -1},
			wantErr: "timeouts must not be negative",
		},
		{
			name:    "negative max timeout",
			opts:    Options{Registry: reg, MaxTimeout: -1},
			wantErr: "timeouts must not be negative",
		},
		{
			name:    "negative response cap",
			opts:    Options{Registry: reg, MaxResponseBytes: -1},
			wantErr: "byte budgets must not be negative",
		},
		{
			name:    "negative global budget",
			opts:    Options{Registry: reg, GlobalResponseBudget: -1},
			wantErr: "byte budgets must not be negative",
		},
		{
			name:    "negative in-flight cap",
			opts:    Options{Registry: reg, MaxInflightPerCluster: -1},
			wantErr: "must not be negative",
		},
		{
			// A per-response cap larger than the whole budget means no maximum
			// sized call could ever be admitted, which would look like a hang.
			name:    "global budget smaller than the per-response cap",
			opts:    Options{Registry: reg, MaxResponseBytes: 1 << 20, GlobalResponseBudget: 1 << 10},
			wantErr: "smaller than the per-response cap",
		},
		{
			name:    "default timeout above the ceiling",
			opts:    Options{Registry: reg, DefaultTimeout: time.Hour, MaxTimeout: time.Minute},
			wantErr: "exceeds max timeout",
		},
		{
			// "exceeds" is a strict comparison. A deployment that pins both
			// knobs to the same value is asking every call to be allowed the
			// full ceiling by default, which is a coherent thing to want and
			// must not be refused as a misconfiguration.
			name: "default timeout equal to the ceiling is not an excess",
			opts: Options{Registry: reg, DefaultTimeout: time.Minute, MaxTimeout: time.Minute},
			check: func(t *testing.T, p *Proxy) {
				if p.defaultTimeout != time.Minute || p.maxTimeout != time.Minute {
					t.Errorf("timeouts = %s/%s, want 1m/1m", p.defaultTimeout, p.maxTimeout)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p, err := New(tc.opts)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("New error = %v, want it to mention %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			tc.check(t, p)
		})
	}
}

// TestAuthorizationRunsFirst is the disclosure control: a principal that may
// not reach a cluster must not be able to tell, from the error, whether that
// cluster exists.
func TestAuthorizationRunsFirst(t *testing.T) {
	t.Parallel()

	scoped := func(allow ...string) *fleet.Principal {
		p := allowAll()
		p.Scope.Clusters = fleet.ClusterScope{Allow: allow}
		return p
	}

	t.Run("denial is byte-identical for an existing and a ghost cluster", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, Options{}, "prod-eu")
		p := scoped("some-other-cluster")

		_, existsErr := f.proxy.Do(context.Background(), p, queryCall("prod-eu"))
		_, ghostErr := f.proxy.Do(context.Background(), p, queryCall("ghost"))

		for name, err := range map[string]error{"existing": existsErr, "ghost": ghostErr} {
			if !errors.Is(err, ErrForbidden) {
				t.Errorf("%s cluster: error = %v, want ErrForbidden", name, err)
			}
			if errors.Is(err, registry.ErrUnknownCluster) {
				t.Errorf("%s cluster: error = %v leaks whether the cluster exists", name, err)
			}
		}
		// The only difference permitted between the two messages is the id the
		// caller itself supplied.
		normalise := func(err error, id string) string {
			return strings.ReplaceAll(err.Error(), id, "<id>")
		}
		if got, want := normalise(ghostErr, "ghost"), normalise(existsErr, "prod-eu"); got != want {
			t.Errorf("denial messages differ:\n existing: %s\n ghost:    %s", want, got)
		}
		if got := f.session(t, "prod-eu").observed(); len(got) != 0 {
			t.Errorf("a denied call reached the spoke: %v", got)
		}
		if diff := cmp.Diff([]string{CodeForbidden, CodeForbidden}, f.metrics.codes()); diff != "" {
			t.Errorf("metric codes (-want +got):\n%s", diff)
		}
	})

	t.Run("a label selector denies existing and ghost clusters alike", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, Options{}, "prod-eu")
		p := allowAll()
		p.Scope.Clusters = fleet.ClusterScope{MatchLabels: map[string]string{"env": "canary"}}

		// prod-eu is labelled env=prod, so its labels fail the selector; the
		// ghost contributes no labels and fails it the same way.
		for _, id := range []string{"prod-eu", "ghost"} {
			if _, err := f.proxy.Do(context.Background(), p, queryCall(id)); !errors.Is(err, ErrForbidden) {
				t.Errorf("Do(%s) error = %v, want ErrForbidden", id, err)
			}
		}
	})

	t.Run("deny beats allow", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, Options{}, "prod-eu")
		p := allowAll()
		p.Scope.Clusters = fleet.ClusterScope{Allow: []string{"*"}, Deny: []string{"prod-eu"}}

		if _, err := f.proxy.Do(context.Background(), p, queryCall("prod-eu")); !errors.Is(err, ErrForbidden) {
			t.Errorf("Do error = %v, want ErrForbidden", err)
		}
	})

	t.Run("a nil principal authorizes nothing", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, Options{}, "prod-eu")
		if _, err := f.proxy.Do(context.Background(), nil, queryCall("prod-eu")); !errors.Is(err, ErrForbidden) {
			t.Errorf("Do(nil principal) error = %v, want ErrForbidden", err)
		}
		p := &fleet.Principal{KID: "k"} // authenticated but unscoped
		if _, err := f.proxy.Do(context.Background(), p, queryCall("prod-eu")); !errors.Is(err, ErrForbidden) {
			t.Errorf("Do(unscoped principal) error = %v, want ErrForbidden", err)
		}
	})

	t.Run("denial precedes parameter validation", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, Options{}, "prod-eu")
		call := queryCall("prod-eu")
		call.Form = url.Values{"not_a_parameter": {"x"}}
		call.Endpoint = "no_such_endpoint"

		_, err := f.proxy.Do(context.Background(), scoped("nothing"), call)
		if !errors.Is(err, ErrForbidden) {
			t.Fatalf("error = %v, want ErrForbidden", err)
		}
		if errors.Is(err, promapi.ErrInvalidParam) || errors.Is(err, promapi.ErrUnknownEndpoint) {
			t.Errorf("error = %v: an unauthorized caller learned its arguments were invalid", err)
		}
	})

	t.Run("an authorized caller learns the cluster is unknown", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, Options{}, "prod-eu")

		_, err := f.proxy.Do(context.Background(), allowAll(), queryCall("ghost"))
		if !errors.Is(err, registry.ErrUnknownCluster) {
			t.Fatalf("error = %v, want registry.ErrUnknownCluster", err)
		}
		if errors.Is(err, ErrForbidden) {
			t.Errorf("error = %v, want a distinct unknown-cluster failure", err)
		}
		if got := f.metrics.lastCode(t); got != CodeUnavailable {
			t.Errorf("metric code = %q, want %q", got, CodeUnavailable)
		}
	})

	t.Run("an empty cluster id is a parameter error", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, Options{}, "prod-eu")
		_, err := f.proxy.Do(context.Background(), allowAll(), queryCall(""))
		if !errors.Is(err, promapi.ErrInvalidParam) {
			t.Fatalf("error = %v, want promapi.ErrInvalidParam", err)
		}
		if got := f.metrics.lastCode(t); got != CodeInvalid {
			t.Errorf("metric code = %q, want %q", got, CodeInvalid)
		}
	})
}

// TestCallerCannotSupplyAPath is the structural half of security invariant 9.
// The assertion is not that a bad path is rejected but that there is nowhere to
// put one.
func TestCallerCannotSupplyAPath(t *testing.T) {
	t.Parallel()

	t.Run("Call has no path-shaped field", func(t *testing.T) {
		t.Parallel()
		ct := reflect.TypeFor[Call]()
		for i := range ct.NumField() {
			name := strings.ToLower(ct.Field(i).Name)
			for _, banned := range []string{"path", "url", "uri", "host", "addr", "method"} {
				if strings.Contains(name, banned) {
					t.Errorf("Call.%s exists; the upstream path must come only from promapi",
						ct.Field(i).Name)
				}
			}
		}
	})

	t.Run("every endpoint routes through BuildPath", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, Options{EnableStatusConfig: true}, "prod-eu")
		s := f.session(t, "prod-eu")

		for _, e := range promapi.Endpoints() {
			route, err := promapi.Get(e)
			if err != nil {
				t.Fatalf("promapi.Get(%s): %v", e, err)
			}
			call := Call{ClusterID: "prod-eu", Endpoint: e, Form: validForm(e)}
			if route.HasPathParam() {
				call.LabelName = "job"
			}
			if _, err := f.proxy.Do(context.Background(), allowAll(), call); err != nil {
				t.Fatalf("Do(%s): %v", e, err)
			}

			wantPath, err := promapi.BuildPath(e, call.LabelName)
			if err != nil {
				t.Fatalf("promapi.BuildPath(%s): %v", e, err)
			}
			got := s.lastCall(t)
			if got.Path != wantPath {
				t.Errorf("endpoint %s: path = %q, want %q", e, got.Path, wantPath)
			}
			if got.Method != route.Method {
				t.Errorf("endpoint %s: method = %q, want %q", e, got.Method, route.Method)
			}
			// Re-validating on the spoke must resolve the same route; that is
			// the property the second check on the far side depends on.
			if r2, label, ok := promapi.Lookup(got.Method, got.Path); !ok || r2.Endpoint != e {
				t.Errorf("endpoint %s: the spoke would not resolve %q %q", e, got.Method, got.Path)
			} else if route.HasPathParam() && label != "job" {
				t.Errorf("endpoint %s: label round-tripped as %q", e, label)
			}
		}
	})

	t.Run("validation failures never reach the spoke", func(t *testing.T) {
		t.Parallel()
		tests := []struct {
			name    string
			call    Call
			wantErr error
		}{
			{
				name:    "unknown endpoint",
				call:    Call{ClusterID: "prod-eu", Endpoint: "delete_series"},
				wantErr: promapi.ErrUnknownEndpoint,
			},
			{
				name: "path traversal in the label name",
				call: Call{
					ClusterID: "prod-eu", Endpoint: promapi.EndpointLabelValues,
					LabelName: "../../../api/v1/admin/tsdb/delete_series",
				},
				wantErr: promapi.ErrInvalidLabelName,
			},
			{
				name: "a label name on an endpoint that takes none",
				call: Call{
					ClusterID: "prod-eu", Endpoint: promapi.EndpointQuery,
					LabelName: "job", Form: url.Values{"query": {"up"}},
				},
				wantErr: promapi.ErrInvalidParam,
			},
			{
				name: "unknown parameter",
				call: Call{
					ClusterID: "prod-eu", Endpoint: promapi.EndpointQuery,
					Form: url.Values{"query": {"up"}, "sneaky": {"1"}},
				},
				wantErr: promapi.ErrInvalidParam,
			},
			{
				name:    "missing required parameter",
				call:    Call{ClusterID: "prod-eu", Endpoint: promapi.EndpointQuery},
				wantErr: promapi.ErrInvalidParam,
			},
			{
				name:    "gated endpoint",
				call:    Call{ClusterID: "prod-eu", Endpoint: promapi.EndpointConfig},
				wantErr: promapi.ErrEndpointGated,
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				f := newFixture(t, Options{}, "prod-eu")
				_, err := f.proxy.Do(context.Background(), allowAll(), tc.call)
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("error = %v, want %v", err, tc.wantErr)
				}
				if got := f.session(t, "prod-eu").observed(); len(got) != 0 {
					t.Errorf("an invalid call reached the spoke: %v", got)
				}
				if got := f.metrics.lastCode(t); got != CodeInvalid {
					t.Errorf("metric code = %q, want %q", got, CodeInvalid)
				}
				f.budgetsAreClean(t, "prod-eu")
			})
		}
	})

	t.Run("the gate on status/config is the only thing that opens it", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, Options{EnableStatusConfig: true}, "prod-eu")
		call := Call{ClusterID: "prod-eu", Endpoint: promapi.EndpointConfig}
		if _, err := f.proxy.Do(context.Background(), allowAll(), call); err != nil {
			t.Fatalf("Do: %v", err)
		}
		if got := f.session(t, "prod-eu").lastCall(t).Path; got != "/api/v1/status/config" {
			t.Errorf("path = %q", got)
		}
	})
}

// validForm returns a minimal valid parameter set for an endpoint.
func validForm(e promapi.Endpoint) url.Values {
	switch e {
	case promapi.EndpointQuery:
		return url.Values{"query": {"up"}}
	case promapi.EndpointQueryRange:
		return url.Values{
			"query": {"up"}, "start": {"1756000000"}, "end": {"1756003600"}, "step": {"1m"},
		}
	case promapi.EndpointQueryExemplars:
		// Same required-parameter shape as its query siblings; added when the
		// endpoint was, so this table stays exhaustive.
		return url.Values{"query": {"up"}, "start": {"1756000000"}, "end": {"1756003600"}}
	case promapi.EndpointSeries:
		return url.Values{"match[]": {`up{job="api"}`}}
	default:
		return nil
	}
}

func TestEffectiveTimeout(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		defaultTimeout time.Duration
		maxTimeout     time.Duration
		limit          time.Duration
		want           time.Duration
		call           time.Duration
	}{
		{
			name:           "the caller's request is honoured when it is the tightest",
			defaultTimeout: 30 * time.Second, maxTimeout: 120 * time.Second,
			call: 10 * time.Second, want: 10 * time.Second,
		},
		{
			name:           "no request uses the hub default",
			defaultTimeout: 30 * time.Second, maxTimeout: 120 * time.Second,
			want: 30 * time.Second,
		},
		{
			name:           "a negative request uses the hub default",
			defaultTimeout: 30 * time.Second, maxTimeout: 120 * time.Second,
			call: -5 * time.Second, want: 30 * time.Second,
		},
		{
			name:           "the caller cannot exceed MaxTimeout",
			defaultTimeout: 30 * time.Second, maxTimeout: 40 * time.Second,
			call: 300 * time.Second, want: 40 * time.Second,
		},
		{
			name:           "the principal's limit tightens the caller's request",
			defaultTimeout: 30 * time.Second, maxTimeout: 120 * time.Second,
			call: 60 * time.Second, limit: 5 * time.Second, want: 5 * time.Second,
		},
		{
			name:           "the hub default wins when it is tighter than the principal's limit",
			defaultTimeout: 20 * time.Second, maxTimeout: 120 * time.Second,
			limit: 90 * time.Second, want: 20 * time.Second,
		},
		{
			name:           "a principal limit above MaxTimeout cannot widen it",
			defaultTimeout: 100 * time.Second, maxTimeout: 110 * time.Second,
			call: 500 * time.Second, limit: 500 * time.Second, want: 110 * time.Second,
		},
		{
			name:           "the caller wins when it is tighter than the principal's limit",
			defaultTimeout: 30 * time.Second, maxTimeout: 120 * time.Second,
			call: 7 * time.Second, limit: 45 * time.Second, want: 7 * time.Second,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t, Options{
				DefaultTimeout: tc.defaultTimeout,
				MaxTimeout:     tc.maxTimeout,
			}, "prod-eu")

			call := queryCall("prod-eu")
			call.Timeout = tc.call
			before := time.Now()
			if _, err := f.proxy.Do(context.Background(), withLimits(fleet.Limits{
				Timeout: fleet.Duration(tc.limit),
			}), call); err != nil {
				t.Fatalf("Do: %v", err)
			}

			got := f.session(t, "prod-eu").lastCall(t)
			if !got.HasDeadline {
				t.Fatal("the outgoing request carried no deadline")
			}
			// before is sampled just outside Do, so the observed budget is the
			// clamped timeout plus the scheduling delay in between.
			budget := got.Deadline.Sub(before)
			if budget > tc.want+time.Second || budget < tc.want-time.Second {
				t.Errorf("deadline budget = %s, want ~%s", budget, tc.want)
			}
		})
	}
}

func TestEffectiveMaxBytes(t *testing.T) {
	t.Parallel()

	const hubCap = 1 << 20

	tests := []struct {
		name  string
		call  int64
		limit int64
		want  int64
	}{
		{name: "no request uses the hub cap", want: hubCap},
		{name: "a tighter request is honoured", call: 4096, want: 4096},
		{name: "the caller cannot exceed the hub cap", call: 100 << 20, want: hubCap},
		{name: "the principal's limit tightens the request", call: 4096, limit: 1024, want: 1024},
		{name: "the request wins when it is tighter", call: 512, limit: 4096, want: 512},
		{name: "a principal limit above the hub cap cannot widen it", limit: 100 << 20, want: hubCap},
		{name: "a negative request uses the hub cap", call: -1, want: hubCap},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t, Options{MaxResponseBytes: hubCap}, "prod-eu")
			call := queryCall("prod-eu")
			call.MaxBytes = tc.call
			p := withLimits(fleet.Limits{MaxResponseBytes: tc.limit})

			if _, err := f.proxy.Do(context.Background(), p, call); err != nil {
				t.Fatalf("Do: %v", err)
			}
			if got := f.session(t, "prod-eu").lastCall(t).MaxResponseBytes; got != tc.want {
				t.Errorf("MaxResponseBytes = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestPerClusterInflightRefusesRatherThanQueues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		hubLimit  int
		principal int
		want      int
	}{
		{name: "hub ceiling applies", hubLimit: 3, want: 3},
		{name: "the principal's limit tightens it", hubLimit: 4, principal: 2, want: 2},
		{name: "the principal cannot widen it", hubLimit: 2, principal: 50, want: 2},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t, Options{MaxInflightPerCluster: tc.hubLimit}, "prod-eu")
			s := f.session(t, "prod-eu")

			hold := make(chan struct{})
			s.doFn = func(ctx context.Context, _ int, _ *tunnel.Request) (*tunnel.Response, error) {
				<-hold
				return jsonResponse(200, []byte(`{}`)), nil
			}
			p := withLimits(fleet.Limits{MaxConcurrentPerCluster: tc.principal})

			var wg sync.WaitGroup
			for range tc.want {
				wg.Add(1)
				go func() {
					defer wg.Done()
					if _, err := f.proxy.Do(context.Background(), p, queryCall("prod-eu")); err != nil {
						t.Errorf("Do: %v", err)
					}
				}()
			}
			for range tc.want {
				s.waitEntered(t)
			}

			// The next call must be refused immediately rather than queued: an
			// unbounded queue in front of a slow Prometheus is how one slow
			// cluster becomes hub-wide latency.
			start := time.Now()
			_, err := f.proxy.Do(context.Background(), p, queryCall("prod-eu"))
			elapsed := time.Since(start)

			var busy *BusyError
			if !errors.As(err, &busy) {
				t.Fatalf("error = %v, want a *BusyError", err)
			}
			if !errors.Is(err, ErrBusy) {
				t.Errorf("error = %v, want it to wrap ErrBusy", err)
			}
			want := &BusyError{
				ClusterID:  "prod-eu",
				Budget:     "cluster-inflight",
				Limit:      int64(tc.want),
				RetryAfter: ClusterBusyRetryAfter,
			}
			if diff := cmp.Diff(want, busy); diff != "" {
				t.Errorf("BusyError (-want +got):\n%s", diff)
			}
			if elapsed > time.Second {
				t.Errorf("the refusal took %s; it must not wait for a slot", elapsed)
			}
			if got := f.metrics.lastCode(t); got != CodeBusy {
				t.Errorf("metric code = %q, want %q", got, CodeBusy)
			}
			// The refused call must not consume a byte reservation either.
			if got, want := f.proxy.bytes.available(), f.proxy.bytes.capacity; got >= want {
				t.Logf("byte budget %d of %d is held by the %d in-flight calls", got, want, tc.want)
			}

			close(hold)
			wg.Wait()
			f.budgetsAreClean(t, "prod-eu")

			// A freed slot is reusable, so the refusal really was a refusal and
			// not a leak.
			if _, err := f.proxy.Do(context.Background(), p, queryCall("prod-eu")); err != nil {
				t.Errorf("Do after the burst drained: %v", err)
			}
		})
	}
}

func TestPerClusterInflightIsPerCluster(t *testing.T) {
	t.Parallel()

	f := newFixture(t, Options{MaxInflightPerCluster: 1}, "prod-eu", "prod-us")
	hold := make(chan struct{})
	blocking := func(ctx context.Context, _ int, _ *tunnel.Request) (*tunnel.Response, error) {
		<-hold
		return jsonResponse(200, []byte(`{}`)), nil
	}
	f.session(t, "prod-eu").doFn = blocking

	go func() { _, _ = f.proxy.Do(context.Background(), allowAll(), queryCall("prod-eu")) }()
	f.session(t, "prod-eu").waitEntered(t)

	// A saturated cluster must not refuse calls to a different one.
	if _, err := f.proxy.Do(context.Background(), allowAll(), queryCall("prod-us")); err != nil {
		t.Errorf("Do(prod-us) = %v, want success while prod-eu is saturated", err)
	}
	close(hold)
}

func TestGlobalByteBudget(t *testing.T) {
	t.Parallel()

	t.Run("a waiter proceeds once a permit is returned", func(t *testing.T) {
		t.Parallel()
		const cap = 1 << 20
		f := newFixture(t, Options{
			MaxResponseBytes:      cap,
			GlobalResponseBudget:  cap,
			MaxInflightPerCluster: 4,
		}, "prod-eu")
		s := f.session(t, "prod-eu")

		hold := make(chan struct{})
		s.doFn = func(ctx context.Context, n int, _ *tunnel.Request) (*tunnel.Response, error) {
			if n == 0 {
				<-hold
			}
			return jsonResponse(200, []byte(`{}`)), nil
		}

		first := make(chan struct{})
		go func() {
			defer close(first)
			_, _ = f.proxy.Do(context.Background(), allowAll(), queryCall("prod-eu"))
		}()
		s.waitEntered(t)
		if got := f.proxy.bytes.available(); got != 0 {
			t.Fatalf("available = %d, want the whole budget reserved", got)
		}

		second := make(chan error, 1)
		go func() {
			_, err := f.proxy.Do(context.Background(), allowAll(), queryCall("prod-eu"))
			second <- err
		}()

		select {
		case err := <-second:
			t.Fatalf("the second call did not wait for the budget: %v", err)
		case <-time.After(50 * time.Millisecond):
		}

		close(hold)
		select {
		case err := <-second:
			if err != nil {
				t.Fatalf("the second call failed after the budget freed: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("the second call never obtained the freed budget")
		}
		// The second call returning does not mean the first has: Do releases
		// the byte budget before the in-flight slot (the release defers run in
		// that order), so the waiter can wake and finish while the first call
		// is still between the two. Wait for it before reading the gauges.
		select {
		case <-first:
		case <-time.After(3 * time.Second):
			t.Fatal("the first call never returned")
		}
		f.budgetsAreClean(t, "prod-eu")
	})

	t.Run("a call that cannot fit before its deadline is refused, not queued forever", func(t *testing.T) {
		t.Parallel()
		const cap = 1 << 20
		f := newFixture(t, Options{
			MaxResponseBytes:      cap,
			GlobalResponseBudget:  cap,
			MaxInflightPerCluster: 4,
		}, "prod-eu")
		s := f.session(t, "prod-eu")

		hold := make(chan struct{})
		defer close(hold)
		s.doFn = func(ctx context.Context, n int, _ *tunnel.Request) (*tunnel.Response, error) {
			if n == 0 {
				<-hold
			}
			return jsonResponse(200, []byte(`{}`)), nil
		}
		go func() { _, _ = f.proxy.Do(context.Background(), allowAll(), queryCall("prod-eu")) }()
		s.waitEntered(t)

		call := queryCall("prod-eu")
		call.Timeout = 50 * time.Millisecond
		_, err := f.proxy.Do(context.Background(), allowAll(), call)

		var busy *BusyError
		if !errors.As(err, &busy) {
			t.Fatalf("error = %v, want a *BusyError", err)
		}
		want := &BusyError{
			ClusterID:  "prod-eu",
			Budget:     "hub-response-bytes",
			Limit:      cap,
			RetryAfter: HubBusyRetryAfter,
		}
		if diff := cmp.Diff(want, busy); diff != "" {
			t.Errorf("BusyError (-want +got):\n%s", diff)
		}
		if got := f.metrics.lastCode(t); got != CodeBusy {
			t.Errorf("metric code = %q, want %q", got, CodeBusy)
		}
		if got := f.proxy.inflight.held("prod-eu"); got != 1 {
			t.Errorf("in-flight slots = %d, want only the blocked call's", got)
		}
	})

	t.Run("parent cancellation while waiting reports a timeout, not busy", func(t *testing.T) {
		t.Parallel()
		const cap = 1 << 20
		f := newFixture(t, Options{
			MaxResponseBytes:      cap,
			GlobalResponseBudget:  cap,
			MaxInflightPerCluster: 4,
		}, "prod-eu")
		s := f.session(t, "prod-eu")

		hold := make(chan struct{})
		defer close(hold)
		s.doFn = func(ctx context.Context, n int, _ *tunnel.Request) (*tunnel.Response, error) {
			if n == 0 {
				<-hold
			}
			return jsonResponse(200, []byte(`{}`)), nil
		}
		go func() { _, _ = f.proxy.Do(context.Background(), allowAll(), queryCall("prod-eu")) }()
		s.waitEntered(t)

		ctx, cancel := context.WithCancel(context.Background())
		go func() { time.Sleep(30 * time.Millisecond); cancel() }()
		_, err := f.proxy.Do(ctx, allowAll(), queryCall("prod-eu"))

		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error = %v, want context.Canceled", err)
		}
		if errors.Is(err, ErrBusy) {
			t.Errorf("error = %v, want the caller's own cancellation, not a busy signal", err)
		}
		if got := f.metrics.lastCode(t); got != CodeTimeout {
			t.Errorf("metric code = %q, want %q", got, CodeTimeout)
		}
	})
}

// TestBudgetIsReleasedOnEveryPath is the leak test. A byte permit that is never
// returned does not fail anything immediately; it quietly shrinks the hub's
// capacity until unrelated callers start getting ErrBusy, which is close to
// undiagnosable in production. Every outcome therefore ends here.
func TestBudgetIsReleasedOnEveryPath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		doFn    func(t *testing.T) func(ctx context.Context, n int, req *tunnel.Request) (*tunnel.Response, error)
		wantErr error
		wantRes bool
	}{
		{
			name: "success",
			doFn: func(*testing.T) func(context.Context, int, *tunnel.Request) (*tunnel.Response, error) {
				return func(context.Context, int, *tunnel.Request) (*tunnel.Response, error) {
					return jsonResponse(200, []byte(`{"status":"success"}`)), nil
				}
			},
			wantRes: true,
		},
		{
			name: "upstream 500 is a result, not an error",
			doFn: func(*testing.T) func(context.Context, int, *tunnel.Request) (*tunnel.Response, error) {
				return func(context.Context, int, *tunnel.Request) (*tunnel.Response, error) {
					return jsonResponse(500, []byte(`{"status":"error"}`)), nil
				}
			},
			wantRes: true,
		},
		{
			name: "transport failure",
			doFn: func(*testing.T) func(context.Context, int, *tunnel.Request) (*tunnel.Response, error) {
				return func(context.Context, int, *tunnel.Request) (*tunnel.Response, error) {
					return nil, errBoom
				}
			},
			wantErr: ErrUpstream,
		},
		{
			name: "session closed",
			doFn: func(*testing.T) func(context.Context, int, *tunnel.Request) (*tunnel.Response, error) {
				return func(context.Context, int, *tunnel.Request) (*tunnel.Response, error) {
					return nil, tunnel.ErrSessionClosed
				}
			},
			wantErr: ErrUpstream,
		},
		{
			name: "tunnel reports the cluster gone",
			doFn: func(*testing.T) func(context.Context, int, *tunnel.Request) (*tunnel.Response, error) {
				return func(context.Context, int, *tunnel.Request) (*tunnel.Response, error) {
					return nil, tunnel.ErrNotConnected
				}
			},
			wantErr: tunnel.ErrNotConnected,
		},
		{
			name: "transport aborted an oversize transfer",
			doFn: func(*testing.T) func(context.Context, int, *tunnel.Request) (*tunnel.Response, error) {
				return func(context.Context, int, *tunnel.Request) (*tunnel.Response, error) {
					return nil, tunnel.ErrResponseTooLarge
				}
			},
			wantErr: ErrTooLarge,
		},
		{
			name: "body fails mid-stream",
			doFn: func(*testing.T) func(context.Context, int, *tunnel.Request) (*tunnel.Response, error) {
				return func(context.Context, int, *tunnel.Request) (*tunnel.Response, error) {
					return &tunnel.Response{
						StatusCode: 200,
						Body:       &errReader{prefix: []byte(`{"sta`), err: errBoom},
					}, nil
				}
			},
			wantErr: ErrUpstream,
		},
		{
			name: "body is cut by the transport's own cap",
			doFn: func(*testing.T) func(context.Context, int, *tunnel.Request) (*tunnel.Response, error) {
				return func(context.Context, int, *tunnel.Request) (*tunnel.Response, error) {
					return &tunnel.Response{
						StatusCode: 200,
						Body: &errReader{
							prefix: []byte(`{"sta`), err: tunnel.ErrResponseTooLarge,
						},
					}, nil
				}
			},
			wantErr: ErrTooLarge,
			wantRes: true,
		},
		{
			name: "the trailer reports the spoke could not finish",
			doFn: func(*testing.T) func(context.Context, int, *tunnel.Request) (*tunnel.Response, error) {
				return func(context.Context, int, *tunnel.Request) (*tunnel.Response, error) {
					return trailerResponse(200, []byte(`{}`), tunnel.Trailer{Err: errBoom}), nil
				}
			},
			wantErr: ErrUpstream,
		},
		{
			name: "the body claims gzip but is not",
			doFn: func(*testing.T) func(context.Context, int, *tunnel.Request) (*tunnel.Response, error) {
				return func(context.Context, int, *tunnel.Request) (*tunnel.Response, error) {
					r := jsonResponse(200, []byte(`not gzip at all`))
					r.ContentEncoding = "gzip"
					return r, nil
				}
			},
			wantErr: ErrUpstream,
		},
		{
			name: "the response has no body at all",
			doFn: func(*testing.T) func(context.Context, int, *tunnel.Request) (*tunnel.Response, error) {
				return func(context.Context, int, *tunnel.Request) (*tunnel.Response, error) {
					return &tunnel.Response{StatusCode: 204}, nil
				}
			},
			wantRes: true,
		},
		{
			name: "the call is cancelled inside the cluster",
			doFn: func(*testing.T) func(context.Context, int, *tunnel.Request) (*tunnel.Response, error) {
				return func(ctx context.Context, _ int, _ *tunnel.Request) (*tunnel.Response, error) {
					return nil, context.DeadlineExceeded
				}
			},
			wantErr: context.DeadlineExceeded,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t, Options{}, "prod-eu")
			f.session(t, "prod-eu").doFn = tc.doFn(t)

			res, err := f.proxy.Do(context.Background(), allowAll(), queryCall("prod-eu"))
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("Do: %v", err)
				}
			} else if !errors.Is(err, tc.wantErr) {
				t.Fatalf("error = %v, want %v", err, tc.wantErr)
			}
			if (res != nil) != tc.wantRes {
				t.Errorf("result = %v, want a result: %v", res, tc.wantRes)
			}
			f.budgetsAreClean(t, "prod-eu")
		})
	}
}

func TestByteCapTruncation(t *testing.T) {
	t.Parallel()

	const cap = 512

	t.Run("a plain body over the cap is truncated", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, Options{MaxResponseBytes: cap}, "prod-eu")
		body := bytes.Repeat([]byte("a"), cap*4)
		f.session(t, "prod-eu").doFn = func(context.Context, int, *tunnel.Request) (*tunnel.Response, error) {
			return jsonResponse(200, body), nil
		}

		res, err := f.proxy.Do(context.Background(), allowAll(), queryCall("prod-eu"))
		if !errors.Is(err, ErrTooLarge) {
			t.Fatalf("error = %v, want ErrTooLarge", err)
		}
		if res == nil {
			t.Fatal("Do returned no partial result")
		}
		if !res.Truncated {
			t.Error("Result.Truncated = false")
		}
		if int64(len(res.Body)) != cap || res.Bytes != cap {
			t.Errorf("body = %d bytes, Bytes = %d, want %d", len(res.Body), res.Bytes, cap)
		}
		if got := f.metrics.lastCode(t); got != CodeTooLarge {
			t.Errorf("metric code = %q, want %q", got, CodeTooLarge)
		}
		f.budgetsAreClean(t, "prod-eu")
	})

	t.Run("a body exactly at the cap is not truncated", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, Options{MaxResponseBytes: cap}, "prod-eu")
		body := bytes.Repeat([]byte("a"), cap)
		f.session(t, "prod-eu").doFn = func(context.Context, int, *tunnel.Request) (*tunnel.Response, error) {
			return jsonResponse(200, body), nil
		}

		res, err := f.proxy.Do(context.Background(), allowAll(), queryCall("prod-eu"))
		if err != nil {
			t.Fatalf("Do: %v", err)
		}
		if res.Truncated {
			t.Error("a body of exactly MaxBytes was reported as truncated")
		}
		if diff := cmp.Diff(body, res.Body); diff != "" {
			t.Errorf("body (-want +got):\n%s", diff)
		}
		if diff := cmp.Diff([]int64{cap}, f.metrics.responseBytes()); diff != "" {
			t.Errorf("response byte observations (-want +got):\n%s", diff)
		}
	})

	// A gzip body is the interesting case: the compressed stream fits under the
	// cap easily, so a cap applied to the wire bytes would let an attacker
	// spend a few kilobytes to make the hub hold hundreds of megabytes.
	t.Run("a gzip body that inflates past the cap is truncated", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, Options{MaxResponseBytes: cap}, "prod-eu")
		inflated := bytes.Repeat([]byte("a"), 64<<10)
		resp := gzipResponse(t, 200, inflated)

		var compressedLen int
		if b, ok := resp.Body.(io.Reader); ok {
			raw, _ := io.ReadAll(b)
			compressedLen = len(raw)
			resp.Body = io.NopCloser(bytes.NewReader(raw))
		}
		if int64(compressedLen) >= cap {
			t.Fatalf("the compressed body is %d bytes, which is not under the %d cap; "+
				"this test would not distinguish the two caps", compressedLen, cap)
		}

		f.session(t, "prod-eu").doFn = func(context.Context, int, *tunnel.Request) (*tunnel.Response, error) {
			return resp, nil
		}

		res, err := f.proxy.Do(context.Background(), allowAll(), queryCall("prod-eu"))
		if !errors.Is(err, ErrTooLarge) {
			t.Fatalf("error = %v, want ErrTooLarge: the cap was applied to the compressed size", err)
		}
		if int64(len(res.Body)) != cap {
			t.Errorf("body = %d bytes, want the cap %d", len(res.Body), cap)
		}
		f.budgetsAreClean(t, "prod-eu")
	})

	t.Run("a gzip body under the cap round-trips", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, Options{MaxResponseBytes: cap}, "prod-eu")
		body := []byte(`{"status":"success","data":{"resultType":"vector","result":[]}}`)
		f.session(t, "prod-eu").doFn = func(context.Context, int, *tunnel.Request) (*tunnel.Response, error) {
			return gzipResponse(t, 200, body), nil
		}

		res, err := f.proxy.Do(context.Background(), allowAll(), queryCall("prod-eu"))
		if err != nil {
			t.Fatalf("Do: %v", err)
		}
		if diff := cmp.Diff(body, res.Body); diff != "" {
			t.Errorf("inflated body (-want +got):\n%s", diff)
		}
		if !f.session(t, "prod-eu").lastCall(t).AcceptGzip {
			t.Error("AcceptGzip = false; the tunnel hop should carry compressed bytes")
		}
	})

	// A compressed stream cut at the cap makes the inflater report a corrupt
	// trailer. That is the cap working, not an upstream failure, and the two
	// must not be conflated.
	t.Run("a gzip stream cut at the cap is truncation, not corruption", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, Options{MaxResponseBytes: 64}, "prod-eu")

		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		if _, err := zw.Write(bytes.Repeat([]byte("a"), 1<<16)); err != nil {
			t.Fatalf("gzip write: %v", err)
		}
		if err := zw.Close(); err != nil {
			t.Fatalf("gzip close: %v", err)
		}
		f.session(t, "prod-eu").doFn = func(context.Context, int, *tunnel.Request) (*tunnel.Response, error) {
			return &tunnel.Response{
				StatusCode:      200,
				ContentEncoding: "gzip",
				Body:            io.NopCloser(bytes.NewReader(buf.Bytes())),
			}, nil
		}

		res, err := f.proxy.Do(context.Background(), allowAll(), queryCall("prod-eu"))
		if !errors.Is(err, ErrTooLarge) {
			t.Fatalf("error = %v, want ErrTooLarge", err)
		}
		if !errors.Is(err, ErrUpstream) && res == nil {
			t.Fatal("expected a partial result")
		}
		f.budgetsAreClean(t, "prod-eu")
	})

	t.Run("a truncated gzip header is an upstream failure", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, Options{MaxResponseBytes: 4}, "prod-eu")
		f.session(t, "prod-eu").doFn = func(context.Context, int, *tunnel.Request) (*tunnel.Response, error) {
			return &tunnel.Response{
				StatusCode:      200,
				ContentEncoding: "gzip",
				Body:            io.NopCloser(bytes.NewReader([]byte{0x1f, 0x8b, 0x08})),
			}, nil
		}
		res, err := f.proxy.Do(context.Background(), allowAll(), queryCall("prod-eu"))
		if err == nil {
			t.Fatalf("Do = %v, want an error", res)
		}
		f.budgetsAreClean(t, "prod-eu")
	})

	t.Run("the spoke's own truncation flag is honoured", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, Options{}, "prod-eu")
		f.session(t, "prod-eu").doFn = func(context.Context, int, *tunnel.Request) (*tunnel.Response, error) {
			return trailerResponse(200, []byte(`{"partial":true}`), tunnel.Trailer{
				Truncated: true,
				Warnings:  []string{"upstream truncated the result"},
			}), nil
		}

		res, err := f.proxy.Do(context.Background(), allowAll(), queryCall("prod-eu"))
		if !errors.Is(err, ErrTooLarge) {
			t.Fatalf("error = %v, want ErrTooLarge", err)
		}
		if !res.Truncated {
			t.Error("Result.Truncated = false despite the spoke reporting truncation")
		}
		if diff := cmp.Diff([]string{"upstream truncated the result"}, res.Warnings); diff != "" {
			t.Errorf("warnings (-want +got):\n%s", diff)
		}
		f.budgetsAreClean(t, "prod-eu")
	})
}

func TestNotConnectedCarriesLastSeen(t *testing.T) {
	t.Parallel()

	t.Run("a cluster inside its disconnect grace window", func(t *testing.T) {
		t.Parallel()
		reg, err := registry.New(registry.Options{
			FactsPollInterval: time.Hour,
			DisconnectGrace:   time.Hour,
		})
		if err != nil {
			t.Fatalf("registry.New: %v", err)
		}
		t.Cleanup(func() { reg.Close("test") })

		s := newFakeSession("prod-eu")
		release, err := reg.OnSession(context.Background(), s)
		if err != nil {
			t.Fatalf("OnSession: %v", err)
		}
		metrics := newCountingMetrics()
		p, err := New(Options{Registry: reg, Metrics: metrics})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		release()

		_, err = p.Do(context.Background(), allowAll(), queryCall("prod-eu"))

		var nc *NotConnectedError
		if !errors.As(err, &nc) {
			t.Fatalf("error = %v, want a *NotConnectedError", err)
		}
		if !errors.Is(err, tunnel.ErrNotConnected) || !errors.Is(err, ErrUpstream) {
			t.Errorf("error = %v, want both tunnel.ErrNotConnected and ErrUpstream", err)
		}
		if errors.Is(err, registry.ErrUnknownCluster) {
			t.Errorf("error = %v, want it distinguished from an unknown cluster", err)
		}
		if nc.ClusterID != "prod-eu" {
			t.Errorf("ClusterID = %q", nc.ClusterID)
		}
		if nc.LastSeen.IsZero() {
			t.Error("LastSeen is zero; an agent cannot tell 30 seconds ago from yesterday")
		}
		if !strings.Contains(nc.Error(), nc.LastSeen.UTC().Format(time.RFC3339)) {
			t.Errorf("Error() = %q, want the last-seen time in it", nc.Error())
		}
		if got := metrics.lastCode(t); got != CodeUnavailable {
			t.Errorf("metric code = %q, want %q", got, CodeUnavailable)
		}
	})

	t.Run("the tunnel drops between routing and the call", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, Options{}, "prod-eu")
		f.session(t, "prod-eu").doFn = func(context.Context, int, *tunnel.Request) (*tunnel.Response, error) {
			return nil, fmt.Errorf("send: %w", tunnel.ErrNotConnected)
		}

		_, err := f.proxy.Do(context.Background(), allowAll(), queryCall("prod-eu"))

		var nc *NotConnectedError
		if !errors.As(err, &nc) {
			t.Fatalf("error = %v, want a *NotConnectedError", err)
		}
		if nc.LastSeen.IsZero() {
			t.Error("LastSeen is zero although the registry still holds the cluster")
		}
		if nc.Since <= 0 {
			t.Errorf("Since = %s, want a positive age", nc.Since)
		}
		f.budgetsAreClean(t, "prod-eu")
	})

	t.Run("never seen", func(t *testing.T) {
		t.Parallel()
		nc := &NotConnectedError{ClusterID: "prod-eu"}
		if !strings.Contains(nc.Error(), "never seen") {
			t.Errorf("Error() = %q, want it to say the cluster was never seen", nc.Error())
		}
		if got := codeFor(nc); got != CodeUnavailable {
			t.Errorf("codeFor = %q, want %q", got, CodeUnavailable)
		}
	})
}

func TestContextCancellationPropagates(t *testing.T) {
	t.Parallel()

	t.Run("the caller's cancellation reaches the remote cluster", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, Options{}, "prod-eu")
		s := f.session(t, "prod-eu")
		s.doFn = func(ctx context.Context, _ int, _ *tunnel.Request) (*tunnel.Response, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		}

		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() {
			_, err := f.proxy.Do(ctx, allowAll(), queryCall("prod-eu"))
			done <- err
		}()
		s.waitEntered(t)
		cancel()

		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("error = %v, want context.Canceled", err)
			}
			if errors.Is(err, ErrUpstream) {
				t.Errorf("error = %v: the caller's own cancellation is not an upstream failure", err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("Do did not return after cancellation")
		}

		if diff := cmp.Diff([]error{context.Canceled}, s.contextErrors(),
			cmpopts.EquateErrors()); diff != "" {
			t.Errorf("the spoke's observed context error (-want +got):\n%s", diff)
		}
		if got := f.metrics.lastCode(t); got != CodeTimeout {
			t.Errorf("metric code = %q, want %q", got, CodeTimeout)
		}
		f.budgetsAreClean(t, "prod-eu")
	})

	t.Run("a deadline is always set on the outgoing request", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, Options{DefaultTimeout: 5 * time.Second}, "prod-eu")

		// Even with an undeadlined parent, the hub must bound the remote work:
		// an agent that hangs up must not leave a query running in a cluster.
		if _, err := f.proxy.Do(context.Background(), allowAll(), queryCall("prod-eu")); err != nil {
			t.Fatalf("Do: %v", err)
		}
		got := f.session(t, "prod-eu").lastCall(t)
		if !got.HasDeadline {
			t.Fatal("the outgoing request had no deadline")
		}
		if d := time.Until(got.Deadline); d <= 0 || d > 5*time.Second {
			t.Errorf("remaining budget = %s, want (0, 5s]", d)
		}
		if got.RequestID != "req-1" {
			t.Errorf("RequestID = %q, want it carried to the spoke", got.RequestID)
		}
	})
}

func TestResultAndMetricCodes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		status   int
		wantCode string
	}{
		{name: "2xx", status: 200, wantCode: CodeOK},
		{name: "4xx is a PromQL error, not a proxy failure", status: 400, wantCode: CodeClientError},
		{name: "5xx", status: 503, wantCode: CodeServerError},
		{name: "a status outside the ranges we know", status: 101, wantCode: CodeUpstream},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t, Options{}, "prod-eu")
			body := []byte(`{"status":"error","errorType":"bad_data","error":"parse error"}`)
			f.session(t, "prod-eu").doFn = func(context.Context, int, *tunnel.Request) (*tunnel.Response, error) {
				return trailerResponse(tc.status, body, tunnel.Trailer{
					Warnings: []string{"a warning"},
				}), nil
			}

			res, err := f.proxy.Do(context.Background(), allowAll(), queryCall("prod-eu"))
			if err != nil {
				t.Fatalf("Do: %v", err)
			}
			want := &Result{
				Body:      body,
				Status:    tc.status,
				Warnings:  []string{"a warning"},
				Latency:   res.Latency,
				Bytes:     int64(len(body)),
				Truncated: false,
			}
			if diff := cmp.Diff(want, res); diff != "" {
				t.Errorf("Result (-want +got):\n%s", diff)
			}
			if got := f.metrics.lastCode(t); got != tc.wantCode {
				t.Errorf("metric code = %q, want %q", got, tc.wantCode)
			}
			f.budgetsAreClean(t, "prod-eu")
		})
	}
}

func TestFormIsSentInTheBody(t *testing.T) {
	t.Parallel()

	f := newFixture(t, Options{}, "prod-eu")
	call := Call{
		ClusterID: "prod-eu",
		Endpoint:  promapi.EndpointQueryRange,
		Form: url.Values{
			"query": {`sum by (job) (rate(http_requests_total[5m]))`},
			"start": {"1756000000"},
			"end":   {"1756003600"},
			"step":  {"1m"},
		},
	}
	before := call.Form.Encode()

	if _, err := f.proxy.Do(context.Background(), allowAll(), call); err != nil {
		t.Fatalf("Do: %v", err)
	}
	got := f.session(t, "prod-eu").lastCall(t)
	if got.Form != before {
		t.Errorf("form = %q, want %q", got.Form, before)
	}
	if diff := cmp.Diff(before, call.Form.Encode()); diff != "" {
		t.Errorf("the caller's Form was mutated (-want +got):\n%s", diff)
	}
	if strings.Contains(got.Path, "query=") {
		t.Errorf("path = %q; parameters must travel in the body, not the URI", got.Path)
	}
}

func TestCodeForAndStatusCode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want string
	}{
		{name: "nil", err: nil, want: CodeOK},
		{name: "forbidden", err: fmt.Errorf("x: %w", ErrForbidden), want: CodeForbidden},
		{name: "busy", err: &BusyError{}, want: CodeBusy},
		{name: "too large", err: fmt.Errorf("x: %w", ErrTooLarge), want: CodeTooLarge},
		{name: "unknown cluster", err: registry.ErrUnknownCluster, want: CodeUnavailable},
		{name: "not connected", err: tunnel.ErrNotConnected, want: CodeUnavailable},
		{name: "deadline", err: context.DeadlineExceeded, want: CodeTimeout},
		{name: "cancelled", err: context.Canceled, want: CodeTimeout},
		{name: "invalid param", err: promapi.ErrInvalidParam, want: CodeInvalid},
		{name: "unknown endpoint", err: promapi.ErrUnknownEndpoint, want: CodeInvalid},
		{name: "gated endpoint", err: promapi.ErrEndpointGated, want: CodeInvalid},
		{name: "invalid label name", err: promapi.ErrInvalidLabelName, want: CodeInvalid},
		{name: "anything else", err: errBoom, want: CodeUpstream},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := codeFor(tc.err); got != tc.want {
				t.Errorf("codeFor(%v) = %q, want %q", tc.err, got, tc.want)
			}
		})
	}

	if got := statusCode(299); got != CodeOK {
		t.Errorf("statusCode(299) = %q", got)
	}
	if got := statusCode(0); got != CodeUpstream {
		t.Errorf("statusCode(0) = %q", got)
	}
}

func TestBusyErrorMessage(t *testing.T) {
	t.Parallel()

	e := &BusyError{
		ClusterID: "prod-eu", Budget: "cluster-inflight", Limit: 8,
		RetryAfter: ClusterBusyRetryAfter,
	}
	for _, want := range []string{"prod-eu", "cluster-inflight", "8", "500ms"} {
		if !strings.Contains(e.Error(), want) {
			t.Errorf("Error() = %q, want it to mention %q", e.Error(), want)
		}
	}
	if !errors.Is(e, ErrBusy) {
		t.Error("BusyError does not unwrap to ErrBusy")
	}
}

func TestNopMetricsIsInert(t *testing.T) {
	t.Parallel()

	var m Metrics = NopMetrics{}
	m.ProxyRequest("prod-eu", promapi.EndpointQuery, CodeOK)
	m.ProxyDuration("prod-eu", promapi.EndpointQuery, time.Second)
	m.ProxyInflight("prod-eu", 1)
	m.ProxyResponseBytes(1024)
}

// TestConcurrentCalls hammers the proxy from many goroutines. Its job is to be
// run under -race; the budget assertion at the end is the substantive one.
func TestConcurrentCalls(t *testing.T) {
	t.Parallel()

	f := newFixture(t, Options{
		MaxInflightPerCluster: 4,
		MaxResponseBytes:      1 << 16,
		GlobalResponseBudget:  1 << 20,
	}, "prod-eu", "prod-us")

	var wg sync.WaitGroup
	for i := range 60 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			id := "prod-eu"
			if i%2 == 0 {
				id = "prod-us"
			}
			call := queryCall(id)
			call.Timeout = 2 * time.Second
			res, err := f.proxy.Do(context.Background(), allowAll(), call)
			switch {
			case err == nil && res.Status != 200:
				t.Errorf("status = %d", res.Status)
			case err != nil && !errors.Is(err, ErrBusy):
				t.Errorf("Do: %v", err)
			}
		}()
	}
	wg.Wait()

	f.budgetsAreClean(t, "prod-eu")
	f.budgetsAreClean(t, "prod-us")
	for _, s := range f.sessions {
		if got := s.peakConcurrency(); got > 4 {
			t.Errorf("cluster %s saw %d simultaneous calls, want at most 4",
				s.ident.ClusterID, got)
		}
	}
}

// TestSessionResolutionIsDefensive covers the routing helper directly. Do
// checks the registry twice — once for authorization labels and once for the
// tunnel — and a cluster can be forgotten in between, so the second lookup
// cannot assume the first one's answer still holds.
func TestSessionResolutionIsDefensive(t *testing.T) {
	t.Parallel()

	f := newFixture(t, Options{}, "prod-eu")

	_, err := f.proxy.session("ghost")
	if !errors.Is(err, registry.ErrUnknownCluster) {
		t.Errorf("session(ghost) = %v, want registry.ErrUnknownCluster", err)
	}
	if !errors.Is(err, tunnel.ErrNotConnected) {
		t.Errorf("session(ghost) = %v, want it to also report tunnel.ErrNotConnected", err)
	}
	if _, err := f.proxy.session("prod-eu"); err != nil {
		t.Errorf("session(prod-eu) = %v, want the live session", err)
	}
}

// TestLimitsOfDefaultsToZero covers the defensive branch: authorization has
// already rejected a principal with no scope by the time limits are read, but
// a nil dereference here would be a panic on the hot path rather than a denial.
func TestLimitsOfDefaultsToZero(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		p    *fleet.Principal
		want fleet.Limits
	}{
		{name: "nil principal", p: nil},
		{name: "no scope", p: &fleet.Principal{KID: "k"}},
		{
			name: "scoped",
			p:    withLimits(fleet.Limits{MaxPoints: 11, Timeout: fleet.Duration(time.Second)}),
			want: fleet.Limits{MaxPoints: 11, Timeout: fleet.Duration(time.Second)},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if diff := cmp.Diff(tc.want, limitsOf(tc.p)); diff != "" {
				t.Errorf("limitsOf (-want +got):\n%s", diff)
			}
		})
	}
}

// TestGzipHeaderCutByTheCap is the case where the cap bites before the gzip
// header is even complete. The inflater cannot tell that from a corrupt stream,
// so the cap reader has to, or a tiny MaxBytes would be reported as an upstream
// failure instead of a truncation.
func TestGzipHeaderCutByTheCap(t *testing.T) {
	t.Parallel()

	f := newFixture(t, Options{MaxResponseBytes: 4}, "prod-eu")
	f.session(t, "prod-eu").doFn = func(context.Context, int, *tunnel.Request) (*tunnel.Response, error) {
		return gzipResponse(t, 200, []byte(`{"status":"success"}`)), nil
	}

	res, err := f.proxy.Do(context.Background(), allowAll(), queryCall("prod-eu"))
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("error = %v, want ErrTooLarge", err)
	}
	if errors.Is(err, ErrUpstream) {
		t.Errorf("error = %v: a cap hit was reported as an upstream failure", err)
	}
	if res == nil || !res.Truncated || len(res.Body) != 0 {
		t.Errorf("result = %+v, want a truncated, empty body", res)
	}
	f.budgetsAreClean(t, "prod-eu")
}
