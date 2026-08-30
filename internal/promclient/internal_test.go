// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package promclient

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/promapi"
)

func TestLimitedBodyRepeatsTerminalErrors(t *testing.T) {
	t.Parallel()

	t.Run("too large", func(t *testing.T) {
		t.Parallel()
		b := newLimitedBody(io.NopCloser(strings.NewReader("abcd")), 2, 0, nil, false)
		buf := make([]byte, 8)
		if n, err := b.Read(buf); n != 2 || !errors.Is(err, ErrTooLarge) {
			t.Fatalf("first Read = %d, %v; want 2, ErrTooLarge", n, err)
		}
		if n, err := b.Read(buf); n != 0 || !errors.Is(err, ErrTooLarge) {
			t.Errorf("second Read = %d, %v; want 0, ErrTooLarge", n, err)
		}
	})

	t.Run("source failure", func(t *testing.T) {
		t.Parallel()
		want := errors.New("source failed")
		b := newLimitedBody(&failingBody{err: want}, 8, 0, nil, false)
		buf := make([]byte, 1)
		if _, err := b.Read(buf); !errors.Is(err, want) {
			t.Fatalf("first Read = %v, want source failure", err)
		}
		if _, err := b.Read(buf); !errors.Is(err, want) {
			t.Errorf("second Read = %v, want cached source failure", err)
		}
	})
}

func TestRoundTripInternalFailures(t *testing.T) {
	t.Parallel()
	c := mustInternalClient(t, Config{BaseURL: "http://prom.example"})

	badLabelRoute, err := promapi.Get(promapi.EndpointLabelValues)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := c.roundTrip(t.Context(), badLabelRoute, "bad/label", nil, false, ""); !errors.Is(err, ErrNotAllowed) {
		t.Errorf("roundTrip invalid label = %v, want ErrNotAllowed", err)
	}

	queryRoute, err := promapi.Get(promapi.EndpointQuery)
	if err != nil {
		t.Fatal(err)
	}
	queryRoute.Method = "bad method"
	if _, _, _, err := c.roundTrip(t.Context(), queryRoute, "", url.Values{"query": {"up"}}, false, ""); err == nil || !strings.Contains(err.Error(), "build request") {
		t.Errorf("roundTrip invalid method = %v, want build request failure", err)
	}
}

func TestProbeInternalFailures(t *testing.T) {
	t.Parallel()

	t.Run("request construction", func(t *testing.T) {
		t.Parallel()
		c := mustInternalClient(t, Config{BaseURL: "http://prom.example"})
		c.base = &url.URL{Scheme: "http", Host: "[::1"}
		if err := c.probe(t.Context(), "/-/healthy"); err == nil || !strings.Contains(err.Error(), "/-/healthy") {
			t.Errorf("probe malformed URL = %v, want path-named construction error", err)
		}
	})

	t.Run("bearer token read", func(t *testing.T) {
		t.Parallel()
		c := mustInternalClient(t, Config{BaseURL: "http://prom.example", BearerTokenFile: "/missing/token"})
		if err := c.probe(t.Context(), "/-/healthy"); err == nil || !strings.Contains(err.Error(), "read bearer token") {
			t.Errorf("probe missing bearer token = %v, want token read error", err)
		}
	})
}

func TestJSONHelpersPropagateTransportAndReadFailures(t *testing.T) {
	t.Parallel()

	t.Run("label values transport", func(t *testing.T) {
		t.Parallel()
		c := mustInternalClient(t, Config{BaseURL: "http://prom.example"})
		c.httpc.Transport = roundTripper(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("dial failed")
		})
		if _, err := c.LabelValues(t.Context(), "job"); !errors.Is(err, ErrUpstream) {
			t.Errorf("LabelValues = %v, want ErrUpstream", err)
		}
	})

	t.Run("instant query transport", func(t *testing.T) {
		t.Parallel()
		c := mustInternalClient(t, Config{BaseURL: "http://prom.example"})
		c.httpc.Transport = roundTripper(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("dial failed")
		})
		if _, err := c.InstantQuery(t.Context(), "up"); !errors.Is(err, ErrUpstream) {
			t.Errorf("InstantQuery = %v, want ErrUpstream", err)
		}
	})

	t.Run("response read", func(t *testing.T) {
		t.Parallel()
		c := mustInternalClient(t, Config{BaseURL: "http://prom.example"})
		c.httpc.Transport = roundTripper(func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       &failingBody{err: io.ErrUnexpectedEOF},
			}, nil
		})
		route, _ := promapi.Get(promapi.EndpointLabels)
		if _, err := c.fetch(t.Context(), route, "", nil, &struct{}{}); !errors.Is(err, ErrUpstream) || !strings.Contains(err.Error(), "read body") {
			t.Errorf("fetch = %v, want upstream read failure", err)
		}
	})

	t.Run("bad scalar value", func(t *testing.T) {
		t.Parallel()
		c := mustInternalClient(t, Config{BaseURL: "http://prom.example"})
		c.httpc.Transport = roundTripper(func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body: io.NopCloser(bytes.NewBufferString(
					`{"status":"success","data":{"resultType":"scalar","result":[1,"not-a-number"]}}`)),
			}, nil
		})
		if _, err := c.InstantQuery(t.Context(), "up"); !errors.Is(err, ErrUpstream) || !strings.Contains(err.Error(), "not-a-number") {
			t.Errorf("InstantQuery = %v, want invalid scalar value error", err)
		}
	})
}

func mustInternalClient(t *testing.T, cfg Config) *Client {
	t.Helper()
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

type roundTripper func(*http.Request) (*http.Response, error)

func (f roundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type failingBody struct{ err error }

func (b *failingBody) Read([]byte) (int, error) { return 0, b.err }
func (*failingBody) Close() error               { return nil }
