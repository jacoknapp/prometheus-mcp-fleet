// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package obs

import (
	"context"
	"errors"
	"math"
	"sync"
	"testing"

	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/version"
)

type recordingExporter struct {
	mu          sync.Mutex
	spans       []sdktrace.ReadOnlySpan
	shutdownErr error
}

func (e *recordingExporter) ExportSpans(_ context.Context, spans []sdktrace.ReadOnlySpan) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.spans = append(e.spans, spans...)
	return nil
}

func (e *recordingExporter) Shutdown(context.Context) error { return e.shutdownErr }

func (e *recordingExporter) snapshot() []sdktrace.ReadOnlySpan {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]sdktrace.ReadOnlySpan(nil), e.spans...)
}

// Tracing mutates OpenTelemetry global state and the exporter constructor, so
// these cases intentionally run in one non-parallel top-level test.
func TestInitTracing(t *testing.T) {
	original := newTraceExporter
	t.Cleanup(func() { newTraceExporter = original })

	t.Run("disabled", func(t *testing.T) {
		called := false
		newTraceExporter = func(context.Context, string) (sdktrace.SpanExporter, error) {
			called = true
			return nil, errors.New("must not be called")
		}
		shutdown, err := InitTracing(t.Context(), TracingConfig{Endpoint: " \t"})
		if err != nil {
			t.Fatalf("InitTracing: %v", err)
		}
		if called {
			t.Fatal("disabled tracing constructed an exporter")
		}
		if err := shutdown(t.Context()); err != nil {
			t.Fatalf("disabled shutdown: %v", err)
		}
	})

	t.Run("exporter error", func(t *testing.T) {
		boom := errors.New("collector configuration rejected")
		newTraceExporter = func(_ context.Context, endpoint string) (sdktrace.SpanExporter, error) {
			if endpoint != "collector.invalid:4317" {
				t.Fatalf("endpoint = %q", endpoint)
			}
			return nil, boom
		}
		shutdown, err := InitTracing(t.Context(), TracingConfig{Endpoint: "collector.invalid:4317"})
		if !errors.Is(err, boom) {
			t.Fatalf("InitTracing error = %v, want wrapped exporter error", err)
		}
		if shutdown != nil {
			t.Fatal("InitTracing returned shutdown with an error")
		}
	})

	t.Run("exports configured resource", func(t *testing.T) {
		exporter := &recordingExporter{}
		newTraceExporter = func(_ context.Context, endpoint string) (sdktrace.SpanExporter, error) {
			if endpoint != "http://collector.test:4317" {
				t.Fatalf("endpoint = %q", endpoint)
			}
			return exporter, nil
		}
		shutdown, err := InitTracing(t.Context(), TracingConfig{
			Endpoint:    "http://collector.test:4317",
			SampleRatio: 1,
			Build:       version.Build{Version: "1.2.3", Commit: "abc123"},
		})
		if err != nil {
			t.Fatalf("InitTracing: %v", err)
		}
		_, span := otel.Tracer("test").Start(t.Context(), "operation")
		span.End()
		if err := shutdown(t.Context()); err != nil {
			t.Fatalf("shutdown: %v", err)
		}
		spans := exporter.snapshot()
		if len(spans) != 1 {
			t.Fatalf("exported %d spans, want 1", len(spans))
		}
		attrs := map[string]string{}
		for _, attr := range spans[0].Resource().Attributes() {
			attrs[string(attr.Key)] = attr.Value.AsString()
		}
		for key, want := range map[string]string{
			"service.name":    DefaultServiceName,
			"service.version": "1.2.3",
			"vcs.revision":    "abc123",
		} {
			if attrs[key] != want {
				t.Errorf("resource %s = %q, want %q", key, attrs[key], want)
			}
		}
	})

	t.Run("shutdown error", func(t *testing.T) {
		boom := errors.New("flush failed")
		newTraceExporter = func(context.Context, string) (sdktrace.SpanExporter, error) {
			return &recordingExporter{shutdownErr: boom}, nil
		}
		shutdown, err := InitTracing(t.Context(), TracingConfig{
			Endpoint: "collector.test:4317", ServiceName: "custom", SampleRatio: 0,
		})
		if err != nil {
			t.Fatalf("InitTracing: %v", err)
		}
		if err := shutdown(t.Context()); !errors.Is(err, boom) {
			t.Fatalf("shutdown error = %v, want wrapped exporter error", err)
		}
	})
}

func TestEndpointOptionForms(t *testing.T) {
	t.Parallel()
	if endpointOption("collector.test:4317") == nil {
		t.Fatal("bare endpoint produced a nil option")
	}
	if endpointOption("http://collector.test:4317") == nil {
		t.Fatal("URL endpoint produced a nil option")
	}
}

func TestClampRatio(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		in   float64
		want float64
	}{
		{name: "nan", in: math.NaN(), want: 0},
		{name: "negative", in: -0.1, want: 0},
		{name: "zero", in: 0, want: 0},
		{name: "fraction", in: 0.25, want: 0.25},
		{name: "one", in: 1, want: 1},
		{name: "above one", in: 1.1, want: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := clampRatio(tc.in); got != tc.want {
				t.Errorf("clampRatio(%v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}
