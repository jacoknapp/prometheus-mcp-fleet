// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package obs

import (
	"context"
	"fmt"
	"strings"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.43.0"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/version"
)

// DefaultServiceName is used when TracingConfig.ServiceName is empty.
const DefaultServiceName = "prometheus-mcp-fleet"

// TracingConfig configures OTLP/gRPC trace export.
type TracingConfig struct {
	// Endpoint is the collector address. It accepts a bare "host:port", which
	// is exported over TLS, or a URL such as "http://collector:4317", where an
	// http scheme selects an insecure connection. An empty Endpoint disables
	// tracing entirely.
	Endpoint string
	// SampleRatio is the head sampling ratio. It is clamped into [0,1], and
	// sampling is parent-based so a sampled incoming trace stays sampled.
	SampleRatio float64
	// ServiceName is the OpenTelemetry service.name. Empty uses
	// [DefaultServiceName].
	ServiceName string
	// Build stamps the service.version and vcs revision resource attributes.
	Build version.Build
}

// newTraceExporter is the network boundary of tracing initialisation. Keeping
// it narrow lets tests exercise exporter and shutdown failures deterministically
// without depending on a collector or a particular gRPC dial schedule.
var newTraceExporter = func(ctx context.Context, endpoint string) (sdktrace.SpanExporter, error) {
	return otlptracegrpc.New(ctx, endpointOption(endpoint))
}

// InitTracing installs the global tracer provider and text-map propagator, and
// returns a shutdown function that flushes pending spans.
//
// With an empty [TracingConfig.Endpoint] it installs a no-op provider and
// returns a no-op shutdown: no exporter is built, no connection is opened, and
// nothing is queued. That is the default configuration, so a hub or spoke with
// tracing off performs zero tracing work.
//
// It mutates OpenTelemetry global state and is intended to be called once from
// a composition root. The returned shutdown is safe to call more than once.
func InitTracing(ctx context.Context, cfg TracingConfig) (func(context.Context) error, error) {
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{}, propagation.Baggage{},
	))

	if strings.TrimSpace(cfg.Endpoint) == "" {
		otel.SetTracerProvider(noop.NewTracerProvider())
		return func(context.Context) error { return nil }, nil
	}

	exporter, err := newTraceExporter(ctx, cfg.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("otlp trace exporter %q: %w", cfg.Endpoint, err)
	}

	name := cfg.ServiceName
	if name == "" {
		name = DefaultServiceName
	}
	attrs := []attribute.KeyValue{
		semconv.ServiceName(name),
		semconv.ServiceVersion(cfg.Build.Version),
	}
	if cfg.Build.Commit != "" {
		attrs = append(attrs, attribute.String("vcs.revision", cfg.Build.Commit))
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(resource.NewWithAttributes(semconv.SchemaURL, attrs...)),
		sdktrace.WithSampler(sdktrace.ParentBased(
			sdktrace.TraceIDRatioBased(clampRatio(cfg.SampleRatio)))),
	)
	otel.SetTracerProvider(tp)

	return func(ctx context.Context) error {
		if err := tp.Shutdown(ctx); err != nil {
			return fmt.Errorf("shutdown tracer provider: %w", err)
		}
		return nil
	}, nil
}

// endpointOption turns a configured endpoint into an exporter option. A value
// carrying a scheme goes through WithEndpointURL, which honours http for
// insecure; a bare host:port keeps the OTLP default of TLS.
func endpointOption(endpoint string) otlptracegrpc.Option {
	if strings.Contains(endpoint, "://") {
		return otlptracegrpc.WithEndpointURL(endpoint)
	}
	return otlptracegrpc.WithEndpoint(endpoint)
}

// clampRatio forces a sampling ratio into [0,1]. A configured value outside
// that range is a mistake, and clamping is safer than sampling everything.
func clampRatio(r float64) float64 {
	switch {
	case r != r: // NaN
		return 0
	case r < 0:
		return 0
	case r > 1:
		return 1
	default:
		return r
	}
}
