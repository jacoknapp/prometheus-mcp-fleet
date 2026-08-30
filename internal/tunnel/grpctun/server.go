// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package grpctun

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	fleetv1 "github.com/jacoknapp/prometheus-mcp-fleet/internal/gen/fleet/v1"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/tunnel"
)

// defaultChunkBytes is the body chunk size on the wire. The proto caps it at
// 64 KiB; small enough that flow control is fine grained, large enough that a
// 40 MiB response is ~640 messages rather than 40 000.
const defaultChunkBytes = 64 << 10

// spokeServer is the gRPC service the spoke serves over the connection it
// dialled. It is a thin bridge onto tunnel.Handler and holds no state beyond
// its configuration, so it is safe for unlimited concurrent streams.
type spokeServer struct {
	fleetv1.UnimplementedSpokeServiceServer

	h          tunnel.Handler
	generation int64
	chunkBytes int
	log        *slog.Logger
}

// Describe implements fleetv1.SpokeServiceServer.
//
// The reply's started_at_unix_nano is stamped from the dialer's configured
// generation, not from whatever the facts collector produced: process start
// time belongs to the process, and the hub uses it to break reconnect races.
func (s *spokeServer) Describe(ctx context.Context, in *fleetv1.DescribeRequest) (*fleetv1.DescribeResponse, error) {
	facts, err := s.h.Describe(ctx, in.GetKnownFingerprint())
	if err != nil {
		return nil, status.Error(codeFor(ctx, err), err.Error())
	}
	return factsToProto(facts, s.generation), nil
}

// Proxy implements fleetv1.SpokeServiceServer. It performs one upstream call
// and streams the body back as head, data..., trail.
func (s *spokeServer) Proxy(in *fleetv1.ProxyRequest, stream fleetv1.SpokeService_ProxyServer) error {
	ctx := stream.Context()

	req, err := requestFromProto(in)
	if err != nil {
		return status.Error(codes.InvalidArgument, err.Error())
	}

	started := time.Now()
	resp, err := s.h.Do(ctx, req)
	if err != nil {
		// Nothing has been sent yet, so this can still be a clean RPC error.
		return status.Error(codeFor(ctx, err), err.Error())
	}
	if resp.Body == nil {
		return status.Error(codes.Internal, "handler returned a nil body")
	}
	defer func() { _ = resp.Body.Close() }()

	if err := stream.Send(&fleetv1.ProxyChunk{Kind: &fleetv1.ProxyChunk_Head{Head: &fleetv1.ResponseHead{
		StatusCode:      int32(resp.StatusCode), //nolint:gosec // G115: an HTTP status is three digits; net/http will not produce anything outside int32.
		ContentType:     resp.ContentType,
		ContentEncoding: resp.ContentEncoding,
	}}}); err != nil {
		return err
	}

	sent, truncated, copyErr := s.streamBody(stream, resp.Body, req.MaxResponseBytes)
	if copyErr != nil && ctx.Err() != nil {
		// The hub cancelled: RST_STREAM already told it everything. Sending a
		// trailer into a dead stream would only produce a confusing log line.
		return status.FromContextError(ctx.Err()).Err()
	}

	trail := &fleetv1.ResponseTrail{
		BytesTotal:         uint64(sent), //nolint:gosec // G115: streamBody only ever adds a non-negative Read count to sent, capped at req.MaxResponseBytes.
		UpstreamDurationMs: time.Since(started).Milliseconds(),
		Truncated:          truncated,
	}
	if resp.Trailer != nil {
		t := resp.Trailer()
		if t.UpstreamLatency > 0 {
			trail.UpstreamDurationMs = t.UpstreamLatency.Milliseconds()
		}
		trail.Truncated = trail.Truncated || t.Truncated
		trail.Warnings = t.Warnings
		if t.Err != nil {
			trail.Error = t.Err.Error()
		}
	}
	if copyErr != nil && trail.Error == "" {
		trail.Error = copyErr.Error()
	}
	return stream.Send(&fleetv1.ProxyChunk{Kind: &fleetv1.ProxyChunk_Trail{Trail: trail}})
}

// streamBody copies at most budget bytes from body into the stream in
// chunkBytes-sized messages. It reports how many bytes were sent, whether the
// body was longer than the budget, and any read or send failure.
//
// The budget is enforced exactly: the spoke sends the first budget bytes and
// then probes for one more. That makes truncation byte-deterministic instead of
// "wherever the last chunk happened to land", which is what lets the hub
// deliver exactly MaxResponseBytes before reporting ErrResponseTooLarge.
func (s *spokeServer) streamBody(stream fleetv1.SpokeService_ProxyServer, body io.Reader, budget int64) (sent int64, truncated bool, err error) {
	buf := make([]byte, s.chunkBytes)
	for {
		remaining := budget - sent
		if remaining <= 0 {
			n, rerr := body.Read(buf[:1])
			if n > 0 {
				truncated = true
			}
			if rerr != nil && !errors.Is(rerr, io.EOF) {
				return sent, truncated, rerr
			}
			return sent, truncated, nil
		}
		lim := int64(len(buf))
		if remaining < lim {
			lim = remaining
		}
		n, rerr := body.Read(buf[:lim])
		if n > 0 {
			if serr := stream.Send(&fleetv1.ProxyChunk{Kind: &fleetv1.ProxyChunk_Data{Data: buf[:n]}}); serr != nil {
				return sent, truncated, serr
			}
			sent += int64(n)
		}
		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				return sent, truncated, nil
			}
			return sent, truncated, rerr
		}
	}
}

// codeFor maps a handler error onto a gRPC status code so the hub can recover
// context.Canceled and context.DeadlineExceeded on the far side.
func codeFor(ctx context.Context, err error) codes.Code {
	switch {
	case errors.Is(err, context.Canceled) || errors.Is(ctx.Err(), context.Canceled):
		return codes.Canceled
	case errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded):
		return codes.DeadlineExceeded
	case errors.Is(err, tunnel.ErrResponseTooLarge):
		return codes.ResourceExhausted
	case errors.Is(err, ErrInvalidRequest):
		return codes.InvalidArgument
	default:
		return codes.Unavailable
	}
}
