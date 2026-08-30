// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package promclient

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"sync"
	"time"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/tunnel"
)

// limitedBody streams an upstream body while counting it and enforcing the
// byte cap.
//
// The cap is enforced during the read, not from Content-Length: a hostile or
// merely buggy upstream can under-report Content-Length, send a chunked
// response with no length at all, or stream forever. Only bytes actually
// delivered to the caller are trusted.
//
// It also buffers the first [warningsPeekLimit] bytes when — and only when —
// the body is uncompressed JSON, so that the Prometheus "warnings" member can
// be reported in the trailer. Larger bodies are never buffered and simply
// report no warnings, because holding a 32 MiB response in memory to read
// metadata off it would defeat the streaming design.
type limitedBody struct {
	src     io.ReadCloser
	limit   int64
	latency time.Duration
	cancel  context.CancelFunc

	mu        sync.Mutex
	n         int64
	truncated bool
	closed    bool
	peek      *bytes.Buffer
	warnings  []string
	warned    bool
	readErr   error
}

// newLimitedBody wraps src. peek enables warning extraction.
func newLimitedBody(src io.ReadCloser, limit int64, latency time.Duration, cancel context.CancelFunc, peek bool) *limitedBody {
	b := &limitedBody{src: src, limit: limit, latency: latency, cancel: cancel}
	if peek {
		b.peek = &bytes.Buffer{}
	}
	return b
}

// Read implements io.Reader. Once the cap is exceeded it returns the bytes
// that still fit followed by [ErrTooLarge], and every later call returns
// ErrTooLarge again.
func (b *limitedBody) Read(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.truncated {
		return 0, ErrTooLarge
	}
	if b.readErr != nil {
		return 0, b.readErr
	}
	if remaining := b.limit - b.n; int64(len(p)) > remaining {
		// Read one byte past the cap so that a body which is exactly at the
		// limit is not falsely reported as truncated, while one that is a
		// single byte over is caught.
		p = p[:remaining+1]
	}
	n, err := b.src.Read(p)
	if n > 0 {
		over := b.n + int64(n) - b.limit
		if over > 0 {
			n -= int(over)
			b.truncated = true
		}
		b.n += int64(n)
		if b.peek != nil {
			if b.n > int64(warningsPeekLimit) {
				b.peek = nil
			} else {
				b.peek.Write(p[:n])
			}
		}
	}
	switch {
	case b.truncated:
		return n, ErrTooLarge
	case err != nil:
		if err != io.EOF {
			b.readErr = err
		}
		return n, err
	}
	return n, nil
}

// Close releases the upstream connection and the derived request context.
func (b *limitedBody) Close() error {
	b.mu.Lock()
	alreadyClosed := b.closed
	b.closed = true
	b.mu.Unlock()
	if alreadyClosed {
		return nil
	}
	err := b.src.Close()
	if b.cancel != nil {
		b.cancel()
	}
	return err
}

// trailer reports the accounting for this response. It is safe to call before
// the body is drained, in which case BytesTotal reflects what has been read so
// far.
func (b *limitedBody) trailer() tunnel.Trailer {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.warned {
		b.warned = true
		b.warnings = extractWarnings(b.peek)
		b.peek = nil
	}
	t := tunnel.Trailer{
		BytesTotal:      b.n,
		UpstreamLatency: b.latency,
		Truncated:       b.truncated,
		Warnings:        b.warnings,
	}
	switch {
	case b.truncated:
		t.Err = ErrTooLarge
	case b.readErr != nil:
		t.Err = b.readErr
	}
	return t
}

// warningEnvelope is the only part of a Prometheus reply this package ever
// parses, and only for small uncompressed bodies.
type warningEnvelope struct {
	Warnings []string `json:"warnings"`
}

// extractWarnings pulls the "warnings" member out of a buffered JSON body.
// Anything unparseable yields no warnings rather than an error: warnings are
// advisory metadata and must never fail a request.
func extractWarnings(buf *bytes.Buffer) []string {
	if buf == nil || buf.Len() == 0 {
		return nil
	}
	var env warningEnvelope
	if err := json.Unmarshal(buf.Bytes(), &env); err != nil {
		return nil
	}
	if len(env.Warnings) == 0 {
		return nil
	}
	return env.Warnings
}
