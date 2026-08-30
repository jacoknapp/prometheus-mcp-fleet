// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package obs

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
)

// Errors returned when constructing a logger. Callers branch on these with
// errors.Is.
var (
	// ErrLogLevel is returned for an unrecognised level name.
	ErrLogLevel = errors.New("obs: unknown log level")
	// ErrLogFormat is returned for an unrecognised format name.
	ErrLogFormat = errors.New("obs: unknown log format")
)

// NewLogger builds the process logger.
//
// level is one of "debug", "info", "warn" or "error"; an empty level means
// "info". format is "json" or "text"; an empty format means "json". A nil w
// writes to os.Stderr.
//
// The returned logger is safe for concurrent use.
func NewLogger(level, format string, w io.Writer) (*slog.Logger, error) {
	lvl, err := parseLevel(level)
	if err != nil {
		return nil, err
	}
	if w == nil {
		w = os.Stderr
	}
	opts := &slog.HandlerOptions{Level: lvl}

	var h slog.Handler
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", "json":
		h = slog.NewJSONHandler(w, opts)
	case "text":
		h = slog.NewTextHandler(w, opts)
	default:
		return nil, fmt.Errorf("%w: %q (want json or text)", ErrLogFormat, format)
	}
	return slog.New(h), nil
}

// parseLevel maps a level name to a slog.Level.
func parseLevel(level string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		return slog.LevelDebug, nil
	case "", "info":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("%w: %q (want debug, info, warn or error)", ErrLogLevel, level)
	}
}
