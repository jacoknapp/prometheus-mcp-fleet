// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package obs

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestNewLogger(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		level, format string
		wantDebug     bool
		wantJSON      bool
	}{
		{name: "debug json", level: "debug", format: "json", wantDebug: true, wantJSON: true},
		{name: "info json", level: "info", format: "json", wantJSON: true},
		{name: "warn text", level: "warn", format: "text"},
		{name: "warning alias", level: "warning", format: "text"},
		{name: "error text", level: "error", format: "text"},
		{name: "defaults", level: "", format: "", wantJSON: true},
		{name: "case and space insensitive", level: " DEBUG ", format: " JSON ", wantDebug: true, wantJSON: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var buf bytes.Buffer
			log, err := NewLogger(tc.level, tc.format, &buf)
			if err != nil {
				t.Fatalf("NewLogger(%q, %q) error = %v", tc.level, tc.format, err)
			}
			log.Debug("dbg")
			log.Error("err", "k", "v")

			out := buf.String()
			if got := strings.Contains(out, "dbg"); got != tc.wantDebug {
				t.Errorf("debug record present = %v, want %v (%q)", got, tc.wantDebug, out)
			}
			if !strings.Contains(out, "err") {
				t.Fatalf("error record missing from %q", out)
			}
			line := strings.TrimSpace(strings.Split(strings.TrimSpace(out), "\n")[len(strings.Split(strings.TrimSpace(out), "\n"))-1])
			var m map[string]any
			isJSON := json.Unmarshal([]byte(line), &m) == nil
			if isJSON != tc.wantJSON {
				t.Errorf("output is JSON = %v, want %v (%q)", isJSON, tc.wantJSON, line)
			}
		})
	}
}

func TestNewLoggerErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		level, format string
		want          error
	}{
		{name: "bad level", level: "trace", format: "json", want: ErrLogLevel},
		{name: "bad format", level: "info", format: "logfmt", want: ErrLogFormat},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			log, err := NewLogger(tc.level, tc.format, nil)
			if !errors.Is(err, tc.want) {
				t.Fatalf("NewLogger() error = %v, want %v", err, tc.want)
			}
			if log != nil {
				t.Error("NewLogger() returned a logger alongside an error")
			}
		})
	}
}

func TestNewLoggerNilWriterDoesNotPanic(t *testing.T) {
	t.Parallel()

	log, err := NewLogger("error", "json", nil)
	if err != nil {
		t.Fatalf("NewLogger() error = %v", err)
	}
	log.Debug("this goes to stderr and must not panic")
}
