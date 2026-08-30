// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"os"
	"strings"
	"testing"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/config"
)

func TestRunWith(t *testing.T) {
	t.Parallel()

	wantRunErr := errors.New("run hub")
	tests := []struct {
		name      string
		args      []string
		getenv    func(string) string
		run       func(context.Context, *config.Hub) error
		wantErr   error
		wantError bool
		wantText  string
		wantRuns  int
	}{
		{
			name: "version",
			args: []string{"version"},
			getenv: func(string) string {
				t.Fatal("version consulted the environment")
				return ""
			},
			run: func(context.Context, *config.Hub) error {
				t.Fatal("version started the hub")
				return nil
			},
			wantText: "go1.",
		},
		{
			name:    "flag help",
			args:    []string{"--help"},
			getenv:  func(string) string { return "" },
			run:     func(context.Context, *config.Hub) error { return nil },
			wantErr: flag.ErrHelp,
		},
		{
			name:      "unknown flag",
			args:      []string{"--does-not-exist"},
			getenv:    func(string) string { return "" },
			run:       func(context.Context, *config.Hub) error { return nil },
			wantError: true,
		},
		{
			name:    "validation failure",
			getenv:  func(string) string { return "" },
			run:     func(context.Context, *config.Hub) error { return nil },
			wantErr: config.ErrInvalid,
		},
		{
			name: "valid config reaches hub",
			getenv: func(key string) string {
				if key == "PMF_PUBLIC_URL" {
					return "https://fleet.example/mcp"
				}
				return ""
			},
			run: func(ctx context.Context, cfg *config.Hub) error {
				if ctx == nil || cfg.PublicURL != "https://fleet.example/mcp" {
					t.Fatalf("run inputs: ctx=%v publicURL=%q", ctx, cfg.PublicURL)
				}
				return wantRunErr
			},
			wantErr:  wantRunErr,
			wantRuns: 1,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var stdout bytes.Buffer
			runs := 0
			runner := func(ctx context.Context, cfg *config.Hub) error {
				runs++
				return tc.run(ctx, cfg)
			}
			err := runWith(tc.args, tc.getenv, &stdout, runner)
			if tc.wantError {
				if err == nil {
					t.Fatal("runWith() error = nil, want an error")
				}
			} else if !errors.Is(err, tc.wantErr) {
				t.Fatalf("runWith() error = %v, want %v", err, tc.wantErr)
			}
			if runs != tc.wantRuns {
				t.Fatalf("hub runs = %d, want %d", runs, tc.wantRuns)
			}
			if !strings.Contains(stdout.String(), tc.wantText) {
				t.Fatalf("stdout = %q, want substring %q", stdout.String(), tc.wantText)
			}
		})
	}
}

func TestRunUsesProcessDependencies(t *testing.T) {
	t.Setenv("PMF_PUBLIC_URL", "")
	if err := run([]string{"--help"}); !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("run(--help) = %v, want flag.ErrHelp", err)
	}
}

func TestMainVersionPath(t *testing.T) {
	oldArgs, oldStdout := os.Args, os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Args, os.Stdout = []string{"hub", "version"}, w
	t.Cleanup(func() {
		os.Args, os.Stdout = oldArgs, oldStdout
		_ = r.Close()
		_ = w.Close()
	})

	main()
	if err := w.Close(); err != nil {
		t.Fatalf("close stdout pipe: %v", err)
	}
	out := make([]byte, 4096)
	n, err := r.Read(out)
	if err != nil {
		t.Fatalf("read stdout: %v", err)
	}
	if !strings.Contains(string(out[:n]), "go1.") {
		t.Fatalf("main stdout = %q", out[:n])
	}
}

func TestMainWithExit(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantStderr string
	}{
		{name: "help exits successfully", args: []string{"--help"}, wantCode: 0},
		{name: "bad flag exits with failure", args: []string{"--bad"}, wantCode: 1, wantStderr: "hub:"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var stderr bytes.Buffer
			codes := []int{}
			mainWithExit(tc.args, &stderr, func(code int) { codes = append(codes, code) })
			if len(codes) != 1 || codes[0] != tc.wantCode {
				t.Fatalf("exit codes = %v, want [%d]", codes, tc.wantCode)
			}
			if !strings.Contains(stderr.String(), tc.wantStderr) {
				t.Fatalf("stderr = %q, want substring %q", stderr.String(), tc.wantStderr)
			}
		})
	}
}
