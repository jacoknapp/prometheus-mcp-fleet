// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

// Command spoke runs the per-cluster agent.
//
// It dials out to the hub over mutually authenticated TLS, serves that
// cluster's Prometheus HTTP API back through the tunnel, and publishes cluster
// facts so the hub can route and so an AI agent can discover what exists
// without querying. It listens for nothing but its own metrics and health.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/config"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/spoke"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/version"
)

func main() {
	mainWithExit(os.Args[1:], os.Stderr, os.Exit)
}

func mainWithExit(args []string, stderr io.Writer, exit func(int)) {
	if err := run(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			exit(0)
			return
		}
		// Nothing useful remains if the diagnostic itself cannot be written:
		// the process is on its way out and stderr is the only channel it has.
		_, _ = fmt.Fprintf(stderr, "spoke: %v\n", err)
		exit(1)
	}
}

// run is separated from main so that the exit path is the only thing main does,
// which keeps the error handling testable.
func run(args []string) error {
	return runWith(args, os.Getenv, os.Stdout, spoke.Run)
}

// runWith contains the command wiring while allowing tests to exercise the
// successful lifecycle without dialing a hub or sending process signals.
func runWith(
	args []string,
	getenv func(string) string,
	stdout io.Writer,
	runSpoke func(context.Context, *config.Spoke) error,
) error {
	if len(args) > 0 && args[0] == "version" {
		if _, err := fmt.Fprintln(stdout, version.Get()); err != nil {
			return err
		}
		return nil
	}

	cfg, err := config.LoadSpoke(args, getenv)
	if err != nil {
		return err
	}
	if err := cfg.Validate(); err != nil {
		return err
	}

	// SIGTERM is what Kubernetes sends; SIGINT is what a developer sends. Both
	// begin the same graceful drain.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()

	return runSpoke(ctx, cfg)
}
