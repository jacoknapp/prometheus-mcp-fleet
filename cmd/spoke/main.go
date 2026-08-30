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
	"os"
	"os/signal"
	"syscall"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/config"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/spoke"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/version"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		fmt.Fprintf(os.Stderr, "spoke: %v\n", err)
		os.Exit(1)
	}
}

// run is separated from main so that the exit path is the only thing main does,
// which keeps the error handling testable.
func run(args []string) error {
	if len(args) > 0 && args[0] == "version" {
		fmt.Println(version.Get())
		return nil
	}

	cfg, err := config.LoadSpoke(args, os.Getenv)
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

	return spoke.Run(ctx, cfg)
}
