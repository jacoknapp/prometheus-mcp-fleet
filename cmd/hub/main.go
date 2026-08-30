// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

// Command hub runs the fleet's Model Context Protocol server.
//
// It serves AI agents over Streamable HTTP, terminates the mutually
// authenticated tunnels that spokes dial, issues and revokes spoke identities,
// and keeps an in-memory registry of the fleet that the spokes themselves
// populate.
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
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/hub"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/version"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		fmt.Fprintf(os.Stderr, "hub: %v\n", err)
		os.Exit(1)
	}
}

// run is separated from main so that the exit path is the only thing main
// does, which keeps error handling testable.
func run(args []string) error {
	if len(args) > 0 && args[0] == "version" {
		fmt.Println(version.Get())
		return nil
	}

	cfg, err := config.LoadHub(args, os.Getenv)
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

	return hub.Run(ctx, cfg)
}
