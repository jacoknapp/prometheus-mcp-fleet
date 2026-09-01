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
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/config"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/hub"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/hubcli"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/version"
)

func main() {
	mainWithExit(os.Args[1:], os.Stderr, os.Exit)
}

func mainWithExit(args []string, stderr io.Writer, exit func(int)) {
	if err := run(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			// flag has already written the usage text to the FlagSet's output.
			// Discarding the error here is what makes `--help` a success; it
			// used to print nothing at all, because the usage went to a writer
			// nothing surfaced.
			_, _ = fmt.Fprintln(stderr, err)
			exit(0)
			return
		}
		// Nothing useful remains if the diagnostic itself cannot be written:
		// the process is on its way out and stderr is the only channel it has.
		_, _ = fmt.Fprintf(stderr, "hub: %v\n", err)
		exit(1)
	}
}

// run is separated from main so that the exit path is the only thing main
// does, which keeps error handling testable.
func run(args []string) error {
	return runWith(args, os.Getenv, os.Stdout, hub.Run)
}

// runWith contains the command wiring while allowing tests to exercise the
// successful lifecycle without starting listeners or sending process signals.
func runWith(
	args []string,
	getenv func(string) string,
	stdout io.Writer,
	runHub func(context.Context, *config.Hub) error,
) error {
	if len(args) > 0 && args[0] == "version" {
		if _, err := fmt.Fprintln(stdout, version.Get()); err != nil {
			return err
		}
		return nil
	}

	// Administrative subcommands talk to the hub's loopback admin API rather
	// than starting a server. They are documented as
	// `kubectl exec deploy/pmf-hub -- hub enroll create ...`, which is why they
	// live in the same binary as the server.
	if len(args) > 0 && (args[0] == "enroll" || args[0] == "keys") {
		return hubcli.Run(context.Background(), args, getenv, stdout, nil)
	}

	cfg, err := config.LoadHub(args, getenv)
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

	return runHub(ctx, cfg)
}
