// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"errors"
	"fmt"
)

// Errors reported by the registry. Callers branch on these with errors.Is.
var (
	// ErrUnknownCluster reports a cluster the registry has never seen, or one
	// whose disconnect grace window has elapsed. It is joined with
	// [tunnel.ErrNotConnected] by [Registry.Session], so a caller that only
	// cares "can I route to it" tests the latter, while a caller building an
	// UNKNOWN_CLUSTER tool error with did-you-mean suggestions tests this one.
	ErrUnknownCluster = errors.New("registry: unknown cluster")
	// ErrRejectedSession reports a session the registry refused to admit:
	// no certificate identity, an unanswerable Describe, or a closed registry.
	// The transport should close the connection.
	ErrRejectedSession = errors.New("registry: session rejected")
	// ErrStaleGeneration reports a session whose generation is older than the
	// one already registered for that pod's slot in that cluster. It is the
	// losing side of the reconnect race and wraps [ErrRejectedSession].
	ErrStaleGeneration = fmt.Errorf("%w: stale generation", ErrRejectedSession)
	// ErrClosed reports use of a registry that has been closed.
	ErrClosed = errors.New("registry: closed")
)
