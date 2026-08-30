// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package authn

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/fleet"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/token"
)

// TestDecoyRunsOnKeyIdentifierMiss proves the constant-work branch is actually
// taken. Without it, "no such KID" returns after a map probe while "wrong
// secret" returns after an HMAC, and an attacker can enumerate live key
// identifiers with a stopwatch.
func TestDecoyRunsOnKeyIdentifierMiss(t *testing.T) {
	t.Parallel()
	v, store, _, _ := newTestVerifier(t, nil)
	var decoys atomic.Int64
	real := v.decoy
	v.decoy = func(secret []byte) {
		decoys.Add(1)
		real(secret)
	}

	unknown, err := token.Mint(fleet.ClassAgent)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if _, err := v.Verify(context.Background(), unknown.Raw.Reveal(), fleet.ClassAgent); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("Verify(unknown) error = %v, want %v", err, ErrUnauthenticated)
	}
	if got := decoys.Load(); got != 1 {
		t.Fatalf("decoy invocations on a key-identifier miss = %d, want 1", got)
	}

	// The hit path must not run the decoy: it does the real HMAC instead.
	raw, _ := mintKey(t, store, v.hasher, fleet.ClassAgent, nil)
	if _, err := v.Verify(context.Background(), raw, fleet.ClassAgent); err != nil {
		t.Fatalf("Verify(known): %v", err)
	}
	if got := decoys.Load(); got != 1 {
		t.Errorf("decoy invocations after a successful verify = %d, want 1", got)
	}

	// A store that fails for a reason other than "absent" still gets the
	// constant work, because the caller cannot tell the two apart either.
	store.setErrs(errors.New("api server unreachable"), nil)
	raw2, _ := mintKey(t, store, v.hasher, fleet.ClassAgent, nil)
	_, _ = v.Verify(context.Background(), raw2, fleet.ClassAgent)
	if got := decoys.Load(); got != 2 {
		t.Errorf("decoy invocations after a store failure = %d, want 2", got)
	}
}
