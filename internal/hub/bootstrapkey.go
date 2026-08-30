// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package hub

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/fleet"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/store"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/token"
)

// bootstrapKeyName is the name given to the automatically minted first admin
// credential. It is a fixed name so that an operator can find and revoke it
// after issuing a properly scoped replacement.
const bootstrapKeyName = "bootstrap"

// bootstrapAdminKey mints the first admin credential, once, if none exists.
//
// Without it a freshly installed hub cannot be administered at all: there is no
// credential with which to mint an agent key or an enrollment token, and no
// out-of-band path to create one. The alternative designs are worse — a
// well-known default is a backdoor, and requiring the operator to pre-create a
// Secret puts a credential into Helm values, which `helm get values` will hand
// to anyone with namespace read.
//
// The token is printed exactly once, to the log, at warn level. It is the one
// place in this codebase that deliberately writes a credential to stdout, and
// it is bounded: it happens only when the store holds no admin key at all, so a
// restart never reprints it and never mints a second one.
func (h *hub) bootstrapAdminKey(ctx context.Context) error {
	existing, err := h.store.ListKeys(ctx, fleet.ClassAdmin)
	if err != nil {
		return fmt.Errorf("list admin keys: %w", err)
	}
	for _, k := range existing {
		if !k.Revoked() {
			// An admin credential already exists. Say nothing: logging even the
			// KID here on every start would be noise, and logging more would be
			// a leak.
			return nil
		}
	}

	minted, err := token.Mint(fleet.ClassAdmin)
	if err != nil {
		return fmt.Errorf("mint the bootstrap admin key: %w", err)
	}

	now := h.clock()
	record := &fleet.Key{
		KID:        minted.KID,
		Class:      fleet.ClassAdmin,
		Name:       bootstrapKeyName,
		SecretHMAC: h.hasher.Sum(minted.Secret),
		CreatedAt:  now,
		ExpiresAt:  now.Add(h.bootstrapTTL()),
	}
	if err := h.store.PutKey(ctx, record); err != nil {
		// Losing a create race with another replica is fine and expected: the
		// winner's key is the one that counts, and ours was never revealed.
		if errors.Is(err, store.ErrAlreadyExists) {
			return nil
		}
		return fmt.Errorf("store the bootstrap admin key: %w", err)
	}

	h.logger.Warn("BOOTSTRAP ADMIN TOKEN — shown once, store it now",
		"token", minted.Raw.Reveal(),
		"kid", minted.KID,
		"expires_at", record.ExpiresAt.Format(time.RFC3339),
		"note", "no admin credential existed, so one was created. "+
			"Mint a replacement and revoke this one: hub keys revoke "+minted.KID)
	return nil
}

// bootstrapTTL is how long the automatically minted admin key lives. It matches
// the configured admin lifetime where one is set, and otherwise defaults to the
// agent key TTL, so the bootstrap credential is never longer-lived than the
// credentials it is used to create.
func (h *hub) bootstrapTTL() time.Duration {
	if h.cfg.AgentKeyTTL > 0 {
		return h.cfg.AgentKeyTTL
	}
	return 720 * time.Hour
}

// clock returns the current time. It exists so tests can pin it.
func (h *hub) clock() time.Time {
	if h.now != nil {
		return h.now()
	}
	return time.Now()
}
