// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package hub

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/ca"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/config"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/kube"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/token"
)

// Keys inside the CA Secret.
const (
	secretKeyCACert = "ca.crt"
	secretKeyCAKey  = "ca.key"
	secretKeyPepper = "pepper.key"
)

// bootstrapper materialises the hub's long-lived secret material.
//
// There is no PersistentVolumeClaim (see ADR-0005), so the CA keypair and the
// HMAC pepper live in a Kubernetes Secret. The `ca` and `token` packages are
// file-based by design — they must work outside Kubernetes — so this type is
// the adapter between the two: it copies the Secret down into the pod's scratch
// directory before startup, and copies back anything generated on first boot.
//
// The scratch directory is an emptyDir. Nothing there is durable and nothing
// there is the source of truth.
type bootstrapper struct {
	client *kube.Client // nil when running with the file backend
	secret string
	dir    string
	logger *slog.Logger
}

// caMaterial is the CA keypair plus the pepper.
type caMaterial struct {
	certPEM, keyPEM, pepper []byte
}

// empty reports whether nothing at all is stored.
func (m caMaterial) empty() bool {
	return len(m.certPEM) == 0 && len(m.keyPEM) == 0 && len(m.pepper) == 0
}

// complete reports whether every field the hub needs is present.
//
// The distinction from empty matters: a Secret holding a CA but no pepper is
// neither. Treating it as complete would leave each replica hashing keys with
// its own emptyDir-local pepper, so a key minted on one replica would be
// unverifiable on any other and would stop verifying at all after a restart.
func (m caMaterial) complete() bool {
	return len(m.certPEM) > 0 && len(m.keyPEM) > 0 && len(m.pepper) > 0
}

// prepare ensures the CA and pepper exist both on disk and, when running in a
// cluster, in the Secret. It returns the loaded CA and hasher.
//
// The sequence matters. We read the Secret first and write its contents to disk
// *before* asking the ca and token packages to load-or-create, so that a
// restarting pod adopts the existing material rather than generating a second
// CA and orphaning every spoke in the fleet. Only material that did not already
// exist is written back.
func (b *bootstrapper) prepare(ctx context.Context, cfg *config.Hub) (*ca.CA, *token.Hasher, error) {
	if err := os.MkdirAll(b.dir, 0o700); err != nil {
		return nil, nil, fmt.Errorf("create scratch dir %s: %w", b.dir, err)
	}

	stored, err := b.load(ctx)
	if err != nil {
		return nil, nil, err
	}
	if err := b.materialise(stored, cfg); err != nil {
		return nil, nil, err
	}

	// LoadOrCreate is atomic and refuses to overwrite, so if two replicas start
	// together the loser adopts the winner's files rather than clobbering them.
	authority, err := ca.LoadOrCreate(cfg.CACertFile, cfg.CAKeyFile, ca.Options{
		TrustDomain:  cfg.TrustDomain,
		SpokeCertTTL: cfg.SpokeCertTTL,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("load or create the CA: %w", err)
	}

	pepper, err := token.LoadOrCreatePepper(cfg.PepperFile)
	if err != nil {
		return nil, nil, fmt.Errorf("load or create the pepper: %w", err)
	}
	hasher, err := token.NewHasher(pepper)
	if err != nil {
		return nil, nil, fmt.Errorf("configure the hasher: %w", err)
	}

	adopted, err := b.persist(ctx, stored, cfg, pepper)
	if err != nil {
		return nil, nil, err
	}
	if adopted {
		// We lost a create race and just overwrote our scratch files with the
		// winner's material. Everything loaded above is now stale — continuing
		// with it would mean signing spoke certificates with a CA no other
		// replica trusts, and verifying API keys against the wrong pepper.
		if authority, err = reloadAfterAdoption(cfg); err != nil {
			return nil, nil, fmt.Errorf("reload the adopted CA: %w", err)
		}
		adoptedPepper, perr := token.LoadOrCreatePepper(cfg.PepperFile)
		if perr != nil {
			return nil, nil, fmt.Errorf("reload the adopted pepper: %w", perr)
		}
		if hasher, err = token.NewHasher(adoptedPepper); err != nil {
			return nil, nil, fmt.Errorf("configure the hasher: %w", err)
		}
	}
	return authority, hasher, nil
}

// load reads the CA Secret. A missing Secret is not an error: it means first
// boot.
func (b *bootstrapper) load(ctx context.Context) (caMaterial, error) {
	if b.client == nil {
		return caMaterial{}, nil
	}
	sec, err := b.client.GetSecret(ctx, b.secret)
	switch {
	case errors.Is(err, kube.ErrNotFound):
		b.logger.Info("no CA secret yet; this hub will generate one", "secret", b.secret)
		return caMaterial{}, nil
	case err != nil:
		return caMaterial{}, fmt.Errorf("read CA secret %s: %w", b.secret, err)
	}
	return caMaterial{
		certPEM: sec.Data[secretKeyCACert],
		keyPEM:  sec.Data[secretKeyCAKey],
		pepper:  sec.Data[secretKeyPepper],
	}, nil
}

// materialise writes stored material to the scratch directory so the file-based
// loaders find it.
func (b *bootstrapper) materialise(m caMaterial, cfg *config.Hub) error {
	write := func(path string, data []byte) error {
		if len(data) == 0 || path == "" {
			return nil
		}
		// Skip the write when the file already holds exactly these bytes. That
		// is not just an optimisation: the configured path may be a projected
		// Secret mount, which is read-only, and rewriting identical content
		// there would turn a correct configuration into a startup failure.
		if existing, err := os.ReadFile(path); err == nil && bytes.Equal(existing, data) {
			return nil
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return err
		}
		return os.WriteFile(path, data, 0o600)
	}
	if err := write(cfg.CACertFile, m.certPEM); err != nil {
		return fmt.Errorf("write CA certificate: %w", err)
	}
	if err := write(cfg.CAKeyFile, m.keyPEM); err != nil {
		return fmt.Errorf("write CA key: %w", err)
	}
	if err := write(cfg.PepperFile, m.pepper); err != nil {
		return fmt.Errorf("write pepper: %w", err)
	}
	if !m.empty() {
		b.logger.Info("adopted existing CA material from the secret", "secret", b.secret)
	}
	return nil
}

// persist writes back anything that was generated on this boot.
//
// It deliberately never overwrites material that was already in the Secret. If
// another replica won the race and created the Secret first, this hub's freshly
// generated CA is discarded rather than published — a hub that overwrote a live
// CA would invalidate every certificate in the fleet.
// It returns adopted=true when another replica won the race, meaning the
// caller must discard whatever it loaded and re-read from disk.
func (b *bootstrapper) persist(
	ctx context.Context, stored caMaterial, cfg *config.Hub, pepper []byte,
) (adopted bool, err error) {
	if b.client == nil {
		return false, nil
	}
	if stored.complete() {
		return false, nil // nothing was generated; the Secret is authoritative
	}

	certPEM, err := os.ReadFile(cfg.CACertFile)
	if err != nil {
		return false, fmt.Errorf("read generated CA certificate: %w", err)
	}
	keyPEM, err := os.ReadFile(cfg.CAKeyFile)
	if err != nil {
		return false, fmt.Errorf("read generated CA key: %w", err)
	}

	data := map[string][]byte{
		secretKeyCACert: certPEM,
		secretKeyCAKey:  keyPEM,
		secretKeyPepper: pepper,
	}

	// A Secret that already exists but is missing a field is completed in
	// place. Only the absent fields are written: overwriting a live CA would
	// invalidate every certificate in the fleet, so an existing value always
	// wins over the one this process just generated.
	if !stored.empty() {
		return b.complete(ctx, stored, data)
	}

	_, err = b.client.CreateSecret(ctx, &kube.Secret{
		Name: b.secret,
		Data: data,
		Labels: map[string]string{
			"app.kubernetes.io/name":       "prometheus-mcp-fleet",
			"app.kubernetes.io/component":  "hub",
			"app.kubernetes.io/managed-by": "prometheus-mcp-hub",
		},
	})
	switch {
	case errors.Is(err, kube.ErrAlreadyExists):
		// Another replica created it between our read and our write. Its
		// material wins; adopt it and discard ours.
		b.logger.Warn("another replica created the CA secret first; adopting its material",
			"secret", b.secret)
		winner, lerr := b.load(ctx)
		if lerr != nil {
			return false, lerr
		}
		if winner.empty() {
			return false, fmt.Errorf("CA secret %s exists but is empty", b.secret)
		}
		if merr := b.materialise(winner, cfg); merr != nil {
			return false, merr
		}
		return true, nil
	case errors.Is(err, kube.ErrForbidden):
		return false, fmt.Errorf("cannot create the CA secret %s: %w\n"+
			"the hub needs a Role granting create on secrets restricted by "+
			"resourceNames to this object", b.secret, err)
	case err != nil:
		return false, fmt.Errorf("create CA secret %s: %w", b.secret, err)
	}

	b.logger.Info("generated and stored a new CA", "secret", b.secret)
	return false, nil
}

// reloadAfterAdoption re-loads the CA from disk. It is used after a lost
// create race, where the material on disk changed underneath the first load.
func reloadAfterAdoption(cfg *config.Hub) (*ca.CA, error) {
	return ca.Load(cfg.CACertFile, cfg.CAKeyFile, ca.Options{
		TrustDomain:  cfg.TrustDomain,
		SpokeCertTTL: cfg.SpokeCertTTL,
	})
}

// complete fills in the fields a partially populated Secret is missing.
//
// It never replaces a field that already has a value. That is the whole safety
// property: a hub that overwrote a live CA key would orphan every spoke in the
// fleet, and no failure mode is worth risking that.
func (b *bootstrapper) complete(
	ctx context.Context, stored caMaterial, generated map[string][]byte,
) (adopted bool, err error) {
	sec, err := b.client.GetSecret(ctx, b.secret)
	if err != nil {
		return false, fmt.Errorf("read CA secret %s: %w", b.secret, err)
	}
	if sec.Data == nil {
		sec.Data = make(map[string][]byte, len(generated))
	}

	filled := make([]string, 0, len(generated))
	for key, value := range generated {
		if len(sec.Data[key]) > 0 {
			continue // an existing value always wins
		}
		sec.Data[key] = value
		filled = append(filled, key)
	}
	if len(filled) == 0 {
		return false, nil
	}
	slices.Sort(filled)

	if _, err := b.client.UpdateSecret(ctx, sec); err != nil {
		if errors.Is(err, kube.ErrConflict) {
			// Another replica completed it first. Adopt whatever is there now.
			return true, nil
		}
		return false, fmt.Errorf("complete CA secret %s: %w", b.secret, err)
	}
	b.logger.Warn("completed a partially populated CA secret",
		"secret", b.secret, "filled", filled,
		"note", "existing fields were left untouched")

	// The fields we did not fill came from the Secret and are already on disk;
	// the ones we did fill are ours. Nothing to re-adopt.
	_ = stored
	return false, nil
}
