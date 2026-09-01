// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package ca

import "fmt"

// NewRootPEM mints a fresh self-signed root and returns its certificate and
// private key as PEM, writing nothing anywhere.
//
// This is the successor a rotation begins with. [Create] is the same
// generation followed by two exclusive file commits, and files are the wrong
// destination here: the hub has no PersistentVolumeClaim, its only durable
// state is a Kubernetes Secret (ADR-0005), and a successor written to a pod's
// emptyDir would be a root that one replica knows about and the fleet does
// not.
//
// The returned root signs nothing yet. Promoting it is [CA.AdoptPEM], and the
// order in which that happens across the fleet is the whole of
// docs/adr/0015-ca-rotation.md.
func NewRootPEM(opts Options) (certPEM, keyPEM []byte, err error) {
	opts = opts.withDefaults()
	if err := opts.validate(); err != nil {
		return nil, nil, err
	}
	_, _, certPEM, keyPEM, err = mintRoot(opts)
	if err != nil {
		return nil, nil, err
	}
	return certPEM, keyPEM, nil
}

// AdoptPEM replaces this authority's signer and trust bundle in one atomic
// step, so that every holder of the *CA -- the tunnel's verifier, the
// enrollment and renewal handlers, the /pki/bundle route -- follows the change
// without being rebuilt.
//
// It is how a replica catches up with a rotation another replica performed.
// There is no PersistentVolumeClaim and no channel between replicas, so a
// rotation is observed by re-reading the Secret; what is read is handed
// straight to this method.
//
// Nothing is mutated unless everything validates. A hub left half-rotated --
// a new signer with the old bundle, or the reverse -- issues certificates it
// then refuses, so the failure mode on bad material must be "carry on with
// what we had", never "carry on with part of what we were given".
//
// additionalRootsPEM is additive exactly as [Options.AdditionalRootsPEM] is:
// the incoming signer is always trusted, and cannot be configured out.
func (c *CA) AdoptPEM(certPEM, keyPEM, additionalRootsPEM []byte) error {
	opts := c.opts
	opts.AdditionalRootsPEM = additionalRootsPEM
	cert, key, additional, err := parseMaterial(certPEM, keyPEM, opts)
	if err != nil {
		return fmt.Errorf("adopt rotated CA material: %w", err)
	}
	c.material.Store(newMaterial(cert, key, additional))
	return nil
}
