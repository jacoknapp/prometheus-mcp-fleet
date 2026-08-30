// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package kube

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
)

// Verb names used in errors and in the 409 disambiguation.
const (
	verbGetSecret    = "get secret"
	verbCreateSecret = "create secret"
	verbUpdateSecret = "update secret"
)

// Secret is the subset of a Kubernetes Secret this project uses.
//
// Data holds raw bytes. The API server's JSON representation is base64, which
// encoding/json applies to a []byte automatically in both directions, so a
// value containing NUL or any other arbitrary byte round trips unchanged.
type Secret struct {
	// Name is the object name within the client's namespace.
	Name string
	// ResourceVersion is the API server's opaque optimistic-concurrency
	// token. It is returned by every call and must be echoed back to
	// [Client.UpdateSecret].
	ResourceVersion string
	// Data maps key to raw value.
	Data map[string][]byte
	// Labels are the object's labels.
	Labels map[string]string
	// Annotations are the object's annotations.
	Annotations map[string]string
}

// wireSecret is the JSON representation exchanged with the API server.
type wireSecret struct {
	APIVersion string   `json:"apiVersion,omitempty"`
	Kind       string   `json:"kind,omitempty"`
	Metadata   wireMeta `json:"metadata"`
	// Type is Opaque for everything this project writes.
	Type string            `json:"type,omitempty"`
	Data map[string][]byte `json:"data,omitempty"`
}

// wireMeta is the subset of metav1.ObjectMeta this package sends and reads.
type wireMeta struct {
	Name            string            `json:"name,omitempty"`
	Namespace       string            `json:"namespace,omitempty"`
	ResourceVersion string            `json:"resourceVersion,omitempty"`
	Labels          map[string]string `json:"labels,omitempty"`
	Annotations     map[string]string `json:"annotations,omitempty"`
}

// toWire renders s for the API server in namespace ns.
func (s *Secret) toWire(ns string) *wireSecret {
	return &wireSecret{
		APIVersion: "v1",
		Kind:       "Secret",
		Metadata: wireMeta{
			Name:            s.Name,
			Namespace:       ns,
			ResourceVersion: s.ResourceVersion,
			Labels:          maps.Clone(s.Labels),
			Annotations:     maps.Clone(s.Annotations),
		},
		Type: "Opaque",
		Data: maps.Clone(s.Data),
	}
}

// secret converts a decoded response into the domain type. Every map is a
// fresh allocation, so a caller may mutate the result freely.
func (w *wireSecret) secret() *Secret {
	s := &Secret{
		Name:            w.Metadata.Name,
		ResourceVersion: w.Metadata.ResourceVersion,
		Data:            make(map[string][]byte, len(w.Data)),
		Labels:          maps.Clone(w.Metadata.Labels),
		Annotations:     maps.Clone(w.Metadata.Annotations),
	}
	maps.Copy(s.Data, w.Data)
	return s
}

// secretPath returns the collection or object path for the namespace.
func (c *Client) secretPath(name string) string {
	p := "/api/v1/namespaces/" + c.ns + "/secrets"
	if name != "" {
		p += "/" + name
	}
	return p
}

// GetSecret returns the named Secret, or an error wrapping [ErrNotFound].
func (c *Client) GetSecret(ctx context.Context, name string) (*Secret, error) {
	if err := ValidateName(name); err != nil {
		return nil, fmt.Errorf("kube %s: %w", verbGetSecret, err)
	}
	var w wireSecret
	if err := c.do(ctx, verbGetSecret, http.MethodGet, c.secretPath(name), nil, &w); err != nil {
		return nil, fmt.Errorf("secret %s/%s: %w", c.ns, name, err)
	}
	return w.secret(), nil
}

// CreateSecret creates s and returns the stored object, including the
// resource version assigned to it. It returns an error wrapping
// [ErrAlreadyExists] if the name is taken, which a caller racing another
// replica for first-use initialisation treats as "re-read", not as a failure.
func (c *Client) CreateSecret(ctx context.Context, s *Secret) (*Secret, error) {
	if s == nil {
		return nil, errors.New("kube " + verbCreateSecret + ": secret is nil")
	}
	if err := ValidateName(s.Name); err != nil {
		return nil, fmt.Errorf("kube %s: %w", verbCreateSecret, err)
	}
	body := s.toWire(c.ns)
	// A create must not carry a resource version: the API server rejects it,
	// and a caller that has one is describing an update.
	body.Metadata.ResourceVersion = ""
	var w wireSecret
	if err := c.do(ctx, verbCreateSecret, http.MethodPost, c.secretPath(""), body, &w); err != nil {
		return nil, fmt.Errorf("secret %s/%s: %w", c.ns, s.Name, err)
	}
	return w.secret(), nil
}

// UpdateSecret replaces the named Secret, conditional on
// s.ResourceVersion still being current.
//
// This is the compare-and-swap the whole persistence design rests on. A 409
// from the API server means another writer got there first and is returned as
// an error wrapping [ErrConflict]; the caller must re-read, re-apply its
// change and try again. An empty ResourceVersion is refused rather than sent,
// because the API server treats it as an unconditional overwrite and would
// silently discard the other writer's change.
func (c *Client) UpdateSecret(ctx context.Context, s *Secret) (*Secret, error) {
	if s == nil {
		return nil, errors.New("kube " + verbUpdateSecret + ": secret is nil")
	}
	if err := ValidateName(s.Name); err != nil {
		return nil, fmt.Errorf("kube %s: %w", verbUpdateSecret, err)
	}
	if s.ResourceVersion == "" {
		return nil, fmt.Errorf("kube %s: secret %s/%s has no resource version, which would overwrite a concurrent write unconditionally",
			verbUpdateSecret, c.ns, s.Name)
	}
	var w wireSecret
	if err := c.do(ctx, verbUpdateSecret, http.MethodPut, c.secretPath(s.Name), s.toWire(c.ns), &w); err != nil {
		return nil, fmt.Errorf("secret %s/%s: %w", c.ns, s.Name, err)
	}
	return w.secret(), nil
}
