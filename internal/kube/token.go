// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package kube

import (
	"bytes"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"
)

// DefaultTokenTTL is how long a projected service account token is reused
// before the file is re-stat'ed.
//
// The kubelet refreshes a projected token when 80% of its lifetime has
// elapsed -- an hour or more in practice -- and replaces the file by rename,
// so a stat every 30 seconds detects a rotation long before the old token
// expires, while keeping the API call path free of a read syscall per
// request.
const DefaultTokenTTL = 30 * time.Second

// tokenSource reads a bearer token from a file that another process rewrites
// underneath it.
//
// It caches the bytes together with the mtime and size they were read at. A
// get within the TTL returns the cache untouched; after the TTL it stats the
// file and re-reads only when mtime or size moved. It is safe for concurrent
// use.
type tokenSource struct {
	path string
	ttl  time.Duration
	now  func() time.Time
	log  *slog.Logger

	mu      sync.Mutex
	token   string
	mod     time.Time
	size    int64
	checked time.Time
	loaded  bool
}

// newTokenSource returns a source reading path. An empty path yields a source
// that always returns an empty token, which is what a kubeconfig-less test
// server wants.
func newTokenSource(path string, ttl time.Duration, now func() time.Time, log *slog.Logger) *tokenSource {
	return &tokenSource{path: path, ttl: ttl, now: now, log: log}
}

// get returns the current token.
//
// A stat or read failure after the token has been loaded once is not fatal:
// the kubelet's rename is not atomic from the perspective of an unlucky
// reader on every filesystem, and failing a request because of a momentarily
// missing file would turn a rotation into an outage. The previous token is
// reused and the failure is logged. A failure before any successful read is
// returned, because there is nothing to fall back to.
func (s *tokenSource) get() (string, error) {
	if s.path == "" {
		return "", nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	if s.loaded && now.Sub(s.checked) < s.ttl {
		return s.token, nil
	}

	fi, err := os.Stat(s.path)
	if err != nil {
		if s.loaded {
			s.log.Warn("kube: service account token stat failed, reusing cached token",
				"path", s.path, "error", err)
			return s.token, nil
		}
		return "", fmt.Errorf("token file %s: %w", s.path, err)
	}
	s.checked = now
	if s.loaded && fi.ModTime().Equal(s.mod) && fi.Size() == s.size {
		return s.token, nil
	}

	raw, err := os.ReadFile(s.path)
	if err != nil {
		if s.loaded {
			s.log.Warn("kube: service account token read failed, reusing cached token",
				"path", s.path, "error", err)
			return s.token, nil
		}
		return "", fmt.Errorf("token file %s: %w", s.path, err)
	}
	// The projected file has no trailing newline, but a hand-written one for
	// local development usually does, and a token with a stray newline is
	// rejected by the API server with a 401 that explains nothing.
	tok := string(bytes.TrimSpace(raw))
	if tok == "" {
		// Deliberately not cached: an empty token is never usable, and
		// caching it would hide the moment the file becomes valid.
		return "", fmt.Errorf("token file %s is empty", s.path)
	}
	s.token = tok
	s.mod = fi.ModTime()
	s.size = fi.Size()
	s.loaded = true
	return s.token, nil
}
