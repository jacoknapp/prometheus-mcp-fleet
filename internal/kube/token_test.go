// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package kube

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestTokenSource(t *testing.T) {
	t.Parallel()

	t.Run("empty path", func(t *testing.T) {
		t.Parallel()
		ts := newTokenSource("", DefaultTokenTTL, time.Now, slog.New(slog.DiscardHandler))
		got, err := ts.get()
		if err != nil || got != "" {
			t.Errorf("get() = %q, %v; want an empty token and no error", got, err)
		}
	})

	t.Run("missing file", func(t *testing.T) {
		t.Parallel()
		ts := newTokenSource(filepath.Join(t.TempDir(), "absent"), DefaultTokenTTL, time.Now, slog.New(slog.DiscardHandler))
		if _, err := ts.get(); err == nil {
			t.Error("get() = nil, want an error for an unreadable token")
		}
	})

	t.Run("read failure before first token", func(t *testing.T) {
		t.Parallel()
		ts := newTokenSource("/proc/self/mem", 0, time.Now, slog.New(slog.DiscardHandler))
		if _, err := ts.get(); err == nil || !strings.Contains(err.Error(), "token file") {
			t.Errorf("get() = %v, want a read failure", err)
		}
	})

	t.Run("empty file", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "token")
		writeTokenFile(t, path, "   \n", 1)
		ts := newTokenSource(path, 0, time.Now, slog.New(slog.DiscardHandler))
		if _, err := ts.get(); err == nil || !strings.Contains(err.Error(), "is empty") {
			t.Fatalf("get() = %v, want an empty-token error", err)
		}
		// It must not have been cached: the file becoming valid has to be
		// picked up on the very next call.
		writeTokenFile(t, path, "now-valid", 2)
		got, err := ts.get()
		if err != nil || got != "now-valid" {
			t.Errorf("get() = %q, %v; want the newly written token", got, err)
		}
	})

	t.Run("trims whitespace", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "token")
		writeTokenFile(t, path, "tok\n", 1)
		ts := newTokenSource(path, DefaultTokenTTL, time.Now, slog.New(slog.DiscardHandler))
		got, err := ts.get()
		if err != nil {
			t.Fatalf("get(): %v", err)
		}
		if got != "tok" {
			t.Errorf("get() = %q, want the trailing newline stripped", got)
		}
	})

	t.Run("caches within the ttl and re-reads after rotation", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "token")
		writeTokenFile(t, path, "v1", 1000)
		now := time.Unix(0, 0)
		ts := newTokenSource(path, DefaultTokenTTL, func() time.Time { return now }, slog.New(slog.DiscardHandler))

		if got, _ := ts.get(); got != "v1" {
			t.Fatalf("get() = %q, want v1", got)
		}
		writeTokenFile(t, path, "v2", 2000)
		if got, _ := ts.get(); got != "v1" {
			t.Errorf("get() inside the ttl = %q, want the cached v1", got)
		}

		now = now.Add(DefaultTokenTTL)
		if got, _ := ts.get(); got != "v2" {
			t.Errorf("get() after the ttl = %q, want the rotated v2", got)
		}
	})

	t.Run("unchanged mtime skips the read", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "token")
		writeTokenFile(t, path, "v1", 1000)
		now := time.Unix(0, 0)
		ts := newTokenSource(path, DefaultTokenTTL, func() time.Time { return now }, slog.New(slog.DiscardHandler))
		if got, _ := ts.get(); got != "v1" {
			t.Fatalf("get() = %q, want v1", got)
		}

		// Same length, same mtime: the kubelet cannot produce this, and the
		// documented contract is that it is not detected.
		if err := os.WriteFile(path, []byte("v9"), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		setMtime(t, path, 1000)
		now = now.Add(time.Hour)
		if got, _ := ts.get(); got != "v1" {
			t.Errorf("get() = %q, want the cached v1 for an unchanged mtime and size", got)
		}

		// A size change alone is enough, even at the same mtime.
		writeTokenFile(t, path, "v9-longer", 1000)
		now = now.Add(time.Hour)
		if got, _ := ts.get(); got != "v9-longer" {
			t.Errorf("get() = %q, want the re-read token", got)
		}
	})

	t.Run("keeps the cached token when the file disappears mid-rotation", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "token")
		writeTokenFile(t, path, "v1", 1000)
		now := time.Unix(0, 0)
		ts := newTokenSource(path, DefaultTokenTTL, func() time.Time { return now }, slog.New(slog.DiscardHandler))
		if got, _ := ts.get(); got != "v1" {
			t.Fatalf("get() = %q, want v1", got)
		}
		if err := os.Remove(path); err != nil {
			t.Fatalf("remove: %v", err)
		}
		now = now.Add(time.Hour)
		got, err := ts.get()
		if err != nil {
			t.Fatalf("get() = %v, want the cached token rather than an error", err)
		}
		if got != "v1" {
			t.Errorf("get() = %q, want the cached v1", got)
		}
	})

	t.Run("keeps the cached token when the file becomes unreadable", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("running as root: file modes do not deny reads")
		}
		t.Parallel()
		path := filepath.Join(t.TempDir(), "token")
		writeTokenFile(t, path, "v1", 1000)
		now := time.Unix(0, 0)
		ts := newTokenSource(path, DefaultTokenTTL, func() time.Time { return now }, slog.New(slog.DiscardHandler))
		if got, _ := ts.get(); got != "v1" {
			t.Fatalf("get() = %q, want v1", got)
		}
		writeTokenFile(t, path, "v2", 2000)
		if err := os.Chmod(path, 0o000); err != nil {
			t.Fatalf("chmod: %v", err)
		}
		now = now.Add(time.Hour)
		got, err := ts.get()
		if err != nil || got != "v1" {
			t.Errorf("get() = %q, %v; want the cached v1", got, err)
		}
	})

	t.Run("keeps cached token after a post-stat read failure", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "token")
		writeTokenFile(t, path, "v1", 1000)
		now := time.Unix(0, 0)
		ts := newTokenSource(path, DefaultTokenTTL, func() time.Time { return now }, slog.New(slog.DiscardHandler))
		if got, err := ts.get(); err != nil || got != "v1" {
			t.Fatalf("initial get() = %q, %v", got, err)
		}
		ts.path = "/proc/self/mem"
		now = now.Add(time.Hour)
		if got, err := ts.get(); err != nil || got != "v1" {
			t.Errorf("get() after read failure = %q, %v; want cached v1", got, err)
		}
	})

	t.Run("concurrent readers", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "token")
		writeTokenFile(t, path, "v1", 1000)
		ts := newTokenSource(path, 0, time.Now, slog.New(slog.DiscardHandler))
		var wg sync.WaitGroup
		for range 16 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if got, err := ts.get(); err != nil || got != "v1" {
					t.Errorf("get() = %q, %v", got, err)
				}
			}()
		}
		wg.Wait()
	})
}
