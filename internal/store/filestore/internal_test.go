// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package filestore

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/store"
)

// TestReadRejectsCorruptInMemoryState covers the defensive decode check in
// read. Nothing reachable through the public API can put an undecodable
// document in s.data -- Open validates and write only ever stores its own
// encoding -- but the check is what makes that a checked invariant rather
// than an assumption.
func TestReadRejectsCorruptInMemoryState(t *testing.T) {
	t.Parallel()
	s, err := Open(Options{Path: filepath.Join(t.TempDir(), "state.json")})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	s.data = []byte("{not json")
	if _, err := s.read(t.Context()); !errors.Is(err, store.ErrCorrupt) {
		t.Errorf("read error = %v, want ErrCorrupt", err)
	}
}

// TestWriteRenameFailure covers the rename branch, which is the one write
// failure that a caller can actually provoke: something else took the target
// path and is not a file.
func TestWriteRenameFailure(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	s, err := Open(Options{Path: path})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(path, "occupied"), nil, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	err = s.write([]byte(`{"schemaVersion":1}`))
	if err == nil || !strings.Contains(err.Error(), "rename onto") {
		t.Errorf("write error = %v, want a rename failure", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("a failed write left the temp file %s behind", e.Name())
		}
	}
}

// TestOpenUnreadableFile covers the read branch of Open for a path that
// exists but cannot be read as a file.
func TestOpenUnreadableFile(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if _, err := Open(Options{Path: path}); err == nil || !strings.Contains(err.Error(), "read") {
		t.Errorf("Open error = %v, want a read failure", err)
	}
}
