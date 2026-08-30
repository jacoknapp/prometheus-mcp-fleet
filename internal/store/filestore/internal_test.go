// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package filestore

import (
	"errors"
	"io/fs"
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

func TestOpenReportsStatFailure(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte(`{"schemaVersion":1}`), FileMode); err != nil {
		t.Fatal(err)
	}
	want := errors.New("injected stat failure")
	_, err := Open(Options{
		Path: path,
		stat: func(string) (fs.FileInfo, error) { return nil, want },
	})
	if !errors.Is(err, want) || !strings.Contains(err.Error(), "stat") {
		t.Errorf("Open error = %v, want named stat failure", err)
	}
}

func TestOpenReportsInitialWriteFailure(t *testing.T) {
	t.Parallel()
	want := errors.New("injected create-temp failure")
	_, err := Open(Options{
		Path: filepath.Join(t.TempDir(), "state.json"),
		createTemp: func(string, string) (tempFile, error) {
			return nil, want
		},
	})
	if !errors.Is(err, want) || !strings.Contains(err.Error(), "temp file") {
		t.Errorf("Open error = %v, want initial temp-file failure", err)
	}
}

func TestWriteReportsEveryTemporaryFileFailure(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		configure func(*fakeTempFile)
		want      string
		wantClose bool
	}{
		{"write", func(f *fakeTempFile) { f.writeErr = errors.New("write failed") }, "write", true},
		{"sync", func(f *fakeTempFile) { f.syncErr = errors.New("sync failed") }, "sync", true},
		{"close", func(f *fakeTempFile) { f.closeErr = errors.New("close failed") }, "close", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "state.json")
			s, err := Open(Options{Path: path})
			if err != nil {
				t.Fatal(err)
			}
			before := append([]byte(nil), s.data...)
			f := &fakeTempFile{name: filepath.Join(filepath.Dir(path), "fake.tmp")}
			tc.configure(f)
			s.createTemp = func(string, string) (tempFile, error) { return f, nil }
			err = s.write([]byte(`{"schemaVersion":1,"epoch":9}`))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("write error = %v, want %q failure", err, tc.want)
			}
			if tc.wantClose && f.closes == 0 {
				t.Error("temporary file was not closed after failure")
			}
			if string(s.data) != string(before) {
				t.Error("failed write changed the in-memory committed document")
			}
		})
	}
}

type fakeTempFile struct {
	name                        string
	writeErr, syncErr, closeErr error
	closes                      int
}

func (f *fakeTempFile) Name() string { return f.name }
func (f *fakeTempFile) Write(p []byte) (int, error) {
	if f.writeErr != nil {
		return 0, f.writeErr
	}
	return len(p), nil
}
func (f *fakeTempFile) Sync() error { return f.syncErr }
func (f *fakeTempFile) Close() error {
	f.closes++
	return f.closeErr
}
