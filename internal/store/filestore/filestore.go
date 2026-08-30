// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package filestore

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/fleet"
	"github.com/jacoknapp/prometheus-mcp-fleet/internal/store"
)

// FileMode is the permission bitmask the state file is created with and must
// still carry when it is read back. The document holds the HMAC of every
// issued credential, so a group-readable file is a credential disclosure.
const FileMode fs.FileMode = 0o600

// DirMode is the permission bitmask the containing directory is created with.
const DirMode fs.FileMode = 0o700

// ErrInsecureFile reports a state file readable or writable by anyone other
// than its owner. The hub refuses to start rather than serve credentials out
// of a world-readable file.
var ErrInsecureFile = errors.New("state file has insecure permissions")

// Options configures [Open].
type Options struct {
	// Path is the JSON state file. Its parent directory is created [DirMode]
	// and the file [FileMode]. Required.
	Path string
	// Clock supplies the current time for operations given a zero timestamp.
	// Nil means time.Now. Tests inject a fake clock here.
	Clock func() time.Time
	// MaxBytes bounds the encoded document, matching the production backend's
	// limit so that a state that would be refused in the cluster is also
	// refused locally. Zero means [store.MaxStateBytes]; negative is
	// unbounded.
	MaxBytes int
}

// Store is a store.Store backed by one JSON file.
type Store struct {
	path     string
	now      func() time.Time
	maxBytes int

	mu     sync.Mutex
	data   []byte
	closed bool
}

// Ensure the backend satisfies the interface it claims.
var _ store.Store = (*Store)(nil)

// Open loads the state file, creating an empty one if it does not exist.
//
// It returns an error wrapping [store.ErrCorrupt] for a file that is not a
// decodable document and [ErrInsecureFile] for one whose permissions expose
// it beyond its owner. Neither is recoverable automatically: silently
// re-initialising would discard every issued credential and every revocation.
func Open(opts Options) (*Store, error) {
	if opts.Path == "" {
		return nil, errors.New("filestore: path is required")
	}
	maxBytes := opts.MaxBytes
	if maxBytes == 0 {
		maxBytes = store.MaxStateBytes
	}
	s := &Store{path: opts.Path, now: store.Clock(opts.Clock), maxBytes: maxBytes}

	if dir := filepath.Dir(opts.Path); dir != "" {
		if err := os.MkdirAll(dir, DirMode); err != nil {
			return nil, fmt.Errorf("filestore: directory %s: %w", dir, err)
		}
	}
	raw, err := os.ReadFile(opts.Path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		fresh, encErr := store.NewState().Encode()
		if encErr != nil {
			return nil, fmt.Errorf("filestore: %w", encErr)
		}
		if err := s.write(fresh); err != nil {
			return nil, err
		}
		return s, nil
	case err != nil:
		return nil, fmt.Errorf("filestore: read %s: %w", opts.Path, err)
	}
	fi, err := os.Stat(opts.Path)
	if err != nil {
		return nil, fmt.Errorf("filestore: stat %s: %w", opts.Path, err)
	}
	if perm := fi.Mode().Perm(); perm&^FileMode != 0 {
		return nil, fmt.Errorf("filestore: %s is mode %#o, want %#o: %w",
			opts.Path, perm, FileMode, ErrInsecureFile)
	}
	if _, err := store.Decode(raw); err != nil {
		return nil, fmt.Errorf("filestore: %s: %w", opts.Path, err)
	}
	s.data = raw
	return s, nil
}

// Path returns the file the store is backed by.
func (s *Store) Path() string { return s.path }

// Size returns the encoded size of the current document in bytes. It is the
// value the hub publishes as promfleet_hub_state_bytes when running on this
// backend.
func (s *Store) Size() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.data)
}

// Close releases the store. It is idempotent.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return nil
}

// read decodes the current document under the lock.
func (s *Store) read(ctx context.Context) (*store.State, error) {
	if err := store.CheckContext(ctx, s.closed); err != nil {
		return nil, err
	}
	st, err := store.Decode(s.data)
	if err != nil {
		return nil, fmt.Errorf("filestore: %s: %w", s.path, err)
	}
	return st, nil
}

// mutate applies fn to the current document and persists the result when fn
// reports a change. The whole sequence runs under the mutex, so it is atomic
// with respect to every other method on this store.
func (s *Store) mutate(ctx context.Context, fn func(*store.State) (bool, error)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.read(ctx)
	if err != nil {
		return err
	}
	changed, err := fn(st)
	if err != nil {
		return err
	}
	if !changed {
		return nil
	}
	encoded, err := st.EncodeWithin(s.maxBytes)
	if err != nil {
		return fmt.Errorf("filestore: %s: %w", s.path, err)
	}
	return s.write(encoded)
}

// write atomically replaces the file with b and updates the in-memory copy.
//
// The temporary file is created in the target's own directory so that the
// rename is within one filesystem, and the directory is fsynced afterwards so
// that the rename itself is durable rather than merely the data.
func (s *Store) write(b []byte) error {
	dir := filepath.Dir(s.path)
	tmp, err := os.CreateTemp(dir, ".state-*.tmp")
	if err != nil {
		return fmt.Errorf("filestore: temp file in %s: %w", dir, err)
	}
	// os.CreateTemp creates the file 0600 with no umask involvement, which is
	// already [FileMode], so there is nothing to chmod.
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() // no-op once the rename succeeded

	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("filestore: write %s: %w", tmpName, err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("filestore: sync %s: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("filestore: close %s: %w", tmpName, err)
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		return fmt.Errorf("filestore: rename onto %s: %w", s.path, err)
	}
	if d, err := os.Open(dir); err == nil {
		// A failed directory sync is not worth failing the write over: the
		// rename is already visible to this machine, and the caller cannot do
		// anything useful with the error.
		_ = d.Sync()
		_ = d.Close()
	}
	s.data = b
	return nil
}

// PutKey implements store.Store.
func (s *Store) PutKey(ctx context.Context, k *fleet.Key) error {
	return s.mutate(ctx, func(st *store.State) (bool, error) { return st.PutKey(k) })
}

// GetKey implements store.Store.
func (s *Store) GetKey(ctx context.Context, kid string) (*fleet.Key, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.read(ctx)
	if err != nil {
		return nil, err
	}
	return st.GetKey(kid)
}

// ListKeys implements store.Store.
func (s *Store) ListKeys(ctx context.Context, class fleet.KeyClass) ([]*fleet.Key, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.read(ctx)
	if err != nil {
		return nil, err
	}
	return st.ListKeys(class), nil
}

// RevokeKey implements store.Store.
func (s *Store) RevokeKey(ctx context.Context, kid, reason string, at time.Time) error {
	return s.mutate(ctx, func(st *store.State) (bool, error) {
		return st.RevokeKey(kid, reason, at, s.now)
	})
}

// DeleteKey implements store.Store.
func (s *Store) DeleteKey(ctx context.Context, kid string) error {
	return s.mutate(ctx, func(st *store.State) (bool, error) { return st.DeleteKey(kid) })
}

// TouchKey implements store.Store.
func (s *Store) TouchKey(ctx context.Context, kid string, at time.Time) error {
	return s.mutate(ctx, func(st *store.State) (bool, error) { return st.TouchKey(kid, at, s.now) })
}

// BurnEnrollment implements store.Store.
func (s *Store) BurnEnrollment(ctx context.Context, kid, certSerial string, at time.Time) (*fleet.Key, error) {
	var burned *fleet.Key
	err := s.mutate(ctx, func(st *store.State) (bool, error) {
		k, changed, err := st.BurnEnrollment(kid, certSerial, at, s.now)
		burned = k
		return changed, err
	})
	if err != nil {
		return nil, err
	}
	return burned, nil
}

// RevokeCert implements store.Store.
func (s *Store) RevokeCert(ctx context.Context, rc store.RevokedCert) error {
	return s.mutate(ctx, func(st *store.State) (bool, error) { return st.RevokeCert(rc, s.now) })
}

// ListRevokedCerts implements store.Store.
func (s *Store) ListRevokedCerts(ctx context.Context) ([]store.RevokedCert, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.read(ctx)
	if err != nil {
		return nil, err
	}
	return st.ListRevokedCerts(), nil
}

// Epoch implements store.Store.
func (s *Store) Epoch(ctx context.Context) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.read(ctx)
	if err != nil {
		return 0, err
	}
	return st.Epoch, nil
}
