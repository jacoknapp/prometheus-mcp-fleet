// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package promproxy

// held reports the current in-flight count for a cluster. It intentionally
// lives in a test file: production makes decisions only through acquire and
// release, while tests need to assert the resulting internal accounting.
func (s *inflightSem) held(clusterID string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.inflight[clusterID]
}

// available reports the currently unreserved byte budget for behavioral
// assertions about cancellation, FIFO grants and cleanup.
func (s *byteSem) available() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.free
}
