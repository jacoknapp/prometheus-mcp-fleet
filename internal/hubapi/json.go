// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package hubapi

import (
	"encoding/json"
	"io"
)

// writeJSONBody encodes v to w. It is separate from
// [server.writeJSON] so a handler that has already written its own headers and
// status can still share one encoder configuration.
func writeJSONBody(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	return enc.Encode(v)
}
