// Copyright The prometheus-mcp-fleet Authors.
// SPDX-License-Identifier: Apache-2.0

package mcptools

import (
	"errors"
	"fmt"

	"github.com/jacoknapp/prometheus-mcp-fleet/internal/render"
)

// parseFormat resolves the format argument, defaulting to
// [render.FormatCompact].
//
// allowJSON is false for the tools that have no upstream payload to pass
// through — a cluster listing is assembled by the hub, so "the raw Prometheus
// shape" does not exist for it, and silently accepting the argument would
// teach a model that it did something it did not.
func parseFormat(s string, allowJSON bool) (render.Format, *ToolError) {
	f, err := render.ParseFormat(s)
	if err != nil {
		if errors.Is(err, render.ErrUnknownFormat) {
			return "", newError(CodeInvalidArgument,
				fmt.Sprintf("format %q is not one of compact, json, table",
					render.ClipRunes(s, 32)), false).
				WithInput(map[string]any{"format": render.ClipRunes(s, 32)}).
				WithHint("Use compact unless a previous compact call lost detail you need.")
		}
		return "", newError(CodeInvalidArgument, err.Error(), false)
	}
	if f == render.FormatJSON && !allowJSON {
		return "", newError(CodeInvalidArgument,
			"format \"json\" is not available for this tool: it has no upstream Prometheus "+
				"payload to pass through", false).
			WithInput(map[string]any{"format": "json"}).
			WithHint("Use compact or table.")
	}
	return f, nil
}
