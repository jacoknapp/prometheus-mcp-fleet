#!/usr/bin/env bash
# Copyright The prometheus-mcp-fleet Authors.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

allow_file="${1:-hack/deadcode.allow}"
observed="$(mktemp)"
allowed="$(mktemp)"
trap 'rm -f "${observed}" "${allowed}"' EXIT

go run golang.org/x/tools/cmd/deadcode@v0.49.0 ./cmd/... \
	| sed 's/^.*unreachable func: //' \
	| LC_ALL=C sort -u >"${observed}"
sed -E '/^[[:space:]]*(#|$)/d' "${allow_file}" | LC_ALL=C sort -u >"${allowed}"

unknown="$(comm -23 "${observed}" "${allowed}")"
stale="$(comm -13 "${observed}" "${allowed}")"
if [[ -n "${unknown}" ]]; then
	echo "unreviewed unreachable production functions:" >&2
	echo "${unknown}" >&2
	exit 1
fi
if [[ -n "${stale}" ]]; then
	echo "stale deadcode allow-list entries (remove or re-review them):" >&2
	echo "${stale}" >&2
	exit 1
fi

echo "deadcode: no unreviewed unreachable production functions"
