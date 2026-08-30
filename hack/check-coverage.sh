#!/usr/bin/env bash
# Copyright The prometheus-mcp-fleet Authors.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

profile="${1:-coverage.out}"
if [[ ! -s "${profile}" ]]; then
	echo "coverage profile is missing or empty: ${profile}" >&2
	exit 1
fi

filtered="$(mktemp)"
trap 'rm -f "${filtered}"' EXIT

# Generated protobuf is reviewed through buf breaking/generate checks. Every
# handwritten statement—including commands and test-support implementations—is
# held to the product's 100% contract.
awk '
	NR == 1 { print; next }
	$1 ~ /\/internal\/gen\// { next }
	{ print }
' "${profile}" > "${filtered}"

uncovered="$(awk 'NR > 1 && $3 == 0 { print }' "${filtered}")"
if [[ -n "${uncovered}" ]]; then
	echo "uncovered handwritten statement blocks:" >&2
	echo "${uncovered}" >&2
	exit 1
fi

total="$(go tool cover -func="${filtered}" | awk '/^total:/ { gsub(/%/, "", $NF); print $NF }')"
if [[ "${total}" != "100.0" ]]; then
	echo "handwritten statement coverage is ${total:-unknown}%, want 100.0%" >&2
	exit 1
fi

echo "handwritten statement coverage: ${total}%"
