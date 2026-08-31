#!/usr/bin/env bash
# Copyright The prometheus-mcp-fleet Authors.
# SPDX-License-Identifier: Apache-2.0
#
# Mutation-test each package separately and compare its test efficacy against
# the recorded baseline in hack/mutation-baseline.txt.
#
# Why per package rather than one `./...` run: Gremlins takes a single package
# argument, and a single fleet-wide score would hide exactly what matters. A
# package whose every mutant is an unkillable capacity hint and a package whose
# survivors are missing boundary assertions can average to the same number.
#
# Why a baseline file rather than one global threshold: the achievable score
# differs per package for reasons that are properties of the code, not of the
# tests. Some mutants are equivalent -- internal/certproof sizes its transcript
# with make([]byte, 0, a+b+c), and mutating that arithmetic changes an
# allocation hint and nothing observable, because append grows the slice
# regardless -- so no test can kill them and the package's ceiling sits below
# 100 permanently. Holding every package to one number would force either a
# meaningless-low bar or contorted tests written to satisfy a tool.
#
# The baseline is a ratchet: a package may rise, never fall.

set -euo pipefail

GREMLINS_VERSION="${GREMLINS_VERSION:-v0.6.0}"
WORKERS="${MUTATION_WORKERS:-4}"
BASELINE="${MUTATION_BASELINE:-hack/mutation-baseline.txt}"

# Mutants are untrusted programs. A broken mutant can bypass Go's test timeout
# while allocating indefinitely, and parallel `go test` builds otherwise each
# use every host CPU. Keep one mutant from exhausting the runner while allowing
# the package sweep to continue and report it as killed/timed out.
MUTATION_GOMAXPROCS="${MUTATION_GOMAXPROCS:-2}"
MUTATION_GOMEMLIMIT="${MUTATION_GOMEMLIMIT:-3GiB}"
MUTATION_VMEM_KIB="${MUTATION_VMEM_KIB:-4194304}"

# Gremlins derives each mutant's test timeout from how long the package's own
# test binary took, multiplied by this coefficient. The default of 2 is far too
# tight here: for a package whose tests run in milliseconds the compile of the
# mutated binary dominates, and every mutant is misreported as TIMED OUT rather
# than killed or escaped. That failure is silent -- it produces a clean-looking
# run with a fabricated score -- so the coefficient is pinned high deliberately.
# It only ever costs wall-clock on a mutant that genuinely hangs.
TIMEOUT_COEFFICIENT="${MUTATION_TIMEOUT_COEFFICIENT:-40}"

# Hard memory ceiling for a package's mutation run.
#
# Mutating a bound check is the whole point of this tool, and a bound check is
# sometimes the only thing standing between a test and an unbounded allocation:
# flip a comparison on a size cap and the mutated test binary will try to
# allocate whatever the input says. The timeout does not save us, because the
# machine runs out of memory long before a 40x timeout expires -- a local run
# took the box down twice, at internal/hub and internal/mcptools, and a CI
# runner has far less headroom than that box had.
#
# So the run is capped by a cgroup rather than trusted to behave. A mutant that
# hits the ceiling is OOM-killed, its `go test` fails, and the mutant is
# recorded as killed -- the honest outcome, since it WAS detected, by dying.
# Deliberately NO GOMEMLIMIT. It looks like a gentler version of the same idea,
# but it makes the Go GC fight for every allocation near the limit, and the
# mutants that go slow are exactly the ones a mutation run needs to finish:
# setting it to 3GiB here turned 31 of internal/hub's kills into timeouts and
# dropped the reported efficacy from 92.9% to 89.7%. A guard that corrupts the
# number this script exists to produce is not a guard. The cgroup ceiling costs
# nothing until a mutant actually runs away.
MEMORY_MAX="${MUTATION_MEMORY_MAX:-8G}"

# systemd-run is how we get a cgroup without being root-only or writing to
# /sys/fs/cgroup by hand. Where it is unavailable the run still works; it is
# just unprotected, and says so rather than pretending otherwise.
memcap=()
if command -v systemd-run >/dev/null 2>&1 &&
	grep -qw memory /sys/fs/cgroup/cgroup.controllers 2>/dev/null &&
	systemd-run --scope --quiet -p MemoryMax=64M /bin/true >/dev/null 2>&1; then
	memcap=(systemd-run --scope --quiet --collect
		-p "MemoryMax=${MEMORY_MAX}" -p MemorySwapMax=0)
	echo "==> memory ceiling ${MEMORY_MAX} per package"
else
	echo "==> WARNING: no cgroup memory ceiling available; a mutated bound check" >&2
	echo "    can exhaust this machine. Lower MUTATION_WORKERS if that matters." >&2
fi

if ! command -v go >/dev/null 2>&1; then
	echo "go is required" >&2
	exit 1
fi

# Resolve the tool once so that N package runs do not each re-link it.
tooldir="$(mktemp -d)"
trap 'rm -rf "${tooldir}"' EXIT
echo "==> building gremlins ${GREMLINS_VERSION}"
GOBIN="${tooldir}" go install "github.com/go-gremlins/gremlins/cmd/gremlins@${GREMLINS_VERSION}"
gremlins="${tooldir}/gremlins"

declare -A baseline=()
while read -r pkg want _rest; do
	[[ -z "${pkg}" || "${pkg}" == \#* ]] && continue
	# Strip any trailing comment. Without this `want` carries the rest of the
	# line, awk sees a string rather than a number, and a string comparison
	# reports "100.0001" < "97 # measured 100.00" as true -- every finished
	# package failing as a regression.
	want="${want%%#*}"
	want="${want//[[:space:]]/}"
	[[ -z "${want}" ]] && continue
	baseline["${pkg}"]="${want}"
done <"${BASELINE}"

# Default to every package that has both handwritten source and a test binary.
# Generated protobuf and the reusable conformance suites are excluded for the
# same reason they are excluded from the coverage gate: they are not
# handwritten product code.
if [[ $# -gt 0 ]]; then
	packages=("$@")
else
	mapfile -t packages < <(
		go list ./... |
			grep -v '/internal/gen/' |
			grep -v '/internal/store/storetest' |
			grep -v '/internal/tunnel/tunneltest' |
			grep -v '/test/'
	)
fi

outdir="$(mktemp -d)"
trap 'rm -rf "${tooldir}" "${outdir}"' EXIT

fail=0
results=()
for pkg in "${packages[@]}"; do
	short="${pkg#github.com/jacoknapp/prometheus-mcp-fleet/}"
	# Accept the ./internal/foo form the Makefile and docs use, not just the
	# fully qualified module path, so both spellings hit the same baseline key.
	short="${short#./}"
	# A package with no test files has nothing to run a mutant against.
	if ! go list -f '{{if or .TestGoFiles .XTestGoFiles}}y{{end}}' "${pkg}" | grep -q y; then
		continue
	fi
	log="${outdir}/$(echo "${short}" | tr / _).log"
	echo "==> ${short}"
	(
		ulimit -v "${MUTATION_VMEM_KIB}"
		GOMAXPROCS="${MUTATION_GOMAXPROCS}" \
			GOMEMLIMIT="${MUTATION_GOMEMLIMIT}" \
			"${memcap[@]}" "${gremlins}" unleash "./${short}" \
			--workers "${WORKERS}" \
			--timeout-coefficient "${TIMEOUT_COEFFICIENT}"
	) >"${log}" 2>&1 || true

	killed=$(sed -n 's/^Killed: \([0-9]*\).*/\1/p' "${log}" | tail -1)
	lived=$(sed -n 's/.*Lived: \([0-9]*\).*/\1/p' "${log}" | tail -1)
	timedout=$(sed -n 's/^Timed out: \([0-9]*\).*/\1/p' "${log}" | tail -1)
	got=$(sed -n 's/^Test efficacy: \([0-9.]*\)%.*/\1/p' "${log}" | tail -1)

	if [[ -z "${got}" ]]; then
		echo "    gremlins produced no score; last lines:" >&2
		tail -5 "${log}" >&2
		fail=1
		results+=("${short}|ERROR|-|-|-")
		continue
	fi

	# A run where nothing was killed and nothing escaped is not a 100%; it is
	# the timeout misconfiguration described above wearing a passing score.
	if [[ "${killed}" == "0" && "${lived}" == "0" ]]; then
		echo "    every mutant timed out (${timedout}); the score is not real" >&2
		fail=1
		results+=("${short}|TIMEOUT|${killed}|${lived}|${timedout}")
		continue
	fi

	want="${baseline[${short}]:-}"
	if [[ -z "${want}" ]]; then
		echo "    no baseline entry for ${short}; add one to ${BASELINE}" >&2
		fail=1
		results+=("${short}|${got}|${killed}|${lived}|${timedout}")
		continue
	fi

	if awk -v g="${got}" -v w="${want}" 'BEGIN { exit !(g + 0.0001 < w + 0) }'; then
		echo "    efficacy ${got}% regressed below baseline ${want}%" >&2
		grep '  LIVED' "${log}" >&2 || true
		fail=1
	fi
	results+=("${short}|${got}|${killed}|${lived}|${timedout}")
done

echo
printf '%-40s %10s %8s %7s %9s\n' PACKAGE EFFICACY KILLED LIVED TIMEDOUT
for row in "${results[@]}"; do
	IFS='|' read -r a b c d e <<<"${row}"
	printf '%-40s %10s %8s %7s %9s\n' "${a}" "${b}" "${c}" "${d}" "${e}"
done

exit "${fail}"
