#!/usr/bin/env bash
# Run Semgrep CE over ./src and write out/semgrep.sarif. It never fails on findings: scripts/sarif_report.py decides.
#
# Environment:
#   SEMGREP_IMAGE        required; Semgrep CE container image pinned by digest.
#   REGISTRY_RULESETS    space-separated registry rulesets (for example "p/default"). Empty means only the vendored
#                        rules/ directory, and the container then runs with no network.
#   SCANS_SEMGREP_NETWORK  optional docker network for local runs when registry rules are used (for example "host").
#
# Semgrep only reads the code. The tree is copied first without .git, .gitignore, and .semgrepignore (a fresh checkout
# holds only tracked files, so there is nothing legitimate to ignore), and run with
# --disable-nosem, so files under test cannot exclude themselves or suppress a finding.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib.sh
. "$here/lib.sh"

require_digest SEMGREP_IMAGE "${SEMGREP_IMAGE:-}"
registry="${REGISTRY_RULESETS-}"
[[ "$registry" =~ ^[A-Za-z0-9_./\ -]*$ ]] || { echo "::error::REGISTRY_RULESETS has characters that are not allowed"; exit 1; }
configs=(--config /security-scans)
for ruleset in $registry; do
  [[ "$ruleset" =~ ^[pr]/[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*$ ]] || { echo "::error::'$ruleset' is not a registry ruleset (p/<name> or r/<rule>)"; exit 1; }
  configs+=(--config "$ruleset")
done
network=()
if [ -z "${registry// /}" ]; then
  network=(--network none)
elif [ -n "${SCANS_SEMGREP_NETWORK:-}" ]; then
  [[ "$SCANS_SEMGREP_NETWORK" =~ ^[a-z][a-z0-9_-]*$ ]] || { echo "::error::bad SCANS_SEMGREP_NETWORK"; exit 1; }
  network=(--network "$SCANS_SEMGREP_NETWORK")
fi

[ -d src ] || { echo "::error::no src directory to scan"; exit 1; }
mkdir -p out
tree="$(mktemp -d)"
trap 'rm -rf "$tree"; guard_end' EXIT
tar -C src --exclude=.git --exclude=.gitignore --exclude=.semgrepignore -cf - . | tar -C "$tree" -xf -
cp "$here/../rules/semgrepignore" "$tree/.semgrepignore"

guard_start
docker run --rm "${network[@]}" --user "$(id -u):$(id -g)" --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges \
  -e HOME=/tmp -v "$tree:/src:ro" -v "$here/../rules:/security-scans:ro" -v "$PWD/out:/out" -w /src "$SEMGREP_IMAGE" \
  semgrep scan "${configs[@]}" --metrics off --disable-version-check --disable-nosem --max-target-bytes 0 \
  --sarif --output /out/semgrep.sarif --quiet .
guard_end
[ -s out/semgrep.sarif ] || { echo "::error::Semgrep wrote no SARIF"; exit 1; }
