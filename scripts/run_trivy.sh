#!/usr/bin/env bash
# Run Trivy over the repository (fs) or over the saved image (image) and write out/trivy-<mode>.sarif.
# Usage: run_trivy.sh fs|image. It never fails on findings: scripts/sarif_report.py decides.
#
# Environment:
#   TRIVY_IMAGE           required; Trivy container image pinned by digest.
#   IGNORE_UNFIXED        "true" or "false" (default "false"): skip vulnerabilities that have no fixed version yet.
#   SCANS_TRIVY_CACHE     cache directory for the vulnerability database (default ./trivy-cache).
#   SCANS_TRIVY_OFFLINE   "true" runs with no network and the cached database (local runs; download the database first).
#   SCANS_TRIVY_NETWORK   optional docker network for the database download in local runs (for example "host").
#
# The container's working directory is not the repository, so a trivy.yaml, .trivyignore, or secret config inside
# the repository under test is never read: only the flags below apply.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib.sh
. "$here/lib.sh"

[ "$#" -eq 1 ] && { [ "$1" = fs ] || [ "$1" = image ]; } || { echo "usage: $0 fs|image" >&2; exit 2; }
mode="$1"
require_digest TRIVY_IMAGE "${TRIVY_IMAGE:-}"
unfixed="${IGNORE_UNFIXED:-false}"
[ "$unfixed" = true ] || [ "$unfixed" = false ] || { echo "::error::IGNORE_UNFIXED must be true or false"; exit 1; }

mkdir -p out
cache="${SCANS_TRIVY_CACHE:-$PWD/trivy-cache}"
mkdir -p "$cache"
common=(--cache-dir /cache --severity HIGH,CRITICAL --format sarif --output "/out/trivy-$mode.sarif")
[ "$unfixed" = false ] || common+=(--ignore-unfixed)
network=()
if [ "${SCANS_TRIVY_OFFLINE:-false}" = true ]; then
  network=(--network none)
  common+=(--skip-db-update --skip-check-update --skip-java-db-update)
elif [ -n "${SCANS_TRIVY_NETWORK:-}" ]; then
  [[ "$SCANS_TRIVY_NETWORK" =~ ^[a-z][a-z0-9_-]*$ ]] || { echo "::error::bad SCANS_TRIVY_NETWORK"; exit 1; }
  network=(--network "$SCANS_TRIVY_NETWORK")
fi

mounts=(-v "$cache:/cache" -v "$PWD/out:/out")
if [ "$mode" = fs ]; then
  [ -d src ] || { echo "::error::no src directory to scan"; exit 1; }
  mounts+=(-v "$PWD/src:/src:ro")
  cmd=(fs --scanners vuln,misconfig,secret --skip-dirs /src/.git "${common[@]}" /src)
else
  [ -f out/image.tar ] || { echo "::error::out/image.tar does not exist: build the image first"; exit 1; }
  cmd=(image --input /out/image.tar --scanners vuln,secret "${common[@]}")
fi

trap guard_end EXIT
guard_start
docker run --rm "${network[@]}" --user "$(id -u):$(id -g)" --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges \
  -e HOME=/tmp "${mounts[@]}" "$TRIVY_IMAGE" "${cmd[@]}"
guard_end
[ -s "out/trivy-$mode.sarif" ] || { echo "::error::Trivy wrote no SARIF"; exit 1; }
