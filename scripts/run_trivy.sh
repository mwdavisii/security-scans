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
#   SCANS_REPOSITORY      owner/name of the repository under test; its exceptions/trivy/<owner>/<name>.yaml applies.
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
# The platform's exceptions for the repository under test come from this repo's exceptions/trivy/<owner>/<repo>.yaml,
# never from the repository under test. Without SCANS_REPOSITORY (a local run) no exceptions apply.
if [ -n "${SCANS_REPOSITORY:-}" ]; then
  [[ "$SCANS_REPOSITORY" =~ ^[A-Za-z0-9-]+/[A-Za-z0-9_-][A-Za-z0-9._-]*$ && "$SCANS_REPOSITORY" != */.* ]] \
    || { echo "::error::SCANS_REPOSITORY is not owner/name"; exit 1; }
  repo="${SCANS_REPOSITORY,,}"
  exceptions="$here/../exceptions/trivy/$repo.yaml"
  if [ -f "$exceptions" ] && [ ! -L "$exceptions" ]; then
    mounts+=(-v "$(cd "$(dirname "$exceptions")" && pwd)/$(basename "$exceptions"):/exceptions/trivyignore.yaml:ro")
    common+=(--ignorefile /exceptions/trivyignore.yaml)
    ids=$(awk '/^ *- id:/ {id=$3} /^ *expired_at:/ {printf "%s%s (until %s)", sep, id, $2; sep=", "}' "$exceptions")
    [ -z "$ids" ] || echo "::notice title=Platform scan exceptions for $repo::Not reported until their date: $ids. See exceptions/trivy/$repo.yaml in the security-scans repo."
  fi
fi
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
