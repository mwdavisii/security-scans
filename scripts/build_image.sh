#!/usr/bin/env bash
# Build the root Dockerfile of ./src WITHOUT pushing, save the image to out/image.tar for the image scan, and remove
# the local image again. Sets built=true or built=false in $GITHUB_OUTPUT.
#
# This runs the repository's Dockerfile, which is repository code. What limits it: the job's token is read-only
# (contents: read only: the comment job that can write to the pull request is a separate job), no secret or credential is on the runner or passed to the build (no --secret, no --ssh, no
# registry login, checkout does not keep credentials), the build context is ./src only, nothing is pushed or loaded
# anywhere but the runner's own daemon, and the runner is a fresh VM that is discarded after the job. RUN steps need
# the network to reach package indexes, so the build keeps the default network.
#
# Environment: SCANS_BUILD_NETWORK optionally sets the docker build network for local runs (for example "host").
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib.sh
. "$here/lib.sh"

output="${GITHUB_OUTPUT:-/dev/null}"
if [ ! -e src/Dockerfile ] && [ ! -L src/Dockerfile ]; then
  echo "::notice title=security-scans::No Dockerfile at the repository root: the image scan is skipped."
  echo "built=false" >> "$output"
  exit 0
fi
{ [ -f src/Dockerfile ] && [ ! -L src/Dockerfile ]; } || { echo "::error::src/Dockerfile must be a regular file, not a symlink"; exit 1; }

network=()
if [ -n "${SCANS_BUILD_NETWORK:-}" ]; then
  [[ "$SCANS_BUILD_NETWORK" =~ ^[a-z][a-z0-9_-]*$ ]] || { echo "::error::bad SCANS_BUILD_NETWORK"; exit 1; }
  network=(--network "$SCANS_BUILD_NETWORK")
fi
tag="security-scans-target:scan-$$"
mkdir -p out
rm -f out/image.tar
trap 'docker image rm --force "$tag" > /dev/null 2>&1 || true; guard_end' EXIT

guard_start
docker build --file src/Dockerfile --tag "$tag" "${network[@]}" src
guard_end
docker save --output out/image.tar "$tag"
echo "built=true" >> "$output"
