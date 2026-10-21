# Shared helpers, sourced by the other scripts. Not run on its own.

# require_digest NAME VALUE: the value must be an image reference pinned by digest.
require_digest() {
  if [[ ! "${2:-}" =~ ^[A-Za-z0-9][A-Za-z0-9._/:-]*@sha256:[0-9a-f]{64}$ ]]; then
    echo "::error::$1 must be an image reference pinned by digest (name@sha256:<64 hex>)"
    exit 1
  fi
}

# guard_start / guard_end: while a scanner or a build runs, the runner ignores workflow commands in its output.
# Those tools print text taken from the repository under test, which could otherwise carry ::error:: or
# ::add-mask:: lines. The token is random, so the text cannot end the guard early.
guard_token=""
guard_start() {
  guard_token="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
  echo "::stop-commands::$guard_token"
}
guard_end() {
  if [ -n "$guard_token" ]; then
    echo "::$guard_token::"
    guard_token=""
  fi
}
