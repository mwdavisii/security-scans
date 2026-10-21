#!/usr/bin/env bash
# Create or update ONE pull request comment per tool. Usage: post_comment.sh <tool> <markdown file>
# Environment: GH_TOKEN, GITHUB_REPOSITORY (owner/name), PR (the pull request number).
#
# The comment is found by the marker on its first line (<!-- security-scans:<tool> -->) AND by its author, the
# GitHub Actions bot, so a comment that someone else wrote with the same marker is never edited. golden-road's own
# comment has no such marker and is left alone.
set -euo pipefail
[ "$#" -eq 2 ] || { echo "usage: $0 <tool> <markdown file>" >&2; exit 2; }
tool="$1"; body="$2"
[[ "$tool" =~ ^[a-z][a-z0-9-]{0,30}$ ]] || { echo "bad tool name" >&2; exit 2; }
[[ "${GITHUB_REPOSITORY:-}" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || { echo "bad GITHUB_REPOSITORY" >&2; exit 2; }
[[ "${PR:-}" =~ ^[0-9]{1,9}$ ]] || { echo "bad PR number" >&2; exit 2; }
marker="<!-- security-scans:$tool -->"
[ "$(head -n 1 "$body")" = "$marker" ] || { echo "the comment must start with $marker" >&2; exit 2; }

existing="$(gh api --paginate "repos/$GITHUB_REPOSITORY/issues/$PR/comments?per_page=100" \
  | jq -r --arg m "$marker" '.[] | select(.user.login == "github-actions[bot]" and ((.body // "") | startswith($m))) | .id' \
  | sed -n '1p')"
if [ -n "$existing" ]; then
  gh api --method PATCH "repos/$GITHUB_REPOSITORY/issues/comments/$existing" --field "body=@$body" > /dev/null
else
  gh api --method POST "repos/$GITHUB_REPOSITORY/issues/$PR/comments" --field "body=@$body" > /dev/null
fi
