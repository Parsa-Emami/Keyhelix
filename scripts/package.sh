#!/usr/bin/env bash
# Build and publish the complete KeyHelix release artifact.
#
# This is a single-writer local operation. A killed writer leaves either the
# previous complete release or the new complete release; stale staging and lock
# state is reconciled on the next run.
set -euo pipefail

root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

case "${KEYHELIX_RELEASE_DIR:-dist/release}" in
  /*) dest="${KEYHELIX_RELEASE_DIR:-dist/release}" ;;
  *) dest="$root/${KEYHELIX_RELEASE_DIR:-dist/release}" ;;
esac
stage_root="$root/dist"
lock="$stage_root/.package-lock"
stage=""

cleanup() {
  local status=$?
  if [ -n "$stage" ] && [ -d "$stage" ]; then rm -rf "$stage"; fi
  rm -rf "$lock"
  trap - EXIT
  exit "$status"
}
trap cleanup EXIT INT TERM

mkdir -p "$stage_root" "$(dirname "$dest")"

# Atomic lock acquisition. A stale lock is reclaimed only when its recorded PID
# is no longer alive.
if ! mkdir "$lock" 2>/dev/null; then
  existing="$(cat "$lock/pid" 2>/dev/null || true)"
  if [ -n "$existing" ] && kill -0 "$existing" 2>/dev/null; then
    echo "package-error: package-in-progress (pid $existing)" >&2
    exit 1
  fi
  rm -rf "$lock"
  if ! mkdir "$lock" 2>/dev/null; then
    echo "package-error: package-lock-contended" >&2
    exit 1
  fi
fi
printf '%s\n' "$$" > "$lock/pid"

# Recover only complete states. A hidden previous release is authoritative when
# the visible destination disappeared between the two publish renames.
if [ -d "${dest}.previous" ] && [ ! -e "$dest" ]; then
  mv "${dest}.previous" "$dest"
fi
find "$stage_root" -mindepth 1 -maxdepth 1 -type d -name '.package-stage.*' -exec rm -rf {} + 2>/dev/null || true

if [ "${KEYHELIX_PACKAGE_SKIP_BUILD:-0}" != "1" ]; then
  export GOFLAGS="${GOFLAGS:+$GOFLAGS }-buildvcs=false"
  npm run build
fi

stage="$(mktemp -d "$stage_root/.package-stage.XXXXXX")"
node scripts/package-web.mjs --stage "$stage" >/dev/null
node scripts/package-source.mjs --stage "$stage" --dest "$dest"
