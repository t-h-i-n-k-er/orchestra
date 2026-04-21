#!/usr/bin/env bash
# Build & package Orchestra release binaries.
#
# Usage: scripts/package.sh [TARGET_TRIPLE]
#   TARGET_TRIPLE defaults to the host triple.
#
# Produces dist/orchestra-<version>-<triple>.tar.gz containing:
#   - bin/console
#   - share/orchestra/agent.toml.example
#   - LICENSE, README.md, docs/USER_GUIDE.md

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

TARGET="${1:-}"
VERSION="$(grep -m1 '^version' Cargo.toml | head -1 | cut -d'"' -f2 || true)"
if [[ -z "$VERSION" ]]; then
  VERSION="$(grep -m1 '^version' console/Cargo.toml | cut -d'"' -f2 || echo "0.1.0")"
fi

if [[ -z "$TARGET" ]]; then
  TARGET="$(rustc -vV | awk '/^host:/ { print $2 }')"
fi

echo "==> Building Orchestra ${VERSION} for ${TARGET}"

CARGO_ARGS=(--release --workspace)
if [[ "$TARGET" != "$(rustc -vV | awk '/^host:/ { print $2 }')" ]]; then
  CARGO_ARGS+=(--target "$TARGET")
fi

cargo build "${CARGO_ARGS[@]}"

if [[ "$TARGET" != "$(rustc -vV | awk '/^host:/ { print $2 }')" ]]; then
  BIN_DIR="target/${TARGET}/release"
else
  BIN_DIR="target/release"
fi

STAGE="dist/staging-orchestra-${VERSION}-${TARGET}"
ARCHIVE="dist/orchestra-${VERSION}-${TARGET}.tar.gz"
rm -rf "$STAGE"
mkdir -p "$STAGE/bin" "$STAGE/share/orchestra" "$STAGE/docs"

# Console binary (Windows adds .exe automatically when cross-compiling)
if [[ -f "${BIN_DIR}/console.exe" ]]; then
  cp "${BIN_DIR}/console.exe" "$STAGE/bin/orchestra-console.exe"
else
  cp "${BIN_DIR}/console" "$STAGE/bin/orchestra-console"
fi

# Sample config
cat > "$STAGE/share/orchestra/agent.toml.example" <<'TOML'
allowed_paths = ["/var/log", "/etc/orchestra", "/home"]
heartbeat_interval_secs = 30
persistence_enabled = false
module_repo_url = "https://updates.example.com/modules"
# module_signing_key = "<base64 AES-256 key>"
TOML

# Docs and license
cp README.md "$STAGE/"
[[ -f LICENSE ]]   && cp LICENSE   "$STAGE/" || true
cp docs/USER_GUIDE.md "$STAGE/docs/"
cp docs/DESIGN.md "$STAGE/docs/"

mkdir -p dist
tar -C "$(dirname "$STAGE")" -czf "$ARCHIVE" "$(basename "$STAGE")"
echo "==> Wrote $ARCHIVE"
ls -lh "$ARCHIVE"
