#!/usr/bin/env bash
# scripts/dev-start.sh — Start Orchestra Control Center + dev-server for
# local development and testing.
#
# Usage:
#   ./scripts/dev-start.sh [--config FILE] [--port PORT]
#
# Starts orchestra-server and dev-server. Press Ctrl+C to stop both.
#
# Environment:
#   ORCHESTRA_HTTP_PORT  — dashboard port (default: 8443)
#   ORCHESTRA_AGENT_PORT — agent port (default: 8444)
#   ORCHESTRA_DEV_PORT   — dev-server HTTP port (default: 8080)

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

HTTP_PORT="${ORCHESTRA_HTTP_PORT:-8443}"
AGENT_PORT="${ORCHESTRA_AGENT_PORT:-8444}"
DEV_PORT="${ORCHESTRA_DEV_PORT:-8080}"
CONFIG="${1:-}"
PIDS=()

cleanup() {
    echo ""
    echo "Stopping Orchestra services..."
    for pid in "${PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    wait 2>/dev/null
    echo "Stopped."
    exit 0
}
trap cleanup INT TERM

# Build both binaries if missing
if [[ ! -x "target/release/orchestra-server" ]]; then
    echo "[dev-start] Building Orchestra Control Center..."
    cargo build --release -p orchestra-server
fi

if [[ ! -x "target/release/dev-server" ]]; then
    echo "[dev-start] Building dev-server..."
    cargo build --release -p dev-server
fi

# Generate a default config if none provided
if [[ -z "$CONFIG" ]]; then
    CONFIG="secrets/dev-server.toml"
    if [[ ! -f "$CONFIG" ]]; then
        ADMIN_TOKEN=$(head -c 24 /dev/urandom | base64 | tr -d '\n')
        AGENT_SECRET=$(head -c 32 /dev/urandom | base64 | tr -d '\n')
        mkdir -p secrets
        cat > "$CONFIG" <<EOF
# Auto-generated dev config
http_addr           = "127.0.0.1:${HTTP_PORT}"
agent_addr          = "127.0.0.1:${AGENT_PORT}"
agent_shared_secret = "${AGENT_SECRET}"
admin_token         = "${ADMIN_TOKEN}"
audit_log_path      = "secrets/orchestra-audit.jsonl"
static_dir          = "orchestra-server/static"
command_timeout_secs = 30
EOF
        echo "[dev-start] Generated $CONFIG"
        echo "[dev-start] Admin token: $ADMIN_TOKEN"
    fi
fi

echo "[dev-start] Starting Orchestra Control Center on :${HTTP_PORT} (HTTPS) / :${AGENT_PORT} (agent)..."
./target/release/orchestra-server --config "$CONFIG" &
PIDS+=($!)

sleep 1

echo "[dev-start] Starting dev-server on :${DEV_PORT}..."
./target/release/dev-server --port "$DEV_PORT" &
PIDS+=($!)

echo ""
echo "  Dashboard: https://127.0.0.1:${HTTP_PORT}/"
echo "  Dev server: http://127.0.0.1:${DEV_PORT}/"
echo ""
echo "  Press Ctrl+C to stop both services."
echo ""

wait
