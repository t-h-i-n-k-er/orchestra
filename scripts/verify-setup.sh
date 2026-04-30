#!/usr/bin/env bash
# scripts/verify-setup.sh — Verify that all Orchestra prerequisites are met.
#
# Usage:
#   ./scripts/verify-setup.sh [--verbose]
#
# Checks:
#   - Rust toolchain (cargo, rustc)
#   - C compiler (gcc/clang)
#   - OpenSSL CLI
#   - Git
#   - Workspace compiles (cargo check)
#   - Feature flags resolve
#   - TLS material exists (optional)
#   - Server config exists (optional)
#
# Exit code: 0 if all required checks pass, 1 otherwise.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

VERBOSE=0
[[ "${1:-}" == "--verbose" ]] && VERBOSE=1

PASS=0
FAIL=0
WARN=0

check() {
    local label="$1" cmd="$2" required="${3:-1}"
    if eval "$cmd" >/dev/null 2>&1; then
        printf '  \033[0;32m✓\033[0m %s\n' "$label"
        ((PASS++))
        if [[ "$VERBOSE" == "1" ]]; then
            local detail
            detail=$(eval "$cmd" 2>/dev/null | head -1)
            [[ -n "$detail" ]] && printf '    %s\n' "$detail"
        fi
    elif [[ "$required" == "1" ]]; then
        printf '  \033[0;31m✗\033[0m %s (required)\n' "$label"
        ((FAIL++))
    else
        printf '  \033[0;33m~\033[0m %s (optional, not found)\n' "$label"
        ((WARN++))
    fi
}

echo ""
echo "  Orchestra Setup Verification"
echo "  ============================"
echo ""

echo "  [Toolchain]"
check "Rust toolchain (cargo)" "command -v cargo"
check "rustc"                   "command -v rustc"
check "C compiler (gcc/clang)"  "command -v gcc || command -v clang"
check "pkg-config"              "command -v pkg-config"
check "openssl CLI"             "command -v openssl"
check "git"                     "command -v git"
echo ""

echo "  [Rust details]"
if command -v cargo >/dev/null 2>&1; then
    check "cargo version"  "cargo --version"
    check "rustc version"  "rustc --version"
    # Check for required targets
    if [[ "$VERBOSE" == "1" ]]; then
        echo "    Installed targets:"
        rustup target list --installed 2>/dev/null | sed 's/^/      /' || true
    fi
else
    printf '  \033[0;31m✗\033[0m Rust not installed — cannot check details\n'
    ((FAIL++))
fi
echo ""

echo "  [Workspace]"
check "Cargo.toml exists"      "test -f Cargo.toml"
check "agent/Cargo.toml exists" "test -f agent/Cargo.toml"
check "workspace metadata"     "cargo metadata --format-version 1 >/dev/null"
echo ""

echo "  [Build check]"
if cargo check --workspace 2>/dev/null; then
    printf '  \033[0;32m✓\033[0m cargo check --workspace passes\n'
    ((PASS++))
else
    printf '  \033[0;31m✗\033[0m cargo check --workspace fails\n'
    ((FAIL++))
fi

if cargo check -p agent --features outbound-c 2>/dev/null; then
    printf '  \033[0;32m✓\033[0m agent with outbound-c feature compiles\n'
    ((PASS++))
else
    printf '  \033[0;31m✗\033[0m agent with outbound-c feature fails\n'
    ((FAIL++))
fi
echo ""

echo "  [TLS / Configuration]"
check "TLS certificate (secrets/server.crt)" "test -f secrets/server.crt" 0
check "TLS private key (secrets/server.key)"  "test -f secrets/server.key" 0
check "Server config (orchestra-server.toml)" "test -f orchestra-server.toml" 0
check "Profile directory (profiles/)"         "test -d profiles" 0
echo ""

echo "  [Summary]"
printf '  Passed: %d  Failed: %d  Optional: %d\n\n' "$PASS" "$FAIL" "$WARN"

if [[ "$FAIL" -gt 0 ]]; then
    echo "  Some required checks failed. Fix the issues above and re-run."
    echo "  Quick fix: install Rust from https://rustup.rs"
    exit 1
else
    echo "  All required checks passed. Ready to run:"
    echo "    ./scripts/quickstart.sh"
    exit 0
fi
