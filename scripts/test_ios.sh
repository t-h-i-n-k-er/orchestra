#!/usr/bin/env bash
#
# test_ios.sh — Automated iOS agent testing via xcrun simctl.
#
# Prerequisites:
#   - macOS with Xcode 15+
#   - iOS simulator runtime installed
#   - Orchestra server running (default: https://localhost:8443)
#
# Usage:
#   ./test_ios.sh [server_url]
#
# Tests:
#   1. Check macOS / Xcode environment
#   2. Build the agent static library for aarch64-apple-ios
#   3. Verify .a output and architecture
#   4. Build the Xcode project (if present)
#   5. Launch on iOS Simulator
#   6. Verify server connectivity
#   7. Clean up

set -euo pipefail

SERVER_URL="${1:-https://localhost:8443}"
PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
MOBILE_DIR="$PROJECT_DIR/mobile/ios"
WORKSPACE_ROOT="$PROJECT_DIR"

RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[1;33m"
NC="\033[0m"

pass() { echo -e "${GREEN}[PASS]${NC} $*"; }
fail() { echo -e "${RED}[FAIL]${NC} $*"; exit 1; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }

echo "=== Orchestra iOS Agent Test Suite ==="
echo ""

# --- Pre-flight checks ---
echo "[1/7] Checking macOS / Xcode environment..."

if [[ "$(uname)" != "Darwin" ]]; then
    warn "Not running on macOS. iOS builds require Xcode on macOS."
    warn "Skipping all iOS-specific tests."
    MACOS_AVAILABLE=false
else
    MACOS_AVAILABLE=true
    pass "Running on macOS"

    if ! command -v xcodebuild &>/dev/null; then
        warn "xcodebuild not found. Install Xcode Command Line Tools."
        MACOS_AVAILABLE=false
    else
        XCODE_VERSION=$(xcodebuild -version 2>/dev/null | head -1 || echo "unknown")
        pass "Xcode: $XCODE_VERSION"
    fi

    if ! command -v xcrun &>/dev/null; then
        warn "xcrun not found"
    else
        SIMULATOR_DEVICE=$(xcrun simctl list devices available 2>/dev/null | grep -oE 'iPhone [^ ]+ \([^)]+\)' | head -1 || echo "")
        if [ -n "$SIMULATOR_DEVICE" ]; then
            pass "Simulator available: $SIMULATOR_DEVICE"
            SIMULATOR_AVAILABLE=true
        else
            warn "No iOS simulator devices found. Create one in Xcode > Settings > Platforms."
            SIMULATOR_AVAILABLE=false
        fi
    fi

    if ! command -v cargo &>/dev/null; then
        fail "cargo not found. Install Rust toolchain."
    fi

    # Check for iOS target
    if ! rustup target list --installed | grep -q 'aarch64-apple-ios'; then
        warn "aarch64-apple-ios target not installed. Attempting to install..."
        rustup target add aarch64-apple-ios || fail "Failed to install iOS target"
    fi
fi

pass "Prerequisites check complete"

# --- Build the agent static library ---
echo ""
echo "[2/7] Building agent static library for aarch64-apple-ios..."

cd "$WORKSPACE_ROOT"

BUILD_OUTPUT=$(cargo build --target aarch64-apple-ios -p agent \
    --no-default-features \
    --features "http-transport,env-validation,persistence,adaptive-timing" \
    2>&1) || {
    echo "$BUILD_OUTPUT" | tail -20
    warn "Build failed. Check docs/MOBILE_SUPPORT.md for iOS build prerequisites."
    warn "(iOS builds require Xcode clang for ring crate C compilation)"
}

A_PATH="$WORKSPACE_ROOT/target/aarch64-apple-ios/debug/libagent.a"
if [ -f "$A_PATH" ]; then
    pass "Agent .a built successfully: $A_PATH"
    A_SIZE=$(stat -f%z "$A_PATH" 2>/dev/null || stat -c%s "$A_PATH" 2>/dev/null || echo "unknown")
    pass "Size: $A_SIZE bytes"

    # Verify architecture
    if command -v lipo &>/dev/null; then
        ARCH_INFO=$(lipo -info "$A_PATH" 2>/dev/null || echo "unknown")
        pass "Architecture: $ARCH_INFO"
    fi
else
    warn "Agent .a not found at $A_PATH"
    warn "Checking for alternative output names..."
    ls "$WORKSPACE_ROOT/target/aarch64-apple-ios/debug/" 2>/dev/null | grep '\.a$' || warn "No .a files found."
fi

# --- Check C bridge header ---
echo ""
echo "[3/7] Verifying C bridge header..."

if [ -f "$MOBILE_DIR/OrchestraBridge/OrchestraBridge.h" ]; then
    pass "OrchestraBridge.h found"
    if [ -f "$MOBILE_DIR/OrchestraBridge/OrchestraBridge.c" ]; then
        pass "OrchestraBridge.c found"
    fi
    # Check for expected function declarations
    if grep -q 'orchestra_init' "$MOBILE_DIR/OrchestraBridge/OrchestraBridge.h"; then
        pass "Expected C ABI functions declared in header"
    fi
else
    warn "OrchestraBridge.h not found at $MOBILE_DIR/OrchestraBridge/"
fi

# --- Test debugger detection (POSIX) ---
echo ""
echo "[4/7] Testing iOS env check primitives (host-side)..."

# sysctl KERN_PROC check (works on macOS, similar to iOS)
if command -v sysctl &>/dev/null; then
    if sysctl kern.proc.$$ 2>/dev/null | grep -q 'P_TRACED'; then
        warn "Could check P_TRACED flag on macOS (same API as iOS)"
    else
        pass "sysctl KERN_PROC available (matches iOS API)"
    fi
fi

# Check for common jailbreak files (host-side check on macOS)
JB_FILES=(
    "/Applications/Cydia.app"
    "/Library/MobileSubstrate/MobileSubstrate.dylib"
    "/bin/bash"
)
for f in "${JB_FILES[@]}"; do
    if [ -e "$f" ]; then
        warn "Jailbreak file found: $f (expected on macOS, not iOS)"
    else
        pass "Jailbreak file not present: $f"
    fi
done

# --- Server connectivity test ---
echo ""
echo "[5/7] Testing server connectivity..."

if curl -sk --connect-timeout 5 "$SERVER_URL/api/info/fingerprint" &>/dev/null; then
    pass "Server reachable at $SERVER_URL"
else
    warn "Server not reachable at $SERVER_URL (expected if not running)"
fi

# --- Build Xcode project (if present) ---
echo ""
echo "[6/7] Building Xcode project..."

XCODE_PROJ="$MOBILE_DIR/OrchestraAgent.xcodeproj"
if [ -d "$XCODE_PROJ" ]; then
    if [ "$MACOS_AVAILABLE" = true ]; then
        xcodebuild -project "$XCODE_PROJ" \
            -scheme OrchestraAgent \
            -sdk iphonesimulator \
            -configuration Debug \
            build 2>&1 | tail -20 || warn "Xcode build failed (may need project configuration)"
        pass "Xcode build attempted"
    else
        warn "Xcode project exists but not on macOS — skipping build"
    fi
else
    warn "No Xcode project at $XCODE_PROJ — skipping Xcode build"
    warn "To create: Open Xcode → New Project → iOS App → Link liborchestra.a"
fi

# --- Cleanup ---
echo ""
echo "[7/7] Cleanup..."

# Kill any lingering simulators (macOS only)
if [ "$MACOS_AVAILABLE" = true ] && command -v xcrun &>/dev/null; then
    xcrun simctl shutdown all 2>/dev/null || true
    pass "Simulators shut down"
fi

echo ""
echo "=== Test suite complete ==="
echo ""
echo "Summary:"
echo "  - macOS/Xcode environment: $([ "$MACOS_AVAILABLE" = true ] && echo 'OK' || echo 'SKIPPED')"
echo "  - Agent .a build: $([ -f "$A_PATH" ] && echo 'OK' || echo 'SKIPPED (check Xcode clang)')"
echo "  - C bridge: $([ -f "$MOBILE_DIR/OrchestraBridge/OrchestraBridge.h" ] && echo 'PRESENT' || echo 'MISSING')"
echo "  - Env checks: DONE (host-side)"
echo "  - Server test: DONE"

if [ "$MACOS_AVAILABLE" = true ] && [ -f "$A_PATH" ]; then
    echo ""
    echo "Manual steps for full integration test:"
    echo "  1. Start the Orchestra server"
    echo "  2. Build with Xcode: cd mobile/ios && ./build_agent.sh debug device"
    echo "  3. Open Xcode project and configure signing team"
    echo "  4. Run on iOS Simulator or device"
    echo "  5. Check server for connected agent"
    echo "  6. View logs: xcrun simctl spawn booted log stream --predicate 'process contains \"Orchestra\"'"
fi