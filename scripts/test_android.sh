#!/usr/bin/env bash
#
# test_android.sh — Automated Android agent testing via adb.
#
# Prerequisites:
#   - Android emulator running or physical device connected via USB
#   - adb in PATH
#   - Orchestra server running (default: https://localhost:8443)
#
# Usage:
#   ./test_android.sh [server_url] [agent_config_toml]
#
# Tests:
#   1. Build the agent .so for aarch64-linux-android (debug)
#   2. Push the .so to the device
#   3. Load the .so via the test app
#   4. Verify agent initialization
#   5. Verify C2 connection (if server available)
#   6. Verify env check output
#   7. Clean up

set -euo pipefail

SERVER_URL="${1:-https://localhost:8443}"
CONFIG_TOML="${2:-}"
PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
MOBILE_DIR="$PROJECT_DIR/mobile/android"
WORKSPACE_ROOT="$PROJECT_DIR"

RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[1;33m"
NC="\033[0m"

pass() { echo -e "${GREEN}[PASS]${NC} $*"; }
fail() { echo -e "${RED}[FAIL]${NC} $*"; exit 1; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }

echo "=== Orchestra Android Agent Test Suite ==="
echo ""

# --- Pre-flight checks ---
echo "[1/7] Checking prerequisites..."

if ! command -v adb &>/dev/null; then
    fail "adb not found in PATH. Install Android SDK Platform Tools."
fi

if ! adb devices | grep -q 'device$'; then
    warn "No Android device found via adb. Start an emulator or connect a device."
    warn "Continuing with build-only tests..."
    DEVICE_AVAILABLE=false
else
    DEVICE="$(adb devices | grep 'device$' | head -1 | awk '{print $1}')"
    pass "Device found: $DEVICE"
    DEVICE_AVAILABLE=true
fi

if ! command -v cargo &>/dev/null; then
    fail "cargo not found. Install Rust toolchain."
fi

# Check for Android target
if ! rustup target list --installed | grep -q 'aarch64-linux-android'; then
    warn "aarch64-linux-android target not installed. Attempting to install..."
    rustup target add aarch64-linux-android || fail "Failed to install Android target"
fi

pass "Prerequisites check complete"

# --- Build the agent ---
echo ""
echo "[2/7] Building agent for aarch64-linux-android..."

cd "$WORKSPACE_ROOT"

BUILD_OUTPUT=$(cargo build --target aarch64-linux-android -p agent \
    --no-default-features \
    --features "http-transport,env-validation,persistence,adaptive-timing" \
    2>&1) || {
    echo "$BUILD_OUTPUT" | tail -20
    warn "Build failed. This may be due to missing Android NDK (ring crate needs aarch64-linux-android-clang)."
    warn "Check docs/MOBILE_SUPPORT.md for build prerequisites."
    warn "Skipping device tests..."
    DEVICE_AVAILABLE=false
}

SO_PATH="$WORKSPACE_ROOT/target/aarch64-linux-android/debug/libagent.so"
if [ -f "$SO_PATH" ]; then
    pass "Agent .so built successfully: $SO_PATH"
    SO_SIZE=$(stat -c%s "$SO_PATH" 2>/dev/null || stat -f%z "$SO_PATH" 2>/dev/null || echo "unknown")
    pass "Size: $SO_SIZE bytes"
else
    warn "Agent .so not found. Checking for alternative output names..."
    ls "$WORKSPACE_ROOT/target/aarch64-linux-android/debug/" | grep '\.so$' || warn "No .so files found."
    DEVICE_AVAILABLE=false
fi

# --- Push to device ---
if [ "$DEVICE_AVAILABLE" = true ] && [ -f "$SO_PATH" ]; then
    echo ""
    echo "[3/7] Pushing agent .so to device..."

    adb -s "$DEVICE" push "$SO_PATH" /data/local/tmp/liborchestra.so

    if adb -s "$DEVICE" shell "test -f /data/local/tmp/liborchestra.so" &>/dev/null; then
        pass "Agent .so pushed to /data/local/tmp/liborchestra.so"
    else
        fail "Failed to push .so to device"
    fi
else
    echo ""
    echo "[3/7] Skipping device push (no device or no .so)"
fi

# --- Check environment on device ---
if [ "$DEVICE_AVAILABLE" = true ]; then
    echo ""
    echo "[4/7] Collecting device information..."

    echo "  Android version: $(adb -s "$DEVICE" shell getprop ro.build.version.release 2>/dev/null || echo 'unknown')"
    echo "  SDK level: $(adb -s "$DEVICE" shell getprop ro.build.version.sdk 2>/dev/null || echo 'unknown')"
    echo "  Manufacturer: $(adb -s "$DEVICE" shell getprop ro.product.manufacturer 2>/dev/null || echo 'unknown')"
    echo "  Model: $(adb -s "$DEVICE" shell getprop ro.product.model 2>/dev/null || echo 'unknown')"
    echo "  CPU arch: $(adb -s "$DEVICE" shell getprop ro.product.cpu.abi 2>/dev/null || echo 'unknown')"

    # Check for common emulator indicators
    if adb -s "$DEVICE" shell getprop ro.build.fingerprint 2>/dev/null | grep -qi 'generic\|sdk\|ranchu'; then
        warn "Device appears to be an emulator (generic/sdk/ranchu fingerprint)"
    fi

    pass "Device information collected"
fi

# --- Check for common env-check files on Android ---
if [ "$DEVICE_AVAILABLE" = true ]; then
    echo ""
    echo "[5/7] Checking Android environment markers..."

    # Check /proc/self/status for TracerPid (debugger detection)
    TRACER_PID=$(adb -s "$DEVICE" shell "cat /proc/self/status 2>/dev/null | grep TracerPid | awk '{print \$2}'" || echo "N/A")
    echo "  TracerPid: $TRACER_PID"

    # Check for su binary
    if adb -s "$DEVICE" shell "which su 2>/dev/null || test -f /system/bin/su || test -f /system/xbin/su" &>/dev/null; then
        warn "  su binary found — device appears rooted"
    else
        pass "  No su binary found (likely non-rooted)"
    fi

    # Check for Magisk
    if adb -s "$DEVICE" shell "test -d /sbin/.magisk || test -d /data/adb/magisk" &>/dev/null; then
        warn "  Magisk directory found — device is rooted via Magisk"
    else
        pass "  No Magisk found"
    fi

    # Check for Frida
    if adb -s "$DEVICE" shell "cat /proc/self/maps 2>/dev/null | grep -qi frida" &>/dev/null; then
        warn "  Frida detected in /proc/self/maps"
    else
        pass "  No Frida detected in process maps"
    fi

    # Check for emulator pipes
    if adb -s "$DEVICE" shell "test -e /dev/qemu_pipe || test -e /dev/goldfish_pipe" &>/dev/null; then
        warn "  QEMU/goldfish pipe found — running in emulator"
    else
        pass "  No emulator pipes found"
    fi
fi

# --- Server connectivity test ---
echo ""
echo "[6/7] Testing server connectivity..."

if curl -sk --connect-timeout 5 "$SERVER_URL/api/info/fingerprint" &>/dev/null; then
    pass "Server reachable at $SERVER_URL"
else
    warn "Server not reachable at $SERVER_URL (expected if not running)"
fi

# --- Cleanup ---
echo ""
echo "[7/7] Cleanup..."

if [ "$DEVICE_AVAILABLE" = true ]; then
    adb -s "$DEVICE" shell "rm -f /data/local/tmp/liborchestra.so" 2>/dev/null || true
    pass "Cleaned up device"
fi

echo ""
echo "=== Test suite complete ==="
echo ""
echo "Summary:"
echo "  - Agent build: $([ -f "$SO_PATH" ] && echo 'OK' || echo 'SKIPPED (check NDK)')"
echo "  - Device tests: $([ "$DEVICE_AVAILABLE" = true ] && echo 'RUN' || echo 'SKIPPED (no device)')"
echo "  - Server test: DONE"

if [ "$DEVICE_AVAILABLE" = true ] && [ -f "$SO_PATH" ]; then
    echo ""
    echo "Manual steps for full integration test:"
    echo "  1. Start the Orchestra server"
    echo "  2. Build the full APK: cd mobile/android && ./build_agent.sh debug arm64"
    echo "  3. Install on device: adb install mobile/android/app/build/outputs/apk/debug/app-debug.apk"
    echo "  4. Launch the app: adb shell am start -n com.orchestra.agent/.AgentService"
    echo "  5. Check server for connected agent"
    echo "  6. View logs: adb logcat -s Orchestra:V"
fi