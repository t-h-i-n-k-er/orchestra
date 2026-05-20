#!/usr/bin/env bash
#
# build_agent.sh — Compile the Orchestra Rust agent for iOS and build the Xcode project.
#
# Prerequisites:
#   - Rust targets: aarch64-apple-ios, x86_64-apple-ios (simulator)
#     Install via: rustup target add aarch64-apple-ios x86_64-apple-ios
#   - Xcode 15+ with iOS SDK and command-line tools
#   - cargo-lipo (optional, for universal binary)
#
# Usage:
#   ./build_agent.sh [debug|release] [device|simulator]
#
# Output: Rust static library (.a) and Xcode-built .app bundle

set -euo pipefail

BUILD_TYPE="${1:-debug}"
PLATFORM="${2:-device}"
PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORKSPACE_ROOT="$(cd "$PROJECT_DIR/../.." && pwd)"

echo "=== Building Orchestra agent for iOS ($PLATFORM, $BUILD_TYPE) ==="
cd "$WORKSPACE_ROOT"

# Step 1: Build the Rust static library
case "$PLATFORM" in
    device)
        TARGET="aarch64-apple-ios"
        ;;
    simulator)
        TARGET="aarch64-apple-ios-sim"
        ;;
    *)
        echo "Unknown platform: $PLATFORM (expected device or simulator)"
        exit 1
        ;;
esac

CARGOCMD="cargo build --target $TARGET -p agent"
if [ "$BUILD_TYPE" = "release" ]; then
    CARGOCMD="$CARGOCMD --release"
fi

echo "Running: $CARGOCMD"
eval "$CARGOCMD"

# Step 2: Copy the static library to the Xcode project
TARGET_DIR="$WORKSPACE_ROOT/target/$TARGET/$BUILD_TYPE"
LIB_DIR="$PROJECT_DIR/OrchestraAgent/libs"
mkdir -p "$LIB_DIR"

if [ -f "$TARGET_DIR/libagent.a" ]; then
    cp "$TARGET_DIR/libagent.a" "$LIB_DIR/liborchestra.a"
    echo "Copied libagent.a → $LIB_DIR/liborchestra.a"
else
    echo "ERROR: Could not find libagent.a in $TARGET_DIR"
    ls -la "$TARGET_DIR" 2>/dev/null || echo "(directory not found)"
    exit 1
fi

# Step 3: Build with Xcode
cd "$PROJECT_DIR"
if [ -d "OrchestraAgent.xcodeproj" ]; then
    xcodebuild -project OrchestraAgent.xcodeproj \
        -scheme OrchestraAgent \
        -configuration "$([ "$BUILD_TYPE" = "release" ] && echo "Release" || echo "Debug")" \
        -sdk iphoneos \
        build
else
    echo "No Xcode project found — skipping Xcode build."
    echo "Static library is at: $LIB_DIR/liborchestra.a"
fi

echo ""
echo "=== Build complete ==="
echo "Library: $LIB_DIR/liborchestra.a"