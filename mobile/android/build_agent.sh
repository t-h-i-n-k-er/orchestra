#!/usr/bin/env bash
#
# build_agent.sh — Compile the Orchestra Rust agent for Android and assemble the APK.
#
# Prerequisites:
#   - Rust toolchain with targets: aarch64-linux-android, x86_64-linux-android
#     Install via: rustup target add aarch64-linux-android x86_64-linux-android
#   - Android NDK (LLVM/clang for aarch64-linux-android)
#   - Gradle 8.x
#   - Android SDK (compileSdk 34)
#
# Usage:
#   ./build_agent.sh [debug|release] [arm64|x86_64]
#
# Output: mobile/android/app/build/outputs/apk/debug/app-debug.apk

set -euo pipefail

BUILD_TYPE="${1:-debug}"
ARCH="${2:-arm64}"
PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORKSPACE_ROOT="$(cd "$PROJECT_DIR/../.." && pwd)"

case "$ARCH" in
    arm64|arm64-v8a|aarch64)
        RUST_TARGET="aarch64-linux-android"
        JNILIBS_DIR="$PROJECT_DIR/app/src/main/jniLibs/arm64-v8a"
        ;;
    x86_64|x64)
        RUST_TARGET="x86_64-linux-android"
        JNILIBS_DIR="$PROJECT_DIR/app/src/main/jniLibs/x86_64"
        ;;
    *)
        echo "Unknown architecture: $ARCH (expected arm64 or x86_64)"
        exit 1
        ;;
esac

echo "=== Building Orchestra agent for $RUST_TARGET ($BUILD_TYPE) ==="

# Step 1: Build the Rust shared library
cd "$WORKSPACE_ROOT"

CARGOCMD="cargo build --target $RUST_TARGET -p agent"
if [ "$BUILD_TYPE" = "release" ]; then
    CARGOCMD="$CARGOCMD --release"
fi

# Use the Android NDK C compiler.  cargo-ndk automates this, but a manual
# fallback is provided when cargo-ndk is not available.
if command -v cargo-ndk &>/dev/null; then
    # cargo-ndk handles CC, AR, and the NDK sysroot automatically.
    cargo ndk --target "$RUST_TARGET" --platform 26 -- build -p agent
    if [ "$BUILD_TYPE" = "release" ]; then
        cargo ndk --target "$RUST_TARGET" --platform 26 -- build --release -p agent
    fi
else
    echo "cargo-ndk not found; using raw cargo build."
    echo "You may need to set CC_aarch64_linux_android or install cargo-ndk."
    echo "Attempting build — if ring/cc-rs fails, install cargo-ndk: cargo install cargo-ndk"
    eval "$CARGOCMD"
fi

# Step 2: Copy the compiled .so to jniLibs
TARGET_DIR="$WORKSPACE_ROOT/target/$RUST_TARGET/$BUILD_TYPE"
mkdir -p "$JNILIBS_DIR"

SO_NAME="liborchestra.so"
if [ -f "$TARGET_DIR/$SO_NAME" ]; then
    cp "$TARGET_DIR/$SO_NAME" "$JNILIBS_DIR/$SO_NAME"
    echo "Copied $SO_NAME → $JNILIBS_DIR/$SO_NAME"
elif [ -f "$TARGET_DIR/libagent.so" ]; then
    cp "$TARGET_DIR/libagent.so" "$JNILIBS_DIR/$SO_NAME"
    echo "Copied libagent.so → $JNILIBS_DIR/$SO_NAME"
else
    echo "ERROR: Could not find compiled .so in $TARGET_DIR"
    echo "Contents of $TARGET_DIR:"
    ls -la "$TARGET_DIR" 2>/dev/null || echo "(directory not found)"
    exit 1
fi

# Step 3: Build the Android APK via Gradle
cd "$PROJECT_DIR"
if [ -f "./gradlew" ]; then
    ./gradlew assembleDebug
else
    gradle assembleDebug
fi

echo ""
echo "=== Build complete ==="
echo "APK: $PROJECT_DIR/app/build/outputs/apk/debug/app-debug.apk"