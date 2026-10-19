#!/bin/bash
# SPDX-License-Identifier: MPL-2.0
# ============================================================================
# build.sh — Build libovpn.so and deploy to HarmonyOS project
# ============================================================================
# Automatically loads env.sh, builds the NAPI shared library, and copies
# the output to the HarmonyOS project's libs/ and ets/ directories.
#
# Usage:
#   ./scripts/build.sh          # build + deploy
#   ./scripts/build.sh --clean  # clean build directory first (same as default)
# ============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="$PROJECT_ROOT/build_napi"
OHOS_PROJECT="${OHOS_APP_DIR:-$PROJECT_ROOT/ohos}"
OHOS_ENTRY="$OHOS_PROJECT/entry"

# ─── Load environment ─────────────────────────────────────────────────────
# Source env.sh to set up NDK paths, compiler, toolchain, etc.

if [ -f "$SCRIPT_DIR/env.sh" ]; then
    source "$SCRIPT_DIR/env.sh"
else
    echo "ERROR: scripts/env.sh not found"
    exit 1
fi

# Verify required environment variables
if [ -z "$CMAKE_TOOLCHAIN_FILE" ]; then
    echo "ERROR: CMAKE_TOOLCHAIN_FILE is not set. Check scripts/env.sh"
    exit 1
fi
if [ -z "$OHOS_NDK_HOME" ]; then
    echo "ERROR: OHOS_NDK_HOME is not set. Check scripts/env.sh"
    exit 1
fi

# ─── Build ─────────────────────────────────────────────────────────────────

echo "=========================================="
echo " Building libovpn.so (HarmonyOS aarch64)"
echo "=========================================="

# Clean & configure
rm -rf "$BUILD_DIR"
cmake -B "$BUILD_DIR" -S "$PROJECT_ROOT" \
    -DCMAKE_TOOLCHAIN_FILE="$CMAKE_TOOLCHAIN_FILE" \
    -DOHOS_ARCH=arm64-v8a

# Build
cmake --build "$BUILD_DIR" -j$(sysctl -n hw.ncpu 2>/dev/null || echo 4)

# ─── Verify ────────────────────────────────────────────────────────────────

SO_FILE="$BUILD_DIR/libovpn.so"
if [ ! -f "$SO_FILE" ]; then
    echo "ERROR: libovpn.so not found at $SO_FILE"
    exit 1
fi

echo ""
echo "Build output:"
ls -lh "$SO_FILE"
python3 "$SCRIPT_DIR/check-no-external-lzo.py" "$SO_FILE" --nm "$OHOS_NDK_HOME/native/llvm/bin/llvm-nm"
echo ""

# Check dynamic dependencies
echo "Dynamic dependencies:"
"$OHOS_NDK_HOME/native/llvm/bin/llvm-readelf" -d "$SO_FILE" 2>/dev/null | grep NEEDED || true
echo ""

# ─── Deploy ─────────────────────────────────────────────────────────────────

if [ ! -d "$OHOS_ENTRY" ]; then
    if [ -n "${OHOS_APP_DIR:-}" ]; then
        echo "ERROR: OHOS_APP_DIR must point to an application containing entry/" >&2
        exit 1
    fi
    echo "Native build complete. No application checkout; deployment skipped."
    echo "Set OHOS_APP_DIR to deploy libovpn.so and index.d.ts into an app."
    exit 0
fi

echo "=========================================="
echo " Deploying to HarmonyOS project"
echo "=========================================="

# 1. Copy libovpn.so to entry/libs/arm64-v8a/
LIBS_DIR="$OHOS_ENTRY/libs/arm64-v8a"
mkdir -p "$LIBS_DIR"
cp -f "$SO_FILE" "$LIBS_DIR/libovpn.so"
echo "  Copied libovpn.so → $LIBS_DIR/libovpn.so"

# 2. Copy index.d.ts to entry/src/main/ets/libovpn/
TS_DIR="$OHOS_ENTRY/src/main/ets/libovpn"
mkdir -p "$TS_DIR"
cp -f "$PROJECT_ROOT/index.d.ts" "$TS_DIR/index.d.ts"
echo "  Copied index.d.ts → $TS_DIR/index.d.ts"

echo ""
echo "=========================================="
echo " Done! libovpn.so deployed to HarmonyOS project."
echo "=========================================="
echo ""
echo "Files deployed:"
echo "  $LIBS_DIR/libovpn.so"
echo "  $TS_DIR/index.d.ts"
