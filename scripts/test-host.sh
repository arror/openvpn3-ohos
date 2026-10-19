#!/bin/bash
# SPDX-License-Identifier: MPL-2.0
# ============================================================================
# Host-side tests (macOS / Linux) for the pure-C++ layers
# ============================================================================
#   src/test_profile_model.cpp  — .ovpn parse/build round-trip
#   src/test_route_emulate.cpp  — exclude-route complement
#
# These do NOT touch the OHOS target: they compile against host OpenSSL/LZ4
# so the logic can be regression-tested without a device or the NDK.
#
# Usage:
#   bash scripts/test-host.sh              # build + run
#   bash scripts/test-host.sh --rebuild    # force recompile
#
# Requires (Homebrew on macOS):
#   brew install openssl@3 lz4
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="$PROJECT_ROOT/build/host-tests"

OPENVPN3_VERSION="${OPENVPN3_VERSION:-3.11.7}"

# ─── Locate OpenVPN 3 source (created by CMake configure, or set OPENVPN3_SRC) ─

if [ -z "${OPENVPN3_SRC:-}" ]; then
    OPENVPN3_SRC="$PROJECT_ROOT/deps/openvpn3-release-$OPENVPN3_VERSION"
fi
if [ ! -d "$OPENVPN3_SRC/openvpn" ]; then
    echo "ERROR: OpenVPN 3 source not found at:"
    echo "         $OPENVPN3_SRC"
    echo "       Get it either by running 'bash scripts/build.sh' once (CMake"
    echo "       downloads it), or by exporting OPENVPN3_SRC=/path/to/openvpn3."
    exit 1
fi

# ─── Locate asio headers (local deps/ first, then CMake-downloaded copies) ─────

ASIO_INC="${ASIO_INCLUDE_DIR:-}"
if [ -z "$ASIO_INC" ]; then
for candidate in \
    "$PROJECT_ROOT/deps/asio/src/asio/include" \
    "$PROJECT_ROOT/deps/asio-asio-1-24-0/asio/include" \
    "$OPENVPN3_SRC/deps/asio/asio/include" \
    "$PROJECT_ROOT/build/prefix/include"; do
    if [ -f "$candidate/asio.hpp" ]; then
        ASIO_INC="$candidate"
        break
    fi
done
fi
if [ -z "$ASIO_INC" ]; then
    echo "ERROR: asio headers not found. Run 'bash scripts/00-fetch-deps.sh'."
    exit 1
fi

# ─── Host OpenSSL / LZ4 ──────────────────────────────────────────────────────

if ! command -v brew >/dev/null 2>&1; then
    echo "ERROR: Homebrew is required on macOS to locate openssl@3 / lz4."
    exit 1
fi
# 'brew --prefix openssl' would resolve to openssl@4; pin the 3.x line that
# matches the cross-compiled target library.
SSL_PREFIX="$(brew --prefix openssl@3)"
LZ4_PREFIX="$(brew --prefix lz4)"
for p in "$SSL_PREFIX" "$LZ4_PREFIX"; do
    if [ ! -d "$p" ]; then
        echo "ERROR: $p missing — 'brew install openssl@3 lz4'"
        exit 1
    fi
done

HOST_CXX="${HOST_CXX:-clang++}"
CXXFLAGS=(-std=c++17 -O1 -Wall -Wno-unused-parameter -Wno-deprecated-declarations)
DEFINES=(
    -DASIO_STANDALONE -DUSE_ASIO -DUSE_OPENSSL -DHAVE_LZ4
    -DUSE_TUN_BUILDER -DOPENVPN_FORCE_TUN_NULL -DOPENVPN_USE_LOG_BASE_SIMPLE
)
INCLUDES=(-I"$OPENVPN3_SRC" -I"$ASIO_INC" -I"$SSL_PREFIX/include"
          -I"$LZ4_PREFIX/include")
LDFLAGS=(-L"$SSL_PREFIX/lib" -L"$LZ4_PREFIX/lib"
         -lcrypto -lssl -llz4 -pthread)
# data_epoch.cpp is the only core .cpp that must be compiled alongside the
# headers (the rest arrives via #include <client/ovpncli.cpp>).
EXTRA_SRCS=("$OPENVPN3_SRC/openvpn/crypto/data_epoch.cpp")

if [ "${1:-}" = "--rebuild" ]; then
    rm -rf "$BUILD_DIR"
fi
mkdir -p "$BUILD_DIR"

TESTS=(test_profile_model test_route_emulate test_session_runtime test_compression)
FAILED=()

for t in "${TESTS[@]}"; do
    echo "▶ building $t ..."
    "$HOST_CXX" "${CXXFLAGS[@]}" "${DEFINES[@]}" "${INCLUDES[@]}" \
        "$PROJECT_ROOT/src/$t.cpp" "${EXTRA_SRCS[@]}" "${LDFLAGS[@]}" \
        -o "$BUILD_DIR/$t"
    echo "▶ running $t"
    if "$BUILD_DIR/$t"; then
        echo "✔ $t passed"
    else
        FAILED+=("$t")
    fi
    echo
done

if [ ${#FAILED[@]} -gt 0 ]; then
    echo "✘ FAILED: ${FAILED[*]}"
    exit 1
fi
export ARKOVPN_APP_ROOT="${ARKOVPN_APP_ROOT:-$PROJECT_ROOT/ohos}"
if [ -d "$ARKOVPN_APP_ROOT/entry/src/main/ets" ]; then
    echo "▶ running external application integration regressions"
    NODE_BIN="${NODE_BIN:-node}"
    "$NODE_BIN" "$PROJECT_ROOT/scripts/test-tun-proxy.cjs"
    "$NODE_BIN" "$PROJECT_ROOT/scripts/test-file-utils.cjs"
    "$NODE_BIN" "$PROJECT_ROOT/scripts/test-lab-readiness.cjs"
    "$NODE_BIN" "$PROJECT_ROOT/scripts/test-legal.cjs"
else
    echo "No application checkout: ArkTS integration tests not run (set ARKOVPN_APP_ROOT)."
fi
python3 "$PROJECT_ROOT/scripts/check-licenses.py"
python3 "$PROJECT_ROOT/scripts/test-dependency-integrity.py"
echo "All host tests passed."
