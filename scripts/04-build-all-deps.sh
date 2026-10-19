#!/bin/bash
# SPDX-License-Identifier: MPL-2.0
# ============================================================================
# Build all third-party dependencies for OpenVPN 3 on HarmonyOS
# ============================================================================
# Usage: source scripts/env.sh && bash scripts/04-build-all-deps.sh
# ============================================================================

set -ex

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  Building all dependencies for OpenVPN 3 on HarmonyOS       ║"
echo "╚══════════════════════════════════════════════════════════════╝"

mkdir -p "$PREFIX"

# ─── 1. OpenSSL (trimmed) ───
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  [1/3] Building OpenSSL (trimmed for OpenVPN)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
bash "$(dirname "$0")/01-build-openssl.sh"

# ─── 2. LZ4 ───
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  [2/3] Building LZ4"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
bash "$(dirname "$0")/02-build-lz4.sh"

# ─── 3. asio (header-only, just copy) ───
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  [3/3] Installing asio (header-only)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
mkdir -p "$PREFIX/include"
cp -r "$DEPS_SRC/asio/src/asio/include/asio" "$PREFIX/include/"
cp "$DEPS_SRC/asio/src/asio/include/asio.hpp" "$PREFIX/include/"

# ─── Summary ───
echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  All dependencies built successfully!                        ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  Output prefix: $PREFIX"
echo "║"
echo "║  Libraries:"
ls -1 "$PREFIX/lib/"*.so* "$PREFIX/lib/"*.a 2>/dev/null | sed 's/^/║    /'
echo "║"
echo "║  Headers:"
ls -d "$PREFIX/include/"*/ 2>/dev/null | sed 's/^/║    /'
echo "╚══════════════════════════════════════════════════════════════╝"
