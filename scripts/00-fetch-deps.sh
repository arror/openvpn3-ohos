#!/bin/bash
# SPDX-License-Identifier: MPL-2.0
# ============================================================================
# Fetch the third-party dependency sources into deps/
# ============================================================================
# deps/ is not tracked by git (it holds ~170MB of upstream sources). This
# script restores exactly the versions the cross-compile scripts expect:
#
#   deps/openssl/src/          OpenSSL 3.5.0     (01-build-openssl.sh)
#   deps/lz4/src/lib/          LZ4 1.10.0        (02-build-lz4.sh)
#   deps/asio/src/asio/        asio 1.24.0       (04-build-all-deps.sh)
#
# OpenVPN 3 core itself is downloaded automatically by CMakeLists.txt.
#
# Usage:
#   bash scripts/00-fetch-deps.sh
#   bash scripts/00-fetch-deps.sh --force    # re-download even if present
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DEPS_SRC="${DEPS_SRC:-$(cd "$SCRIPT_DIR/.." && pwd)/deps}"
FORCE=0
[ "${1:-}" = "--force" ] && FORCE=1

# name | version | url | marker file relative to deps/<name>/src | SHA256
DEPS=(
    "openssl|3.5.0|https://github.com/openssl/openssl/releases/download/openssl-3.5.0/openssl-3.5.0.tar.gz|Configure|344d0a79f1a9b08029b0744e2cc401a43f9c90acd1044d09a530b4885a8e9fc0"
    "lz4|1.10.0|https://github.com/lz4/lz4/archive/refs/tags/v1.10.0.tar.gz|lib/lz4.h|537512904744b35e232912055ccf8ec66d768639ff3abe5788d90d792ec5f48b"
    "asio|1.24.0|https://github.com/chriskohlhoff/asio/archive/refs/tags/asio-1-24-0.tar.gz|asio/include/asio.hpp|cbcaaba0f66722787b1a7c33afe1befb3a012b5af3ad7da7ff0f6b8c9b7a8a5b"
)

for entry in "${DEPS[@]}"; do
    IFS='|' read -r name version url marker expected_sha256 <<<"$entry"
    dest="$DEPS_SRC/$name/src"

    if [ -f "$dest/$marker" ] && [ $FORCE -eq 0 ]; then
        echo "✔ $name $version already present at $dest"
        continue
    fi

    mkdir -p "$DEPS_SRC/$name"
    [ -d "$dest" ] && rm -rf "$dest"
    tarball="$DEPS_SRC/$name-$version.tar.gz"

    echo "▶ downloading $name $version ..."
    echo "  $url"
    if [ ! -f "$tarball" ]; then
        curl -fL --retry 3 --proto '=https' --tlsv1.2 -o "$tarball.part" "$url"
        mv "$tarball.part" "$tarball"
    fi

    actual_sha256="$(shasum -a 256 "$tarball" | cut -d ' ' -f 1)"
    if [ "$actual_sha256" != "$expected_sha256" ]; then
        echo "ERROR: SHA256 mismatch for $name archive: $tarball" >&2
        exit 1
    fi

    echo "▶ extracting → $dest"
    mkdir -p "$dest"
    tar -xzf "$tarball" --strip-components=1 -C "$dest"

    if [ ! -f "$dest/$marker" ]; then
        echo "ERROR: extracted $name but $dest/$marker is missing — wrong archive layout?"
        exit 1
    fi
    echo "✔ $name $version ready"
    echo
done

echo "All dependency sources ready under $DEPS_SRC"
echo "Next: source scripts/env.sh && bash scripts/04-build-all-deps.sh"
