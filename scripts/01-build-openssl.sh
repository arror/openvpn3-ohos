#!/bin/bash
# SPDX-License-Identifier: MPL-2.0
# ============================================================================
# Cross-compile OpenSSL (trimmed) for HarmonyOS aarch64
# ============================================================================
# Usage: source scripts/env.sh && bash scripts/01-build-openssl.sh
# ============================================================================

set -ex

SRC=$DEPS_SRC/openssl/src
BUILD=$DEPS_OUT/openssl
PREFIX_OSSL=$PREFIX

mkdir -p "$BUILD"
cd "$BUILD"

# OpenSSL Configure for HarmonyOS (aarch64-linux-ohos)
# Target: linux-aarch64 with clang cross-compiler
#
# Trimmed features (not needed by OpenVPN 3):
#   no-engine        - no hardware engine support
#   no-legacy        - no legacy algorithms (DES/RC2/BF/CAST/MD2/MD4/SEED/IDEA)
#   no-cmp           - no CMP protocol
#   no-ct            - no Certificate Transparency
#   no-ocsp          - no OCSP (optional, can re-enable if needed)
#   no-srp           - no SRP authentication
#   no-ts            - no Timestamp authority
#   no-ui-console   - no terminal UI
#   no-ssl3         - no SSLv3
#   no-ssl3-method  - no SSLv3 method
#   no-dtls         - no DTLS
#   no-bf           - no Blowfish
#   no-cast         - no CAST5
#   no-md2          - no MD2
#   no-md4          - no MD4
#   no-rc2          - no RC2
#   no-rc4          - no RC4
#   no-rc5          - no RC5
#   no-idea         - no IDEA
#   no-seed         - no SEED
#   no-siv          - no SIV mode
#   no-sm2/no-sm3/no-sm4 - no Chinese crypto standards
#
# Retained algorithms:
#   AES (128/192/256) GCM + CBC
#   SHA (1/256/384/512)
#   HMAC
#   RSA, ECDSA (P-256, P-384, P-521)
#   X25519, Ed25519
#   ChaCha20-Poly1305
#   PKCS12
#   TLS 1.2 + 1.3

# OpenSSL Configure doesn't allow mixing --sysroot and -D flags as separate args.
# Everything must go through CFLAGS/LDFLAGS.
OSSL_CFLAGS="$CFLAGS --sysroot=$SYSROOT -Wno-error=unused-command-line-argument -D__OHOS__"
OSSL_LDFLAGS="--sysroot=$SYSROOT"

$SRC/Configure \
    linux-aarch64 \
    --prefix="$PREFIX_OSSL" \
    --openssldir="$PREFIX_OSSL/ssl" \
    CC="$CC" \
    CFLAGS="$OSSL_CFLAGS" \
    LDFLAGS="$OSSL_LDFLAGS" \
    AR="$AR" \
    RANLIB="$RANLIB" \
    \
    no-engine \
    no-legacy \
    no-cmp \
    no-ct \
    no-srp \
    no-ts \
    no-ui-console \
    no-ssl3 \
    no-ssl3-method \
    no-dtls \
    no-bf \
    no-cast \
    no-md2 \
    no-md4 \
    no-rc2 \
    no-rc4 \
    no-rc5 \
    no-idea \
    no-seed \
    no-siv \
    no-sm2 \
    no-sm3 \
    no-sm4 \
    no-shared \
    \
    enable-tls1_2 \
    enable-tls1_3 \
    enable-ec_nistp_64_gcc_128

# Build
make -j$(sysctl -n hw.ncpu)

# Install
make install_sw install_ssldirs

echo "============================================"
echo " OpenSSL cross-compile DONE"
echo " Output: $PREFIX_OSSL"
echo "============================================"
ls -lh "$PREFIX_OSSL/lib/"
ls "$PREFIX_OSSL/include/openssl/" | head -20
