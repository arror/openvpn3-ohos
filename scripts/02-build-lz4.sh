#!/bin/bash
# SPDX-License-Identifier: MPL-2.0
# ============================================================================
# Cross-compile LZ4 for HarmonyOS aarch64
# ============================================================================
# Usage: source scripts/env.sh && bash scripts/02-build-lz4.sh
# ============================================================================

set -ex

SRC=$DEPS_SRC/lz4/src/lib
BUILD=$DEPS_OUT/lz4
PREFIX_LZ4=$PREFIX

mkdir -p "$BUILD"
cd "$BUILD"

# LZ4 is a simple C library - just compile the core source files
# Core files: lz4.c, lz4hc.c (lz4frame.c and xxhash.c are optional)
# OpenVPN 3 only uses lz4.h/lz4hc.h, not lz4frame

$CC $CFLAGS --sysroot=$SYSROOT \
    -I$SRC \
    -c $SRC/lz4.c -o lz4.o

$CC $CFLAGS --sysroot=$SYSROOT \
    -I$SRC \
    -c $SRC/lz4hc.c -o lz4hc.o

$CC $CFLAGS --sysroot=$SYSROOT \
    -I$SRC \
    -c $SRC/lz4frame.c -o lz4frame.o

$CC $CFLAGS --sysroot=$SYSROOT \
    -I$SRC \
    -c $SRC/xxhash.c -o xxhash.o

# Create shared library
$CC -shared -fPIC \
    --sysroot=$SYSROOT \
    -Wl,-soname,liblz4.so.1 \
    lz4.o lz4hc.o lz4frame.o xxhash.o \
    -o liblz4.so.1.10.0

# Create symlinks
ln -sf liblz4.so.1.10.0 liblz4.so.1
ln -sf liblz4.so.1 liblz4.so

# Create static library
$AR rcs liblz4.a lz4.o lz4hc.o lz4frame.o xxhash.o

# Install
mkdir -p "$PREFIX_LZ4/lib" "$PREFIX_LZ4/include"
cp -a liblz4.so* "$PREFIX_LZ4/lib/"
cp liblz4.a "$PREFIX_LZ4/lib/"
cp $SRC/lz4.h $SRC/lz4hc.h $SRC/lz4frame.h $SRC/lz4file.h "$PREFIX_LZ4/include/"

echo "============================================"
echo " LZ4 cross-compile DONE"
echo " Output: $PREFIX_LZ4/lib/liblz4.so"
echo "============================================"
ls -lh "$PREFIX_LZ4/lib/liblz4*"
