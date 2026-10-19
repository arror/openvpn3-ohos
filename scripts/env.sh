#!/bin/bash
# SPDX-License-Identifier: MPL-2.0
# ============================================================================
# OpenVPN 3 for HarmonyOS - Cross Compilation Environment
# ============================================================================
# Source this file before running any build scripts:
#   source scripts/env.sh
# ============================================================================

# DevEco Studio paths
export TOOL_HOME=${TOOL_HOME:-/Applications/DevEco-Studio.app/Contents}
export DEVECO_SDK_HOME=$TOOL_HOME/sdk
export PATH=$TOOL_HOME/tools/ohpm/bin:$TOOL_HOME/tools/hvigor/bin:$TOOL_HOME/sdk/default/openharmony/toolchains:$PATH
export OHOS_NDK_HOME=${OHOS_NDK_HOME:-$DEVECO_SDK_HOME/default/openharmony}
export PATH=$OHOS_NDK_HOME/native/build-tools/cmake/bin:$PATH

# Project paths
if [ -n "${BASH_SOURCE:-}" ]; then
    ovpn_env_source="${BASH_SOURCE[0]}"
elif [ -n "${ZSH_VERSION:-}" ]; then
    ovpn_env_source="${(%):-%N}"
else
    echo "Source env.sh from bash or zsh" >&2
    return 1
fi
export PROJECT_ROOT="$(cd "$(dirname "$ovpn_env_source")/.." && pwd)"
export DEPS_SRC=$PROJECT_ROOT/deps          # source code
export DEPS_OUT=$PROJECT_ROOT/build         # cross-compiled output
# OPENVPN3_SRC is no longer hardcoded — CMake auto-downloads it.
# To use a local copy: export OPENVPN3_SRC=/path/to/openvpn3
# Or: cmake -DOPENVPN3_SRC=/path/to/openvpn3 ...

# Target architecture: arm64-v8a
export OHOS_ARCH=arm64-v8a
export TARGET_TRIPLE=aarch64-linux-ohos
export HOST_TRIPLE=aarch64-linux-ohos

# Compiler paths
export NDK_LLVM=$OHOS_NDK_HOME/native/llvm
export CC=$NDK_LLVM/bin/aarch64-unknown-linux-ohos-clang
export CXX=$NDK_LLVM/bin/aarch64-unknown-linux-ohos-clang++
export AR=$NDK_LLVM/bin/llvm-ar
export RANLIB=$NDK_LLVM/bin/llvm-ranlib
export STRIP=$NDK_LLVM/bin/llvm-strip

# Sysroot
export SYSROOT=$OHOS_NDK_HOME/native/sysroot
export CMAKE_TOOLCHAIN_FILE=$OHOS_NDK_HOME/native/build/cmake/ohos.toolchain.cmake

# Compiler flags
export CFLAGS="-fPIC -O2 -fstack-protector-strong -D__OHOS__"
export CXXFLAGS="$CFLAGS"
export LDFLAGS="-fPIE -Wl,-z,relro -Wl,-z,now"

# Output prefix for all cross-compiled libraries
export PREFIX=${PREFIX:-$DEPS_OUT/prefix}

echo "============================================"
echo " OpenVPN 3 for HarmonyOS - Build Environment"
echo "============================================"
echo " OHOS_NDK_HOME  = $OHOS_NDK_HOME"
echo " SYSROOT        = $SYSROOT"
echo " CC             = $CC"
echo " CXX            = $CXX"
echo " TARGET         = $TARGET_TRIPLE"
echo " PREFIX         = $PREFIX"
echo "============================================"
