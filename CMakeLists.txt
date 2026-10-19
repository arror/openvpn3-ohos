# SPDX-License-Identifier: MPL-2.0
# ============================================================================
# OpenVPN 3 for HarmonyOS - NAPI Module Build File
# ============================================================================
# This CMake file builds the OpenVPN 3 core as a NAPI shared library
# (libovpn.so) for HarmonyOS (aarch64-linux-ohos).
#
# The library is loadable from ArkTS via:
#   import ovpn from 'libovpn.so';
#
# Usage:
#   source scripts/env.sh
#   cmake -B build -S . \
#     -DCMAKE_TOOLCHAIN_FILE=$CMAKE_TOOLCHAIN_FILE \
#     -DOHOS_ARCH=arm64-v8a
#   cmake --build build -j
# ============================================================================

cmake_minimum_required(VERSION 3.16)

project(OpenVPN3_OHOS VERSION 1.0.0)

# ─── Build configuration ────────────────────────────────────────────────────

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_C_STANDARD 99)

# Output: libovpn.so in the build root (DevEco picks it up from here)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

# ─── Dependency paths ───────────────────────────────────────────────────────

set(PREFIX $ENV{PREFIX})
if(NOT PREFIX)
    set(PREFIX ${CMAKE_SOURCE_DIR}/build/prefix)
endif()
message(STATUS "PREFIX = ${PREFIX}")

# ─── OpenVPN 3 source ─────────────────────────────────────────────────────
#
# Priority:
#   1. -DOPENVPN3_SRC=/path/to/openvpn3  (explicit local path)
#   2. $ENV{OPENVPN3_SRC}                (from environment)
#   3. Auto-download by -DOPENVPN3_VERSION=3.11.7 (default)
#
# Downloaded source is extracted to ${CMAKE_SOURCE_DIR}/deps/openvpn3-release-<version>

set(OPENVPN3_VERSION_DEFAULT "3.11.7")

set(OPENVPN3_SRC $ENV{OPENVPN3_SRC})
if(NOT OPENVPN3_SRC)
    set(OPENVPN3_SRC "" CACHE PATH "Path to OpenVPN 3 source tree (empty = auto-download)")
endif()

if(NOT OPENVPN3_SRC)
    # Auto-download mode
    set(OPENVPN3_VERSION ${OPENVPN3_VERSION_DEFAULT} CACHE STRING "OpenVPN 3 release version to download")
    if(OPENVPN3_VERSION STREQUAL "3.11.7")
        set(OPENVPN3_SHA256_DEFAULT "6ec04d7e7824f043ee2ec6c2d98ce2655350e5cdcc969ab60a5f68cecb232289")
    else()
        set(OPENVPN3_SHA256_DEFAULT "")
    endif()
    set(OPENVPN3_SHA256 "${OPENVPN3_SHA256_DEFAULT}" CACHE STRING "SHA256 of the exact OpenVPN archive")
    if(NOT OPENVPN3_SHA256)
        message(FATAL_ERROR "Set OPENVPN3_SHA256 when selecting a different upstream version")
    endif()
    set(OPENVPN3_SRC ${CMAKE_SOURCE_DIR}/deps/openvpn3-release-${OPENVPN3_VERSION})
    set(OPENVPN3_TARBALL ${CMAKE_SOURCE_DIR}/deps/openvpn3-${OPENVPN3_VERSION}.tar.gz)
    set(OPENVPN3_URL "https://github.com/OpenVPN/openvpn3/archive/refs/tags/release/${OPENVPN3_VERSION}.tar.gz")

    if(NOT EXISTS ${OPENVPN3_SRC}/CMakeLists.txt)
        message(STATUS "OpenVPN 3 source not found, downloading v${OPENVPN3_VERSION}...")
        message(STATUS "  URL: ${OPENVPN3_URL}")
        file(MAKE_DIRECTORY ${CMAKE_SOURCE_DIR}/deps)
        if(NOT EXISTS ${OPENVPN3_TARBALL})
            file(DOWNLOAD ${OPENVPN3_URL} ${OPENVPN3_TARBALL}
                 STATUS download_status
                 TIMEOUT 300
                 SHOW_PROGRESS)
            list(GET download_status 0 status_code)
            if(NOT status_code EQUAL 0)
                list(GET download_status 1 status_msg)
                message(FATAL_ERROR "Failed to download OpenVPN 3: ${status_msg} (${status_code})")
            endif()
        endif()
        file(SHA256 "${OPENVPN3_TARBALL}" OPENVPN3_ARCHIVE_SHA256)
        if(NOT OPENVPN3_ARCHIVE_SHA256 STREQUAL OPENVPN3_SHA256)
            message(FATAL_ERROR "OpenVPN archive SHA256 mismatch: ${OPENVPN3_TARBALL}")
        endif()
        message(STATUS "Extracting OpenVPN 3 ${OPENVPN3_VERSION}...")
        file(ARCHIVE_EXTRACT INPUT ${OPENVPN3_TARBALL}
             DESTINATION ${CMAKE_SOURCE_DIR}/deps)
        # GitHub extracts as openvpn3-release-<version>
        if(NOT EXISTS ${OPENVPN3_SRC}/CMakeLists.txt)
            file(GLOB EXTRACTED_DIRS ${CMAKE_SOURCE_DIR}/deps/openvpn3-*)
            foreach(DIR ${EXTRACTED_DIRS})
                if(EXISTS ${DIR}/CMakeLists.txt)
                    set(OPENVPN3_SRC ${DIR})
                    break()
                endif()
            endforeach()
        endif()
        if(NOT EXISTS ${OPENVPN3_SRC}/CMakeLists.txt)
            message(FATAL_ERROR "OpenVPN 3 source extraction failed. Expected: ${OPENVPN3_SRC}")
        endif()
        message(STATUS "OpenVPN 3 source ready at: ${OPENVPN3_SRC}")
    endif()
endif()

message(STATUS "OPENVPN3_SRC = ${OPENVPN3_SRC}")

# ─── asio (header-only library, required by OpenVPN 3) ─────────────────────
#
# Priority:
#   1. -DASIO_INCLUDE_DIR=/path/to/asio/include  (explicit)
#   2. ${OPENVPN3_SRC}/deps/asio/asio/include     (bundled with OpenVPN 3)
#   3. Auto-download pinned asio-1.24.0 from GitHub

set(ASIO_VERSION_DEFAULT "1.24.0")

set(ASIO_INCLUDE_DIR "" CACHE PATH "Path to asio include directory (empty = auto-detect)")

if(NOT ASIO_INCLUDE_DIR)
    # Try OpenVPN 3 bundled asio
    if(EXISTS ${OPENVPN3_SRC}/deps/asio/asio/include/asio.hpp)
        set(ASIO_INCLUDE_DIR ${OPENVPN3_SRC}/deps/asio/asio/include)
    endif()
endif()

if(NOT ASIO_INCLUDE_DIR)
    # Try local deps/asio
    if(EXISTS ${CMAKE_SOURCE_DIR}/deps/asio/src/asio/include/asio.hpp)
        set(ASIO_INCLUDE_DIR ${CMAKE_SOURCE_DIR}/deps/asio/src/asio/include)
    endif()
endif()

if(NOT ASIO_INCLUDE_DIR)
    # Auto-download
    set(ASIO_VERSION ${ASIO_VERSION_DEFAULT} CACHE STRING "asio version to download")
    if(ASIO_VERSION STREQUAL "1.24.0")
        set(ASIO_SHA256_DEFAULT "cbcaaba0f66722787b1a7c33afe1befb3a012b5af3ad7da7ff0f6b8c9b7a8a5b")
    else()
        set(ASIO_SHA256_DEFAULT "")
    endif()
    set(ASIO_SHA256 "${ASIO_SHA256_DEFAULT}" CACHE STRING "SHA256 of the exact Asio archive")
    if(NOT ASIO_SHA256)
        message(FATAL_ERROR "Set ASIO_SHA256 when selecting a different upstream version")
    endif()
    set(ASIO_TARBALL ${CMAKE_SOURCE_DIR}/deps/asio-${ASIO_VERSION}.tar.gz)
    string(REPLACE "." "-" ASIO_TAG_VERSION "${ASIO_VERSION}")
    set(ASIO_EXTRACTED_DIR ${CMAKE_SOURCE_DIR}/deps/asio-asio-${ASIO_TAG_VERSION})
    set(ASIO_INCLUDE_DIR ${ASIO_EXTRACTED_DIR}/asio/include)
    set(ASIO_URL "https://github.com/chriskohlhoff/asio/archive/refs/tags/asio-${ASIO_TAG_VERSION}.tar.gz")

    if(NOT EXISTS ${ASIO_INCLUDE_DIR}/asio.hpp)
        message(STATUS "asio not found, downloading v${ASIO_VERSION}...")
        message(STATUS "  URL: ${ASIO_URL}")
        file(MAKE_DIRECTORY ${CMAKE_SOURCE_DIR}/deps)
        if(NOT EXISTS ${ASIO_TARBALL})
            file(DOWNLOAD ${ASIO_URL} ${ASIO_TARBALL}
                 STATUS download_status
                 TIMEOUT 300
                 SHOW_PROGRESS)
            list(GET download_status 0 status_code)
            if(NOT status_code EQUAL 0)
                list(GET download_status 1 status_msg)
                message(FATAL_ERROR "Failed to download asio: ${status_msg} (${status_code})")
            endif()
        endif()
        message(STATUS "Extracting asio ${ASIO_VERSION}...")
        file(SHA256 "${ASIO_TARBALL}" ASIO_ARCHIVE_SHA256)
        if(NOT ASIO_ARCHIVE_SHA256 STREQUAL ASIO_SHA256)
            message(FATAL_ERROR "Asio archive SHA256 mismatch: ${ASIO_TARBALL}")
        endif()
        file(ARCHIVE_EXTRACT INPUT ${ASIO_TARBALL}
             DESTINATION ${CMAKE_SOURCE_DIR}/deps)
        # GitHub extracts as asio-asio-<version>
        if(NOT EXISTS ${ASIO_INCLUDE_DIR}/asio.hpp)
            if(EXISTS ${ASIO_EXTRACTED_DIR}/include/asio.hpp)
                set(ASIO_INCLUDE_DIR ${ASIO_EXTRACTED_DIR}/include)
            endif()
        endif()
        if(NOT EXISTS ${ASIO_INCLUDE_DIR}/asio.hpp)
            message(FATAL_ERROR "asio extraction failed. Expected: ${ASIO_INCLUDE_DIR}")
        endif()
        message(STATUS "asio ready at: ${ASIO_INCLUDE_DIR}")
    endif()
endif()

message(STATUS "ASIO_INCLUDE_DIR = ${ASIO_INCLUDE_DIR}")

# HarmonyOS NDK sysroot (for NAPI and hilog headers/libs)
set(OHOS_SYSROOT $ENV{OHOS_NDK_HOME}/native/sysroot)
message(STATUS "OHOS_SYSROOT = ${OHOS_SYSROOT}")

# ─── OpenVPN 3 core sources (compiled into the .so) ────────────────────────

set(OPENVPN3_CORE_SOURCES
    ${OPENVPN3_SRC}/openvpn/crypto/data_epoch.cpp
)

set(OPENVPN3_XKEY_SOURCES
    ${OPENVPN3_SRC}/openvpn/openssl/xkey/xkey_helper.c
    ${OPENVPN3_SRC}/openvpn/openssl/xkey/xkey_provider.c
)

# ─── libovpn.so — NAPI module ──────────────────────────────────────────────
#
# This single shared library contains:
#   1. The entire OpenVPN 3 core (via napi_init.cpp which includes ovpncli.cpp)
#   2. The HarmonyOS TunBuilder implementation
#   3. The NAPI interface layer (exposing createSession/connect/etc. to ArkTS)
#   4. HiLog log redirection

add_library(ovpn SHARED
    ${CMAKE_SOURCE_DIR}/src/napi_init.cpp
    ${OPENVPN3_CORE_SOURCES}
    ${OPENVPN3_XKEY_SOURCES}
)

# ─── Include directories ────────────────────────────────────────────────────

target_include_directories(ovpn PRIVATE
    ${OPENVPN3_SRC}                          # for <openvpn/...> and <client/...>
    ${ASIO_INCLUDE_DIR}                      # asio (header-only)
    ${PREFIX}/include                        # cross-compiled deps (OpenSSL, LZ4)
    ${OHOS_SYSROOT}/usr/include              # NAPI + hilog headers
    ${OHOS_SYSROOT}/usr/include/aarch64-linux-ohos  # arch-specific headers
)

# ─── Compile definitions ───────────────────────────────────────────────────

target_compile_definitions(ovpn PRIVATE
    ASIO_STANDALONE
    USE_ASIO
    HAVE_LZ4
    USE_OPENSSL
    USE_TUN_BUILDER                        # use TunBuilderBase callbacks
    OPENVPN_FORCE_TUN_NULL                  # don't use real /dev/net/tun
    OPENVPN_USE_LOG_BASE_SIMPLE             # simple thread-local logger
    HAVE_XKEY_PROVIDER=1
    __OHOS__
    __linux__                               # OHOS is Linux-kernel based
)

# ─── Compile options ───────────────────────────────────────────────────────

target_compile_options(ovpn PRIVATE
    -Wall
    -Wno-sign-compare
    -Wno-unused-parameter
    -Wno-deprecated-declarations
    -Wno-unused-function
    -Wno-uninitialized
    -Wno-unused-command-line-argument
    -fexceptions
    -fvisibility=hidden
    --sysroot=${OHOS_SYSROOT}
)

# ─── Link directories ───────────────────────────────────────────────────────

target_link_directories(ovpn PRIVATE
    ${PREFIX}/lib
    ${OHOS_SYSROOT}/usr/lib/aarch64-linux-ohos
)

# ─── Link libraries ─────────────────────────────────────────────────────────
#
# Static deps: OpenSSL and LZ4. LZO receive compatibility uses the MPL Core decoder.
# Shared deps: libace_napi.z.so (NAPI runtime), libhilog_ndk.z.so (HiLog)
# System: pthread, dl

target_link_libraries(ovpn
    # NAPI runtime (provides napi_module_register, napi_create_*, etc.)
    ace_napi.z

    # HiLog (provides OH_LOG_Print, OH_LOG_INFO, etc.)
    hilog_ndk.z

    # OpenSSL (static, cross-compiled)
    ${PREFIX}/lib/libssl.a
    ${PREFIX}/lib/libcrypto.a

    # Compression (static, cross-compiled)
    ${PREFIX}/lib/liblz4.a

    # Statically link C++ runtime to avoid libc++_shared.so dependency
    -static-libstdc++

    # System
    pthread
    dl
)

# ─── Install ────────────────────────────────────────────────────────────────

install(TARGETS ovpn
    LIBRARY DESTINATION lib
)

install(FILES ${CMAKE_SOURCE_DIR}/index.d.ts
    DESTINATION .
)
