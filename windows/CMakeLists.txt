# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Nirapod Labs

cmake_minimum_required(VERSION 3.24...3.31)

project(signet_windows
    VERSION 0.1.0
    DESCRIPTION "Signet Windows core: hardware-backed P-256 keys over CNG and the TPM Platform Crypto Provider"
    LANGUAGES CXX)

option(SIGNET_BUILD_TESTS "Build the Signet Windows core tests" ON)

add_library(signet_windows)
add_library(Signet::Windows ALIAS signet_windows)

target_sources(signet_windows
    PRIVATE
        src/signet.cpp)

target_include_directories(signet_windows
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>)

target_compile_features(signet_windows PUBLIC cxx_std_17)

# The CNG key-storage backend links ncrypt on Windows. It lands with the key
# code; the scaffold builds on every platform so the core stays portable.
if(WIN32)
    target_link_libraries(signet_windows PRIVATE ncrypt)
endif()

if(SIGNET_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
