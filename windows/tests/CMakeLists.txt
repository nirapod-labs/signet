# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Nirapod Labs

add_executable(signet_windows_tests test_signet.cpp)
target_link_libraries(signet_windows_tests PRIVATE signet_windows)
add_test(NAME signet_windows_tests COMMAND signet_windows_tests)
