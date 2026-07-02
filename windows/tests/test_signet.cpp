// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

#include "signet/signet.hpp"

// Return-code test: independent of NDEBUG, so it holds in release builds too.
int main() {
    if (signet::kVersion.empty()) {
        return 1;
    }
    if (signet::platform_tag() != "windows") {
        return 2;
    }
    return 0;
}
