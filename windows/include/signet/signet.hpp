// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

#ifndef SIGNET_SIGNET_HPP
#define SIGNET_SIGNET_HPP

#include <string_view>

/// @file
/// @brief Signet Windows core public surface.
///
/// Scaffold: the hardware-backed P-256 API over CNG and the TPM Platform Crypto
/// Provider lands with the key code. Nothing here holds key material or exposes
/// an export path.

namespace signet {

/// @brief Signet library version, aligned with the repository VERSION file.
inline constexpr std::string_view kVersion = "0.1.0-dev";

/// @brief Returns the platform tag of this core build.
/// @return The static platform identifier, "windows".
std::string_view platform_tag();

}  // namespace signet

#endif  // SIGNET_SIGNET_HPP
