// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

import 'signet_platform_interface.dart';

/// Signet: hardware-backed P-256 signing keys via the native cores.
///
/// Scaffold: [getPlatformVersion] is a smoke test that round-trips to the
/// native side. The signing API is added with the key code.
class Signet {
  /// Returns the native platform version string.
  Future<String?> getPlatformVersion() {
    return SignetPlatform.instance.getPlatformVersion();
  }
}
