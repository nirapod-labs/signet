// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

import Testing
@testable import SignetAppleCore

@Test func versionIsSet() async throws {
    #expect(!Signet.version.isEmpty)
    #expect(Signet.platformTag() == "apple")
}
