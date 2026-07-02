// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

// Signet conformance runner (Swift), scaffold stub.
// Answers every behavior with "unimplemented", one answer per request.

import Foundation

while let line = readLine() {
    let text = line.trimmingCharacters(in: .whitespacesAndNewlines)
    if text.isEmpty { continue }
    guard let data = text.data(using: .utf8),
          let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
          let behavior = object["behavior"] as? String else { continue }
    print("{\"behavior\":\"\(behavior)\",\"status\":\"unimplemented\"}")
}
