// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

// Signet conformance runner (Kotlin), scaffold stub.
// Answers every behavior with "unimplemented", one answer per request. The stub
// extracts the behavior id with a regex to stay dependency-free as a script.

generateSequence(::readLine).forEach { line ->
    val text = line.trim()
    if (text.isEmpty()) return@forEach
    val match = Regex("\"behavior\"\\s*:\\s*\"([^\"]+)\"").find(text) ?: return@forEach
    val behavior = match.groupValues[1]
    println("{\"behavior\":\"$behavior\",\"status\":\"unimplemented\"}")
}
