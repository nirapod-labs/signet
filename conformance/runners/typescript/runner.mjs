// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

// Signet conformance runner (TypeScript/Node), scaffold stub.
// Answers every behavior with "unimplemented", one answer per request; an
// unimplemented behavior is never a silent skip. Real assertions replace the
// stub as the binding lands.

import { createInterface } from 'node:readline'

const lines = createInterface({ input: process.stdin, terminal: false })
lines.on('line', (line) => {
  const text = line.trim()
  if (!text) return
  let request
  try {
    request = JSON.parse(text)
  } catch {
    return
  }
  if (!request.behavior) return
  process.stdout.write(
    `${JSON.stringify({ behavior: request.behavior, status: 'unimplemented' })}\n`,
  )
})
