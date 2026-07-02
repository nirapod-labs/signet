// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

// Signet polyglot conformance driver.
//
// Loads the contract in conformance/ (the single source of truth), then drives
// four independent language runners over a line-delimited JSON protocol on
// stdio: for each behavior the driver writes {"behavior": id} and the runner
// answers {"behavior": id, "status": ...}. A behavior passes only when every
// runner answers "pass". A runner that omits an answer is a silent skip and
// fails the run, so unimplemented, unavailable, and skipped all keep it red.

import { readFileSync } from 'node:fs'
import { spawn } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

const HERE = dirname(fileURLToPath(import.meta.url))
const ROOT = join(HERE, '..')

function fail(message) {
  console.error(`conformance contract error: ${message}`)
  process.exit(2)
}

// Minimal parser for the fixed behaviors.yaml shape (id + status per item),
// kept dependency-free so the harness runs with bare Node.
function parseBehaviors(text) {
  const out = []
  let current = null
  for (const raw of text.split('\n')) {
    const line = raw.replace(/#.*$/, '')
    const id = line.match(/^\s*-\s*id:\s*(\S+)\s*$/)
    if (id) {
      current = { id: id[1], status: 'pending' }
      out.push(current)
      continue
    }
    const status = line.match(/^\s+status:\s*(\S+)\s*$/)
    if (status && current) current.status = status[1]
  }
  return out
}

const behaviors = parseBehaviors(readFileSync(join(ROOT, 'behaviors.yaml'), 'utf8'))
const behaviorIds = behaviors.map((b) => b.id)
if (behaviorIds.length === 0) fail('behaviors.yaml declares no behaviors')

const errors = JSON.parse(readFileSync(join(ROOT, 'errors.json'), 'utf8'))
const securityLevel = JSON.parse(readFileSync(join(ROOT, 'security-level.json'), 'utf8'))
const shapes = JSON.parse(readFileSync(join(ROOT, 'shapes.json'), 'utf8'))
const vectors = JSON.parse(readFileSync(join(ROOT, 'vectors.json'), 'utf8'))

if (!Array.isArray(errors.errors) || errors.errors.length === 0) fail('errors.json has no closed error set')
if (!Array.isArray(securityLevel.securityLevel?.values)) fail('security-level.json has no SecurityLevel values')
if (!('signatureVectors' in vectors)) fail('vectors.json is missing signatureVectors')

// Boundary security check: the vocabulary spec must not be able to name a private key.
const forbidden = /private[_-]?key|secret[_-]?key|export[_-]?key|rawprivate|privatebytes/i
if (forbidden.test(JSON.stringify(shapes))) fail('shapes.json can express a private-key field')

// Four independent implementations of the same stdio protocol.
const runners = [
  { name: 'typescript', cmd: 'node', args: [join(ROOT, 'runners/typescript/runner.mjs')] },
  { name: 'dart', cmd: 'dart', args: ['run', join(ROOT, 'runners/dart/runner.dart')] },
  { name: 'kotlin', cmd: 'kotlin', args: [join(ROOT, 'runners/kotlin/runner.main.kts')] },
  { name: 'swift', cmd: 'swift', args: [join(ROOT, 'runners/swift/runner.swift')] },
]

function driveRunner(runner) {
  return new Promise((resolve) => {
    let child
    try {
      child = spawn(runner.cmd, runner.args, { stdio: ['pipe', 'pipe', 'inherit'] })
    } catch {
      resolve({ name: runner.name, available: false, verdicts: new Map() })
      return
    }
    let out = ''
    let settled = false
    const done = (result) => {
      if (!settled) {
        settled = true
        resolve(result)
      }
    }
    child.on('error', () => done({ name: runner.name, available: false, verdicts: new Map() }))
    child.stdin.on('error', () => {})
    child.stdout.on('data', (chunk) => {
      out += chunk
    })
    child.on('close', () => {
      const verdicts = new Map()
      for (const line of out.split('\n')) {
        const text = line.trim()
        if (!text) continue
        try {
          const parsed = JSON.parse(text)
          if (parsed.behavior) verdicts.set(parsed.behavior, parsed.status ?? 'unknown')
        } catch {
          // ignore non-protocol noise on stdout
        }
      }
      done({ name: runner.name, available: true, verdicts })
    })
    try {
      for (const id of behaviorIds) child.stdin.write(`${JSON.stringify({ behavior: id })}\n`)
      child.stdin.end()
    } catch {
      // stdin closed early; the close or error handler settles the runner
    }
  })
}

const results = await Promise.all(runners.map(driveRunner))

let red = false
const table = []
for (const id of behaviorIds) {
  const cells = results.map((runner) => {
    if (!runner.available) return 'unavailable'
    if (!runner.verdicts.has(id)) return 'SKIPPED'
    return runner.verdicts.get(id)
  })
  if (!cells.every((cell) => cell === 'pass')) red = true
  table.push({ id, cells })
}

console.log(`Signet conformance: ${behaviorIds.length} behaviors x ${runners.length} runners\n`)
for (const runner of results) {
  console.log(`  runner ${runner.name.padEnd(11)} ${runner.available ? 'ran' : 'UNAVAILABLE (toolchain missing)'}`)
}
console.log('')
for (const row of table) {
  const summary = row.cells.map((cell, i) => `${runners[i].name}=${cell}`).join('  ')
  console.log(`  ${row.id.padEnd(38)} ${summary}`)
}
const passed = table.filter((row) => row.cells.every((cell) => cell === 'pass')).length
console.log(`\n${passed}/${behaviorIds.length} behaviors pass across all four runners`)

if (red) {
  console.error('\nconformance RED: unimplemented, unavailable, or skipped behaviors present')
  process.exit(1)
}
console.log('\nconformance GREEN')
