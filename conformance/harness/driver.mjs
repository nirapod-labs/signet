// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

// Signet polyglot conformance driver.
//
// Loads the contract in conformance/ (the single source of truth), then drives
// four independent language runners over a line-delimited JSON protocol on
// stdio: for each behavior the driver writes {"behavior": id} and the runner
// answers {"behavior": id, "status": ...}.
//
// Each behavior carries an expected disposition in behaviors.yaml. A `pending`
// behavior requires every available runner to answer "unimplemented"; a silent
// answer (skip) or an early "pass" is a mismatch and turns the run red. A
// `verified` behavior requires every runner to be present and answer "pass".
// Missing toolchains are tolerated only while a behavior is pending. The run is
// green when every behavior matches its declared disposition.

import { spawn } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const HERE = dirname(fileURLToPath(import.meta.url))
const ROOT = join(HERE, '..')

// A behavior that must pass on every runner vs. one not yet required to run.
const MUST_PASS = new Set(['verified', 'active', 'required'])
const NOT_YET = new Set(['pending'])

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
for (const b of behaviors) {
  if (!MUST_PASS.has(b.status) && !NOT_YET.has(b.status))
    fail(`behavior ${b.id} has unknown status "${b.status}"`)
}

const errors = JSON.parse(readFileSync(join(ROOT, 'errors.json'), 'utf8'))
const securityLevel = JSON.parse(readFileSync(join(ROOT, 'security-level.json'), 'utf8'))
const shapes = JSON.parse(readFileSync(join(ROOT, 'shapes.json'), 'utf8'))
const vectors = JSON.parse(readFileSync(join(ROOT, 'vectors.json'), 'utf8'))

if (!Array.isArray(errors.errors) || errors.errors.length === 0)
  fail('errors.json has no closed error set')
if (!Array.isArray(securityLevel.securityLevel?.values))
  fail('security-level.json has no SecurityLevel values')
if (!('signatureVectors' in vectors)) fail('vectors.json is missing signatureVectors')

// Boundary security check: the vocabulary spec must not be able to name a private key.
const forbidden = /private[_-]?key|secret[_-]?key|export[_-]?key|rawprivate|privatebytes/i
if (forbidden.test(JSON.stringify(shapes))) fail('shapes.json can express a private-key field')

// Hardware-only regression guard: the contract admits no software or tpm tier,
// no retired evidence value, and no retired tier-floor vocabulary (bestEffort
// policy, meetsFloor field).
const removedLevels = new Set(['tpm', 'software'])
for (const value of securityLevel.securityLevel?.values ?? [])
  if (removedLevels.has(value)) fail(`security-level.json names removed tier "${value}"`)
const removedEvidence = new Set(['attested', 'inferred', 'selfReportUnverified'])
for (const value of securityLevel.tierEvidence?.values ?? [])
  if (removedEvidence.has(value)) fail(`security-level.json names removed evidence "${value}"`)
if (shapes.SecurityTierReport && 'meetsFloor' in shapes.SecurityTierReport)
  fail('shapes.json still carries the removed meetsFloor field')
if (shapes.TierPolicy?.variants && 'bestEffort' in shapes.TierPolicy.variants)
  fail('shapes.json still carries the removed bestEffort policy')

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

function cellFor(runner, id) {
  if (!runner.available) return 'unavailable'
  if (!runner.verdicts.has(id)) return 'SKIPPED'
  return runner.verdicts.get(id)
}

let red = false
const table = []
for (const b of behaviors) {
  const cells = results.map((runner) => cellFor(runner, b.id))
  let ok
  let note = ''
  if (MUST_PASS.has(b.status)) {
    // Required: every runner must be present and pass.
    ok = cells.every((cell) => cell === 'pass')
    if (!ok) note = 'verified behavior must pass on every runner'
  } else {
    // Pending: available runners must explicitly report "unimplemented".
    // A missing toolchain is tolerated only while the behavior is pending.
    ok = cells.every((cell, i) => !results[i].available || cell === 'unimplemented')
    if (!ok) note = 'pending: available runners must report "unimplemented"'
  }
  if (!ok) red = true
  table.push({ id: b.id, status: b.status, cells, ok, note })
}

console.log(`Signet conformance: ${behaviorIds.length} behaviors x ${runners.length} runners\n`)
for (const runner of results) {
  console.log(
    `  runner ${runner.name.padEnd(11)} ${runner.available ? 'ran' : 'UNAVAILABLE (toolchain missing)'}`,
  )
}
console.log('')
for (const row of table) {
  const summary = row.cells.map((cell, i) => `${runners[i].name}=${cell}`).join('  ')
  const mark = row.ok ? 'ok ' : 'RED'
  console.log(`  ${mark} ${row.id.padEnd(38)} [${row.status}]  ${summary}`)
  if (!row.ok) console.log(`      ${row.note}`)
}
const met = table.filter((row) => row.ok).length
console.log(`\n${met}/${behaviors.length} behaviors meet their declared expectation`)

if (red) {
  console.error('\nconformance RED: a behavior does not match its declared expectation')
  process.exit(1)
}
console.log('\nconformance GREEN')
