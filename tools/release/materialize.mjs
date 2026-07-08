// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

// Dry-run release materialization for Signet.
//
// Reads the canonical VERSION, checks that every publishable package declares a
// matching base version, and emits a checksum manifest. It never publishes; it is
// the version-consistency and reproducibility anchor the real release runs against.

import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..')
const read = (relative) => readFileSync(join(ROOT, relative), 'utf8')
const digest = (text) => createHash('sha256').update(text).digest('hex').slice(0, 16)

const versionFile = read('VERSION').trim()
const base = versionFile.replace(/-.*$/, '')

const packages = [
  {
    name: 'react-native-signet',
    ecosystem: 'npm',
    file: 'react-native/react-native-signet/package.json',
    declared: (text) => JSON.parse(text).version,
  },
  {
    name: 'signet',
    ecosystem: 'pub',
    file: 'flutter/signet/pubspec.yaml',
    declared: (text) => (text.match(/^version:\s*(\S+)/m) || [])[1],
  },
  {
    name: 'org.nirapod:signet',
    ecosystem: 'maven',
    file: 'kmp/signet/build.gradle.kts',
    declared: (text) => (text.match(/^version\s*=\s*"([^"]+)"/m) || [])[1],
  },
]

let drift = false
const materialized = packages.map((pkg) => {
  const text = read(pkg.file)
  const declared = pkg.declared(text)
  const matchesBase = typeof declared === 'string' && declared.replace(/-.*$/, '') === base
  if (!matchesBase) drift = true
  return {
    package: pkg.name,
    ecosystem: pkg.ecosystem,
    declared,
    matchesBase,
    sha256: digest(text),
  }
})

console.log(
  JSON.stringify({ version: versionFile, base, dryRun: true, packages: materialized }, null, 2),
)

if (drift) {
  console.error(`\nrelease: version drift against VERSION base ${base}`)
  process.exit(1)
}
console.log(`\nrelease: all packages match base ${base} (dry-run, nothing published)`)
