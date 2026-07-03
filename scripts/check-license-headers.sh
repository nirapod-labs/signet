#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Nirapod Labs

# Fail if any first-party source file lacks an SPDX license header. Build
# manifests (Package.swift, package.json, pubspec, podspec) carry their license
# through their own metadata and are skipped here.
set -euo pipefail
cd "$(dirname "$0")/.."

missing=0
while IFS= read -r f; do
  case "$f" in */Package.swift) continue ;; esac
  head -5 "$f" 2>/dev/null | grep -q 'SPDX-License-Identifier' || { echo "missing SPDX header: $f"; missing=1; }
done < <(git ls-files \
  'apple/Sources/**/*.swift' 'apple/Tests/**/*.swift' \
  'android/src/**/*.kt' \
  'kmp/signet/src/**/*.kt' \
  'conformance/harness/**/*.mjs' 'conformance/runners/**' \
  'react-native/react-native-signet/src/**/*.ts' \
  'react-native/react-native-signet/apple/**/*.swift' 'react-native/react-native-signet/apple/**/*.h' \
  'react-native/react-native-signet/android/src/main/**/*.kt' \
  'flutter/signet/lib/**/*.dart' \
  'flutter/signet/android/src/**/*.kt' \
  'flutter/signet/darwin/**/*.swift')

if [ "$missing" -ne 0 ]; then
  echo "license-header check failed"
  exit 1
fi
echo "license headers present on all first-party source"
