#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Nirapod Labs
#
# Static non-custodial fence. Asserts, at every commit and independent of the
# test suites, that no core or binding surface exposes a private-key export path
# and that the conformance vocabulary cannot name key material.
set -euo pipefail
cd "$(dirname "$0")/.."

fail=0

# The conformance driver's own guard regex NAMES the forbidden terms in order to
# reject them; it is the single allowed mention.
hits=$(git ls-files -z \
  | xargs -0 grep -InE 'exportKey|getPrivateKey|extractable|rawPrivate|privateBytes|secretKey' 2>/dev/null \
  | grep -vE 'conformance/harness/driver\.mjs|scripts/fence-check\.sh' || true)
if [ -n "$hits" ]; then
  echo "fence: key-export surface found:"
  echo "$hits"
  fail=1
fi

if grep -InE 'privateKey|private_key|secretKey' \
  conformance/shapes.json conformance/security-level.json >/dev/null 2>&1; then
  echo "fence: conformance vocabulary names a private key"
  fail=1
fi

if [ "$fail" -ne 0 ]; then
  echo "fence-check failed"
  exit 1
fi
echo "fence-check passed: no key-export surface, no key-material field in the contract"
