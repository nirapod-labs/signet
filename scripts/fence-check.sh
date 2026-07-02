#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Nirapod Labs
#
# Static non-custodial fence. Asserts the invariants that must hold at every
# commit, independent of the test suites. This is the initial stub; the checks
# below are added as the cores and bindings land.
set -euo pipefail

echo "fence-check: stub. Will assert, statically:"
echo "  - no private-key export symbol in any core or binding surface"
echo "  - no key-material type crosses a binding boundary"
exit 1
