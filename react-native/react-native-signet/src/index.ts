// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

import { NitroModules } from 'react-native-nitro-modules'
import type { Signet as SignetSpec } from './specs/signet.nitro'

/**
 * Signet hybrid object: hardware-backed P-256 signing keys via the native cores.
 */
export const Signet = NitroModules.createHybridObject<SignetSpec>('Signet')
