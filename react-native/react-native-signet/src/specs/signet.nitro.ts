import type { HybridObject } from 'react-native-nitro-modules'

/**
 * Hardware-backed P-256 signing surface exposed to React Native through Nitro.
 *
 * Scaffold: `getVersion` is the only method until the signing API lands; no key
 * material or export path is declared here.
 */
export interface Signet extends HybridObject<{ ios: 'swift', android: 'kotlin' }> {
  /** Returns the Signet library version. */
  getVersion(): string
}
