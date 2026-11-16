import sodiumLib from 'libsodium-wrappers-sumo';
import { CryptoUnavailableError } from './errors.js';

export type Sodium = typeof sodiumLib;

let instance: Sodium | null = null;

/**
 * Initialise the WASM crypto backend. Must be awaited once before calling any
 * other function in this package. Safe to call repeatedly.
 */
export async function ready(): Promise<void> {
  if (instance) return;
  if (!webAssemblyAvailable()) throw new CryptoUnavailableError('webassembly');
  try {
    await sodiumLib.ready;
  } catch {
    throw new CryptoUnavailableError('failed');
  }
  instance = sodiumLib;
}

/** libsodium 0.8 is WebAssembly-only (no asm.js fallback). */
export function webAssemblyAvailable(): boolean {
  try {
    return typeof WebAssembly === 'object' && typeof WebAssembly.instantiate === 'function';
  } catch {
    return false;
  }
}

/** @internal Synchronous accessor; throws if {@link ready} has not completed. */
export function sodium(): Sodium {
  if (!instance) {
    throw new Error('@opsec-aio/crypto: await ready() before using crypto functions');
  }
  return instance;
}
