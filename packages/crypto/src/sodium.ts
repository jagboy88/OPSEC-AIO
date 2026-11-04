import sodiumLib from 'libsodium-wrappers-sumo';

export type Sodium = typeof sodiumLib;

let instance: Sodium | null = null;

/**
 * Initialise the WASM crypto backend. Must be awaited once before calling any
 * other function in this package. Safe to call repeatedly.
 */
export async function ready(): Promise<void> {
  if (instance) return;
  await sodiumLib.ready;
  instance = sodiumLib;
}

/** @internal Synchronous accessor; throws if {@link ready} has not completed. */
export function sodium(): Sodium {
  if (!instance) {
    throw new Error('@opsec-aio/crypto: await ready() before using crypto functions');
  }
  return instance;
}
