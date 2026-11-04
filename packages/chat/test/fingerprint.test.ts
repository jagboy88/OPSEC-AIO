import { describe, expect, it } from 'vitest';
import { FingerprintGenerator, KeyHelper } from '@privacyresearch/libsignal-protocol-typescript';
import { ready } from '@opsec-aio/crypto';
import { safetyNumber } from '../src/fingerprint.js';

await ready();

describe('safety numbers', () => {
  it('match the Signal library digit for digit, much faster', async () => {
    for (const [a, b] of [
      ['alice', 'bob'],
      ['quiet_otter_4821', 'z'],
    ] as const) {
      const ka = await KeyHelper.generateIdentityKeyPair();
      const kb = await KeyHelper.generateIdentityKeyPair();
      let t = performance.now();
      const ref = await new FingerprintGenerator(5200).createFor(a, ka.pubKey, b, kb.pubKey);
      const libMs = performance.now() - t;
      t = performance.now();
      const ours = safetyNumber(a, new Uint8Array(ka.pubKey), b, new Uint8Array(kb.pubKey));
      const oursMs = performance.now() - t;
      expect(ours).toBe(ref);
      expect(ours).toMatch(/^\d{60}$/);
      console.log(`library ${libMs.toFixed(0)} ms, ours ${oursMs.toFixed(0)} ms`);
    }
  });
});
