/**
 * OpenTimestamps → Bitcoin verification.
 *
 * Strategy: defer to the official `javascript-opentimestamps`
 * package. It owns the upgrade path for proof formats and Bitcoin
 * RPC/Esplora wiring; we just feed it the .ots bytes and the
 * expected digest (merkle_root) and report pass / fail / pending.
 *
 * "pending" = the proof references a Bitcoin transaction that
 * hasn't been confirmed yet (e.g., events anchored within the last
 * few hours). This is normal and not a verification failure.
 */

import type { CheckStatus } from './verify.js';

export interface OtsVerifyOpts {
  bitcoinRpcUrl?: string;
}

export async function verifyOtsAgainstBitcoin(
  otsBytes: Buffer,
  expectedDigestHex: string,
  _opts: OtsVerifyOpts = {},
): Promise<CheckStatus> {
  // Lazy require to keep cold-start light when --skip-bitcoin is used.
  // javascript-opentimestamps is CommonJS; dynamic import works in
  // ESM via the interop layer.
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const ots: any = (await import('javascript-opentimestamps')).default
    ?? (await import('javascript-opentimestamps'));

  const detached = ots.DetachedTimestampFile.deserialize(otsBytes);

  // Sanity: the digest the proof commits to must match our expected
  // Merkle root. Otherwise the .ots file is for a different batch.
  // The library's API has shifted across versions: older releases
  // exposed `fileHash()`, current releases use `fileDigest()`. Try
  // both so we work across pinned npm versions in the wild.
  const fileDigestFn = (detached.fileDigest ?? detached.fileHash);
  if (typeof fileDigestFn !== 'function') {
    throw new Error(
      'javascript-opentimestamps: neither fileDigest nor fileHash is a function on DetachedTimestampFile',
    );
  }
  const proofDigest: Uint8Array = fileDigestFn.call(detached);
  const proofDigestHex = bufToHex(proofDigest);
  if (proofDigestHex !== expectedDigestHex) {
    return 'fail';
  }

  try {
    const result = await ots.verify(detached);
    if (!result || Object.keys(result).length === 0) {
      // Library returned no attestations — most commonly: still in
      // the OpenTimestamps calendar's mempool, not yet confirmed in
      // a Bitcoin block.
      return 'pending';
    }
    // result is an object keyed by chain (e.g., {bitcoin: {timestamp}})
    if (result.bitcoin) return 'pass';
    return 'pending';
  } catch (err) {
    const msg = String((err as Error).message ?? err);
    if (/pending|incomplete|unknown\s*attest/i.test(msg)) {
      return 'pending';
    }
    throw err;
  }
}

function bufToHex(b: Uint8Array): string {
  return Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('');
}
