/**
 * Merkle inclusion proof verification — dispatches by `tree_algorithm`
 * to match the backend's services/provenance/merkle_anchor.py.
 *
 * Two algorithms are supported on the read path; new bundles always
 * tag rfc6962-v1, legacy bundles default to symphoria-v0.
 *
 *   symphoria-v0  — pad-by-duplicate-last + hex-string concat. Kept
 *                   for batches anchored before the RFC 6962 migration.
 *                   `siblings` carry an explicit { hash, position }.
 *
 *   rfc6962-v1    — RFC 6962 §2.1.1 audit-path verification. Domain-
 *                   separated hashes (0x00 leaf prefix, 0x01 internal
 *                   prefix), raw-byte concat, unbalanced trees. Same
 *                   algorithm as Certificate Transparency, Sigstore
 *                   Rekor, and sigsum. Position is derived from
 *                   (leaf_index, tree_size) per the RFC, NOT from a
 *                   `position` field on each sibling.
 *
 * The backend's `_verify_v0` and `_verify_rfc6962` functions are this
 * file's source of truth; any divergence is a bug.
 */

import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes, concatBytes } from '@noble/hashes/utils';

export const TREE_ALGORITHM_V0 = 'symphoria-v0';
export const TREE_ALGORITHM_RFC6962 = 'rfc6962-v1';

export interface MerkleSibling {
  hash: string;
  /** Only meaningful for `symphoria-v0`. Unused (and absent) for
   *  `rfc6962-v1`, where position is derived from `leaf_index` and
   *  `tree_size`. */
  position?: 'left' | 'right';
}

/** Verify an inclusion proof against the expected root.
 *
 * For `rfc6962-v1` the caller MUST pass `leafIndex` and `treeSize`;
 * passing them is a no-op for v0. We accept them as optional positional
 * params after `siblings` so existing v0 callers keep working.
 *
 * Returns the recomputed root. The caller compares it to the manifest's
 * stored `merkle_root` for pass/fail. */
export function recomputeMerkleRoot(
  leafHash: string,
  siblings: MerkleSibling[],
  treeAlgorithm: string = TREE_ALGORITHM_V0,
  leafIndex?: number,
  treeSize?: number,
): string {
  if (treeAlgorithm === TREE_ALGORITHM_RFC6962) {
    if (typeof leafIndex !== 'number' || typeof treeSize !== 'number') {
      throw new Error('rfc6962-v1 requires leaf_index and tree_size');
    }
    return _verifyRfc6962(leafHash, siblings, leafIndex, treeSize);
  }
  if (treeAlgorithm !== TREE_ALGORITHM_V0) {
    throw new Error(`unknown tree_algorithm: ${treeAlgorithm}`);
  }
  return _verifyV0(leafHash, siblings);
}

function _verifyV0(leafHash: string, siblings: MerkleSibling[]): string {
  let current = leafHash;
  for (const sib of siblings) {
    if (!sib.position) {
      throw new Error('symphoria-v0 sibling missing position field');
    }
    const combined = sib.position === 'left' ? sib.hash + current : current + sib.hash;
    current = bytesToHex(sha256(new TextEncoder().encode(combined)));
  }
  return current;
}

/** RFC 6962 §2.1.1 audit-path verification.
 *
 * `leafHash` is the LEAF HASH (post `SHA-256(0x00 || content_hash_bytes)`),
 * NOT the raw content_hash. The bundle's manifest already pre-computes
 * this so the caller can sanity-check.
 *
 * Positions at each level are derived from (leaf_index, tree_size) via
 * the parity walk in the RFC, identical to the backend's
 * `_verify_rfc6962` function.
 */
function _verifyRfc6962(
  leafHashHex: string,
  siblings: MerkleSibling[],
  leafIndex: number,
  treeSize: number,
): string {
  if (leafIndex < 0 || treeSize <= 0 || leafIndex >= treeSize) {
    throw new Error('rfc6962-v1: leaf_index out of bounds');
  }
  let fn = leafIndex;
  let sn = treeSize - 1;
  let r = hexToBytes(leafHashHex);
  if (r.length !== 32) {
    throw new Error(`rfc6962-v1: leaf_hash must be 32 bytes (got ${r.length})`);
  }
  for (const sib of siblings) {
    const p = hexToBytes(sib.hash);
    if (p.length !== 32) {
      throw new Error('rfc6962-v1: sibling hash must be 32 bytes');
    }
    if (sn === 0) {
      throw new Error('rfc6962-v1: ran out of tree before audit path consumed');
    }
    if ((fn & 1) === 1 || fn === sn) {
      r = sha256(concatBytes(new Uint8Array([0x01]), p, r));
      while ((fn & 1) === 0) {
        fn >>= 1;
        sn >>= 1;
      }
    } else {
      r = sha256(concatBytes(new Uint8Array([0x01]), r, p));
    }
    fn >>= 1;
    sn >>= 1;
  }
  if (sn !== 0) {
    throw new Error('rfc6962-v1: audit path too short for tree size');
  }
  return bytesToHex(r);
}

/** RFC 6962 §2.1 leaf hash: SHA-256(0x00 || content_hash_bytes).
 *  Exposed for callers who want to derive the leaf_hash from a raw
 *  content_hash before feeding into recomputeMerkleRoot. */
export function rfc6962LeafHash(contentHashHex: string): string {
  const data = hexToBytes(contentHashHex);
  return bytesToHex(sha256(concatBytes(new Uint8Array([0x00]), data)));
}
