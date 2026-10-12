/**
 * Top-level verification orchestration: open bundle, walk the
 * manifest, run all four checks, accumulate per-event results.
 *
 * Each check fails INDEPENDENTLY — a hash mismatch on one event
 * doesn't short-circuit the rest. Final report tells the user
 * exactly which events passed and which failed which check, so
 * they can act on partial damage (e.g., one corrupted event vs.
 * a wholesale tamper).
 */

import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';
import { canonicalize } from './canonical.js';
import {
  Manifest,
  ManifestEvent,
  assertManifestShape,
} from './manifest.js';
import { recomputeMerkleRoot, rfc6962LeafHash } from './merkle.js';
import { verifyEd25519 } from './signature.js';
import { BundleHandle, openBundle, readJson } from './zip.js';

export type CheckStatus = 'pass' | 'fail' | 'skip' | 'pending';

export interface EventVerificationResult {
  stream: string;
  seq: number;
  type: string;
  content_hash: string;
  hash_check: CheckStatus;
  signature_check: CheckStatus;
  merkle_check: CheckStatus;
  bitcoin_check: CheckStatus;
  /** prev_hash → previous-event content_hash linkage check, per stream.
   *  Bundles include only durable+critical events under the durables-
   *  only chain semantics; verifying this link end-to-end catches a
   *  re-ordering attack where individual content_hashes are recomputed
   *  on rewritten prev_hashes. The other four checks pass independently
   *  on a swap; this one fails. */
  chain_check: CheckStatus;
  failures: string[];
}

export interface VerificationReport {
  ok: boolean;
  bundle_path: string;
  format_version: string;
  investigation_id: string;
  events_total: number;
  events_passed: number;
  events_failed: number;
  events_pending: number;  // OTS not yet anchored / mempool
  results: EventVerificationResult[];
  warnings: string[];
  /** Mirror of manifest.anchoring — surfaces project-level intent +
   *  per-status counts so the CLI can render distinct messages for
   *  "anchoring is OFF" vs "anchoring is ON but a batch hasn't been
   *  built yet". */
  anchoring?: {
    active: boolean;
    reasons: string[];
    summary: { confirmed: number; pending: number; queued: number; not_anchored: number };
    next_steps: string;
  };
}

export interface VerifyOptions {
  /** Skip the OpenTimestamps→Bitcoin step. The other three checks
   *  run identically. Useful in air-gapped environments or when
   *  the user wants to confirm only that hashes/signatures match
   *  without reaching out to a Bitcoin node. */
  skipBitcoin?: boolean;
  /** Optional override for an OpenTimestamps Bitcoin RPC. When unset
   *  the OTS library uses public Esplora endpoints. */
  bitcoinRpcUrl?: string;
}

export async function verifyBundle(
  bundlePath: string,
  opts: VerifyOptions = {},
): Promise<VerificationReport> {
  const bundle = await openBundle(bundlePath);
  const manifest = readJson<unknown>(bundle, 'manifest.json');
  assertManifestShape(manifest);

  const warnings: string[] = [];
  const results: EventVerificationResult[] = [];

  // Format-version check. We support format_version "1.x" today; a
  // newer manifest may carry fields we don't understand and would
  // verify as "missing" or worse. Fail loudly so the user knows to
  // upgrade their verifier rather than silently mis-report.
  const SUPPORTED_MAJOR = 1;
  const [majorStr] = manifest.format_version.split('.');
  const manifestMajor = parseInt(majorStr, 10);
  if (Number.isNaN(manifestMajor) || manifestMajor > SUPPORTED_MAJOR) {
    throw new Error(
      `bundle uses format_version=${manifest.format_version}; this verifier supports up to ${SUPPORTED_MAJOR}.x. ` +
      `Run \`npm install -g @symphoria/verify@latest\` to upgrade.`,
    );
  }
  if (manifestMajor < SUPPORTED_MAJOR) {
    warnings.push(
      `bundle is format_version=${manifest.format_version}; verifier supports forward through ${SUPPORTED_MAJOR}.x — proceeding.`,
    );
  }

  // Build a key lookup. For now, single key under "current"; key
  // rotation lands later — see manifest.signing_keys for the schema.
  const keysById = new Map<string, string>();
  for (const k of manifest.signing_keys) {
    keysById.set(k.key_id, k.public_key_b64);
  }

  // Cache OTS verification per merkle_root so we don't re-verify the
  // same root once per leaf when many events share a batch.
  const otsCache = new Map<string, CheckStatus>();

  // Sequence-gap detection: per stream, the manifest's events MUST be
  // contiguous in the durable subset. Sparse seqs (e.g. 1, 2, 79, 80)
  // are normal because the bundle archives only durable+critical events
  // and ephemerals between them are intentionally dropped — so the
  // gap warning fires on legitimate exports. We surface the
  // observation but rely on `chain_check` (below) for the actual
  // tamper-evidence: prev_hash linkage skips ephemerals by design.
  const lastSeqByStream = new Map<string, number>();
  // prev_hash → previous-event content_hash chain, per stream. Tracks
  // the LAST durable+critical event's content_hash; the next event in
  // the same stream must carry that as its prev_hash. Initial value
  // is `null` (chain head sentinel) — matches the seq=1 emit invariant
  // in the backend.
  const prevHashByStream = new Map<string, string | null>();

  // Read each event's prev_hash from disk for the chain check below.
  // The manifest entry doesn't carry prev_hash (it would explode the
  // manifest size); we pull it from the event JSON file.
  const readPrevHash = (eventFile: string): string | null => {
    try {
      const buf = bundle.get(eventFile);
      if (!buf) return null;
      const parsed = JSON.parse(buf.toString('utf-8')) as Record<string, unknown>;
      const ph = parsed.prev_hash;
      if (ph === null || ph === undefined) return null;
      if (typeof ph === 'string') return ph;
      return null;
    } catch {
      return null;
    }
  };

  for (const e of manifest.events) {
    const failures: string[] = [];

    // Sequence gap?
    const last = lastSeqByStream.get(e.stream);
    if (last !== undefined && e.seq !== last + 1) {
      warnings.push(
        `sequence gap on ${e.stream}: ${last} → ${e.seq} ` +
        `(expected for durables-only bundles; verified via chain_check)`
      );
    }
    lastSeqByStream.set(e.stream, e.seq);

    // 0. prev_hash → previous-event chain link (per stream). Catches
    // re-ordering / event-swap attacks that recompute individual
    // content_hashes but can't preserve the in-stream link to the
    // previous event. Chain-broken events are reported but don't
    // short-circuit the other checks — the report shows exactly
    // which link broke.
    //
    // Per the backend spec, ONLY durable + critical events advance
    // the per-stream prev_hash head. Ephemeral events (presence,
    // typing, text-patch streams, etc.) record the contemporaneous
    // head as their `prev_hash` for ordering but don't update it —
    // so the next event's `prev_hash` still points at the prior
    // durable/critical event, NOT at the ephemeral one. The verifier
    // mirrors that asymmetry: read prev_hash from every event, but
    // only advance the head on durable+critical.
    const observedPrev = readPrevHash(e.file);
    const expectedPrev = prevHashByStream.has(e.stream)
      ? prevHashByStream.get(e.stream) ?? null
      : null; // first event in this stream — must be `prev_hash=null`
    let chainCheck: CheckStatus = 'fail';
    if (observedPrev === expectedPrev) {
      chainCheck = 'pass';
    } else {
      failures.push(
        `chain link broken on ${e.stream} seq=${e.seq}: ` +
        `prev_hash=${observedPrev ?? 'null'} expected ${expectedPrev ?? 'null'}`
      );
    }
    // Default `durability` to "durable" when missing (older bundles
    // pre-dating the manifest field) — matches the legacy verifier
    // semantics so old bundles don't regress.
    const isEphemeral = e.durability === 'ephemeral';
    if (!isEphemeral) {
      prevHashByStream.set(e.stream, e.content_hash);
    }

    // 1. content_hash recomputation
    let hashCheck: CheckStatus = 'fail';
    try {
      const eventBuf = bundle.get(e.file);
      if (!eventBuf) throw new Error(`event file missing: ${e.file}`);
      const eventJson = JSON.parse(eventBuf.toString('utf-8')) as Record<string, unknown>;
      const computed = recomputeContentHash(eventJson);
      if (computed === e.content_hash) {
        hashCheck = 'pass';
      } else {
        failures.push(`content_hash mismatch: expected ${e.content_hash} got ${computed}`);
      }
    } catch (err) {
      failures.push(`hash recompute error: ${(err as Error).message}`);
    }

    // 2. Ed25519 signature
    let sigCheck: CheckStatus = 'skip';
    if (e.signature) {
      // Resolve key: prefer signing_key_id, fall back to "current".
      const keyId = e.signing_key_id ?? 'current';
      const pub = keysById.get(keyId) ?? keysById.get('current');
      if (!pub) {
        sigCheck = 'fail';
        failures.push(`no public key found for signing_key_id="${keyId}"`);
      } else {
        const ok = await verifyEd25519(e.signature, e.content_hash, pub);
        sigCheck = ok ? 'pass' : 'fail';
        if (!ok) failures.push('ed25519 signature does not verify');
      }
    }

    // 3. Merkle path
    //
    // Algorithm dispatch: legacy bundles default to `symphoria-v0`
    // (pad-by-duplicate, hex-string concat). New bundles tag
    // `rfc6962-v1`, which uses RFC 6962 §2.1.1 audit-path verification
    // with domain-separated hashes (0x00 leaf, 0x01 internal). The
    // RFC 6962 path requires `leaf_index` + `tree_size` from the
    // manifest; if either is missing on a v1-tagged event we fail
    // loudly rather than silently falling back to v0.
    let merkleCheck: CheckStatus = 'skip';
    if (e.merkle_root && e.merkle_siblings) {
      const algo = e.tree_algorithm || 'symphoria-v0';
      try {
        let leafForProof: string;
        if (algo === 'rfc6962-v1') {
          // RFC 6962 leaves are SHA-256(0x00 || content_hash). Use the
          // pre-computed `leaf_hash` from the manifest when present;
          // otherwise derive it from content_hash so older manifests
          // that pre-date the field still verify.
          leafForProof = e.leaf_hash ?? rfc6962LeafHash(e.content_hash);
        } else {
          leafForProof = e.content_hash;
        }
        const computed = recomputeMerkleRoot(
          leafForProof,
          e.merkle_siblings,
          algo,
          e.leaf_index,
          e.tree_size,
        );
        if (computed === e.merkle_root) {
          merkleCheck = 'pass';
        } else {
          merkleCheck = 'fail';
          failures.push(`merkle root mismatch (${algo}): computed ${computed} expected ${e.merkle_root}`);
        }
      } catch (err) {
        merkleCheck = 'fail';
        failures.push(`merkle verify error (${algo}): ${(err as Error).message}`);
      }
    }

    // 4. OpenTimestamps → Bitcoin. The bitcoin_status field on the
    // manifest entry tells us upfront where this event is in the
    // pipeline — confirmed / pending / queued / not_anchored. We
    // only run the OTS verification when an .ots file is present
    // AND the manifest claims at least pending status; a "queued"
    // event has no .ots file yet (no Merkle batch has been built),
    // so there's nothing to verify.
    if (e.bitcoin_status === 'queued') {
      // Distinct from "skip" so the report can say "still queued
      // for batching" instead of leaving the user wondering.
      results.push({
        stream: e.stream,
        seq: e.seq,
        type: e.type,
        content_hash: e.content_hash,
        hash_check: hashCheck,
        signature_check: sigCheck,
        merkle_check: 'skip',
        bitcoin_check: 'pending',
        chain_check: chainCheck,
        failures,
      });
      continue;
    }

    let btcCheck: CheckStatus = 'skip';
    if (e.merkle_root && e.ots_proof_file && !opts.skipBitcoin) {
      if (otsCache.has(e.merkle_root)) {
        btcCheck = otsCache.get(e.merkle_root)!;
      } else {
        // Defer to a separate OTS module so the import is lazy and
        // failures (e.g., no network) don't crash hash/signature
        // verification for users in air-gapped environments.
        const { verifyOtsAgainstBitcoin } = await import('./ots.js');
        try {
          const otsBytes = bundle.get(e.ots_proof_file);
          if (!otsBytes) {
            btcCheck = 'fail';
            failures.push(`ots file missing: ${e.ots_proof_file}`);
          } else {
            btcCheck = await verifyOtsAgainstBitcoin(otsBytes, e.merkle_root, opts);
          }
        } catch (err) {
          btcCheck = 'fail';
          failures.push(`OTS verification error: ${(err as Error).message}`);
        }
        otsCache.set(e.merkle_root, btcCheck);
      }
    } else if (e.merkle_root && opts.skipBitcoin) {
      btcCheck = 'skip';
    }

    results.push({
      stream: e.stream,
      seq: e.seq,
      type: e.type,
      content_hash: e.content_hash,
      hash_check: hashCheck,
      signature_check: sigCheck,
      merkle_check: merkleCheck,
      bitcoin_check: btcCheck,
      chain_check: chainCheck,
      failures,
    });
  }

  const eventsFailed = results.filter(r => r.failures.length > 0).length;
  const eventsPassed = results.filter(r =>
    r.hash_check === 'pass'
    && (r.signature_check === 'pass' || r.signature_check === 'skip')
    && (r.merkle_check === 'pass' || r.merkle_check === 'skip')
    && (r.bitcoin_check === 'pass' || r.bitcoin_check === 'skip')
  ).length;
  const eventsPending = results.filter(r => r.bitcoin_check === 'pending').length;

  return {
    ok: eventsFailed === 0,
    bundle_path: bundlePath,
    format_version: manifest.format_version,
    investigation_id: manifest.investigation.id,
    events_total: results.length,
    events_passed: eventsPassed,
    events_failed: eventsFailed,
    events_pending: eventsPending,
    results,
    warnings,
    anchoring: manifest.anchoring,
  };
}

function recomputeContentHash(eventJson: Record<string, unknown>): string {
  // Match Python's _hash_fields: exclude id, content_hash, signature.
  const material: Record<string, unknown> = {
    stream: eventJson.stream,
    seq: eventJson.seq,
    ts_ms: eventJson.ts_ms,
    actor: eventJson.actor,
    type: eventJson.type,
    durability: eventJson.durability,
    payload: eventJson.payload,
    causes: eventJson.causes ?? [],
    prev_hash: eventJson.prev_hash ?? null,
    schema_version: eventJson.schema_version ?? 1,
  };
  return bytesToHex(sha256(canonicalize(material)));
}
