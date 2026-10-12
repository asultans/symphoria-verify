/**
 * Manifest schema — TypeScript types matching what the backend's
 * ProjectExportService writes to manifest.json.
 *
 * Adding a new field on the backend with a default value is safe —
 * older verifiers will ignore it. Adding a REQUIRED field is a
 * format-version bump.
 */

export interface ManifestEvent {
  stream: string;
  seq: number;
  ts_ms: number;
  type: string;
  content_hash: string;
  signature: string | null;
  signing_key_id: string | null;
  /** ZIP-relative path to the canonical event JSON. */
  file: string;
  /** Drives the chain-link verifier: ephemeral events do NOT advance
   *  the per-stream prev_hash head (they record the contemporaneous
   *  head as their `prev_hash` for ordering, but don't update it).
   *  Older bundles (pre-2026-05-02) lack this field; the verifier
   *  falls back to "treat absent as durable" for compat. */
  durability?: 'ephemeral' | 'durable' | 'critical';
  /** Anchored events only. */
  merkle_root?: string;
  /** For `symphoria-v0` siblings carry an explicit position; for
   *  `rfc6962-v1` position is derivable from `leaf_index`/`tree_size`
   *  and is omitted on the wire. */
  merkle_siblings?: Array<{ hash: string; position?: 'left' | 'right' }>;
  ots_proof_file?: string;
  bitcoin_status?: 'confirmed' | 'pending' | 'queued' | 'failed' | 'not_anchored';
  /** Default `symphoria-v0` for legacy bundles; new bundles always
   *  emit `rfc6962-v1`. Drives the verifier's algorithm dispatch. */
  tree_algorithm?: string;
  /** Required for `rfc6962-v1` audit-path verification. Position in
   *  the (possibly-unbalanced) Merkle tree. */
  leaf_index?: number;
  /** Required for `rfc6962-v1`. Total leaves at the time of batch
   *  build; binds (root, size) so a verifier can detect the
   *  CVE-2012-2459-class root collision under v0-style padding. */
  tree_size?: number;
  /** Optional pre-computed `SHA-256(0x00 || content_hash_bytes)`. The
   *  verifier can derive this itself but exposing it lets the manifest
   *  cross-check the leaf-hash transform. */
  leaf_hash?: string;
}

export interface ManifestSigningKey {
  key_id: string;
  algorithm: 'ed25519';
  public_key_b64: string;
  valid_from: string | null;
  valid_to: string | null;
  note?: string;
}

export interface ManifestBatch {
  root: string;
  ots_proof_file: string;
  bitcoin_status?: 'confirmed' | 'pending' | 'failed';
}

export interface ManifestAnchoring {
  active: boolean;
  reasons: string[];
  summary: {
    confirmed: number;
    pending: number;
    queued: number;
    not_anchored: number;
  };
  next_steps: string;
}

export interface Manifest {
  format_version: string;
  exported_at: string;
  exported_by: string;
  investigation: {
    id: string;
    name: string | null;
    description: string | null;
    owner_id: string | null;
    created_at: string;
  };
  anchoring?: ManifestAnchoring;
  streams: string[];
  threads: Array<{ id: string; title: string | null; created_at: string }>;
  events_count: number;
  anchored_count: number;
  events: ManifestEvent[];
  merkle_batches: ManifestBatch[];
  signing_keys: ManifestSigningKey[];
  verifier?: {
    npm_package?: string;
    command?: string;
    manual_steps?: string;
  };
}

export function assertManifestShape(m: unknown): asserts m is Manifest {
  if (!m || typeof m !== 'object') throw new Error('manifest: not an object');
  const r = m as Record<string, unknown>;
  if (typeof r.format_version !== 'string') throw new Error('manifest: missing format_version');
  if (!Array.isArray(r.events)) throw new Error('manifest: events must be an array');
  if (!Array.isArray(r.signing_keys)) throw new Error('manifest: signing_keys must be an array');
}
