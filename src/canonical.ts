/**
 * Canonical JSON encoding — must match the backend's
 * services/event_store_v2.py::canonicalize() exactly.
 *
 * Spec:
 *   - sorted object keys
 *   - UTF-8, no BOM
 *   - no whitespace
 *   - NaN / Infinity rejected
 *
 * Mismatch here is the most common failure mode for content_hash
 * recomputation: any unicode escape difference, key ordering bug, or
 * float formatting drift will produce a different hash and fail
 * verification of every event in the bundle. Keep this in lockstep
 * with the Python side.
 */

export function canonicalize(value: unknown): Buffer {
  return Buffer.from(stringify(value), 'utf-8');
}

function stringify(value: unknown): string {
  if (value === null) return 'null';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      throw new Error('canonicalize: NaN/Infinity not allowed');
    }
    // Match Python's default JSON int/float formatting. Integers must
    // serialize without a decimal point ("123", not "123.0"); floats
    // use the shortest round-trip representation. We trust the
    // export side to set ts_ms to an integer.
    return Number.isInteger(value) ? String(value) : JSON.stringify(value);
  }
  if (typeof value === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) {
    return '[' + value.map(stringify).join(',') + ']';
  }
  if (typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).sort();
    const parts = keys.map(k => JSON.stringify(k) + ':' + stringify(obj[k]));
    return '{' + parts.join(',') + '}';
  }
  throw new Error(`canonicalize: unsupported value type ${typeof value}`);
}
