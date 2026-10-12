/**
 * Ed25519 signature verification — must match the backend's
 * services/event_store_v2.py::sign_event() / verify_signature().
 *
 * Spec (per backend):
 *   signature = ed25519.sign(content_hash.encode("ascii"))
 *
 * So we verify against the ASCII bytes of the hex-encoded
 * content_hash string (NOT against the raw digest bytes).
 *
 * @noble/ed25519 v2 separates sync and async paths. We use the
 * async one (`verifyAsync`) so the SHA-512 dependency is provided
 * by the WebCrypto / Node `crypto.subtle` runtime instead of needing
 * a manual hash injection.
 */

import { verifyAsync } from '@noble/ed25519';

export async function verifyEd25519(
  signatureB64: string,
  contentHashHex: string,
  publicKeyB64: string,
): Promise<boolean> {
  const sig = base64ToBytes(signatureB64);
  const pub = base64ToBytes(publicKeyB64);
  const msg = new TextEncoder().encode(contentHashHex);
  try {
    return await verifyAsync(sig, msg, pub);
  } catch {
    return false;
  }
}

function base64ToBytes(s: string): Uint8Array {
  return Uint8Array.from(Buffer.from(s, 'base64'));
}
