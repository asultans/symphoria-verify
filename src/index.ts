/**
 * Programmatic API entry point. Use this in tests, custom wrappers,
 * or other Node tools that need to verify a Symphoria bundle without
 * shelling out to the CLI.
 */
export { verifyBundle, type VerifyOptions, type VerificationReport, type EventVerificationResult } from './verify.js';
export { canonicalize } from './canonical.js';
export {
  recomputeMerkleRoot,
  rfc6962LeafHash,
  TREE_ALGORITHM_V0,
  TREE_ALGORITHM_RFC6962,
} from './merkle.js';
export { verifyEd25519 } from './signature.js';
export type { Manifest, ManifestEvent, ManifestSigningKey } from './manifest.js';
