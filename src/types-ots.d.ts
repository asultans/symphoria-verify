/**
 * Type shim for the javascript-opentimestamps package, which doesn't
 * ship its own .d.ts. We declare only the surface we use; everything
 * else is `any` and the runtime is fully exercised in tests.
 */
declare module 'javascript-opentimestamps' {
  // Default + named exports — the CommonJS shape varies between
  // versions, so we expose `any` and let runtime resolution handle it.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const ots: any;
  export default ots;
  export = ots;
}
