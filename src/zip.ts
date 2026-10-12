/**
 * Read a Symphoria export ZIP into memory. Tiny abstraction over
 * yauzl so the rest of the codebase deals in `BundleHandle` instead
 * of streams.
 *
 * In-memory is fine for v1: typical bundles are MB-scale. If we ever
 * see GB bundles (full multi-year investigations) we can switch to
 * a streaming pass.
 */
import yauzl from 'yauzl';

export type BundleHandle = Map<string, Buffer>;

export async function openBundle(zipPath: string): Promise<BundleHandle> {
  return new Promise((resolve, reject) => {
    yauzl.open(zipPath, { lazyEntries: true }, (err, zf) => {
      if (err || !zf) {
        reject(err ?? new Error('failed to open zip'));
        return;
      }
      const out: BundleHandle = new Map();
      zf.readEntry();
      zf.on('entry', (entry) => {
        if (/\/$/.test(entry.fileName)) {
          // directory
          zf.readEntry();
          return;
        }
        zf.openReadStream(entry, (err2, stream) => {
          if (err2 || !stream) {
            reject(err2 ?? new Error(`failed to read ${entry.fileName}`));
            return;
          }
          const chunks: Buffer[] = [];
          stream.on('data', (c) => chunks.push(c));
          stream.on('end', () => {
            out.set(entry.fileName, Buffer.concat(chunks));
            zf.readEntry();
          });
          stream.on('error', reject);
        });
      });
      zf.on('end', () => resolve(out));
      zf.on('error', reject);
    });
  });
}

export function readJson<T>(bundle: BundleHandle, path: string): T {
  const buf = bundle.get(path);
  if (!buf) throw new Error(`missing in bundle: ${path}`);
  return JSON.parse(buf.toString('utf-8')) as T;
}
