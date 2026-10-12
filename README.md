# @symphoria/verify

Verify a [Symphoria](https://symphoria.ai) investigation export ZIP against the public Bitcoin chain, without Symphoria's cooperation.

## What this does

Given an investigation bundle exported from Symphoria, this CLI confirms four things:

1. **Content integrity**: every event's SHA-256 content hash matches what's in the manifest. A flipped bit anywhere = mismatch = fail.
2. **Authorship**: every event carries an Ed25519 signature; the verifier checks it against the public keys distributed in the bundle (the same keys Symphoria publishes at `/api/ledger/public-key`).
3. **Merkle inclusion**: anchored events carry a Merkle inclusion path. Walking the path must reconstruct the batch root that was committed to Bitcoin.
4. **Bitcoin anchoring**: for each batch root, verifies the OpenTimestamps proof against an actual Bitcoin block. By default uses public Esplora endpoints; pass `--bitcoin-rpc` to use your own node.

If all four pass for every event, the bundle is **tamper-evident**: no party, including Symphoria, including a future owner of Symphoria, including a party with subpoena power over their servers, can have altered any event after the fact without that change being detectable here.

## Install

```sh
npm install -g @symphoria/verify
```

Or run without installing:

```sh
npx @symphoria/verify ./investigation.zip
```

## Usage

```sh
symphoria-verify <bundle.zip> [options]
```

**Options**

| Flag | Effect |
| --- | --- |
| `--skip-bitcoin` | Skip the OpenTimestamps→Bitcoin step. Hash, signature, and Merkle checks still run. Useful in air-gapped environments. |
| `--bitcoin-rpc <url>` | Use a specific Bitcoin RPC / Esplora endpoint instead of public defaults. |
| `--json` | Emit machine-readable JSON (for piping into other tooling). |
| `-h, --help` | Print help. |

**Exit codes**

| Code | Meaning |
| --- | --- |
| `0` | Every event verified, including Bitcoin confirmations. |
| `1` | At least one event FAILED a check (tamper detected). |
| `2` | Bundle could not be opened or manifest is malformed. |
| `3` | At least one event is in pending state (OTS proof not yet confirmed in a Bitcoin block, typical for events anchored within the last few hours). |

## Example output

```
Symphoria evidence verification
  bundle:        ./investigation-proj-abc123.zip
  investigation: proj-abc123
  format:        1.0
  events:        142

  ✓ 142/142 content hashes match the manifest
  ✓ 142/142 Ed25519 signatures verify
  ✓ 142/142 Merkle paths reconstruct
  ✓ 138/140 OpenTimestamps proofs confirmed against Bitcoin
  · 2 events still in OTS mempool (not yet confirmed)

PASS (with 2 pending OTS confirmations).
```

## What this proves

If verification passes, the exact bytes of every anchored event existed at the time of the corresponding Bitcoin block, were authored under Symphoria's published Ed25519 signing key, and have not been altered since.

## What this does NOT prove

- **Truth of contents**, anchoring proves integrity over time, not that what was written is correct. A signed-and-anchored false statement is still false.
- **Completeness**, the verifier flags sequence-number gaps as warnings, but if events were never emitted in the first place, no proof bundle can resurface them.
- **Key compromise audit**, verifies under the keys you have. If a key was ever compromised, you also need to consult `/api/ledger/public-keys/history` to know its validity window.

## Programmatic use

```ts
import { verifyBundle } from '@symphoria/verify';

const report = await verifyBundle('./investigation.zip', { skipBitcoin: false });
if (!report.ok) {
  for (const r of report.results) {
    if (r.failures.length) console.log(`fail: ${r.stream}#${r.seq}`, r.failures);
  }
}
```

## Trust boundary

The verifier is open-source and operates entirely against the bundled artifacts. It never reaches out to Symphoria infrastructure. For the OpenTimestamps→Bitcoin step it queries a public Bitcoin endpoint; that endpoint is independent of Symphoria. You can audit the verifier's source on the package's repository.

## License

MIT.
