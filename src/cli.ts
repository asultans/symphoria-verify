#!/usr/bin/env node
/**
 * symphoria-verify ,  CLI for verifying a Symphoria investigation
 * export ZIP against the public Bitcoin chain.
 *
 *   $ npx @symphoria/verify investigation.zip
 *   $ symphoria-verify investigation.zip --skip-bitcoin
 *   $ symphoria-verify investigation.zip --bitcoin-rpc https://...
 *
 * Exit codes:
 *   0 ,  every event verified, including any pending Bitcoin confirmations
 *   1 ,  one or more events FAILED a check (tamper detected)
 *   2 ,  bundle could not be opened or manifest is malformed
 *   3 ,  at least one event is in pending state (OTS not yet confirmed)
 */

import { verifyBundle } from './verify.js';

async function main() {
  const args = process.argv.slice(2);
  const positional: string[] = [];
  let skipBitcoin = false;
  let bitcoinRpcUrl: string | undefined;
  let printJson = false;

  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--skip-bitcoin') skipBitcoin = true;
    else if (a === '--bitcoin-rpc') bitcoinRpcUrl = args[++i];
    else if (a === '--json') printJson = true;
    else if (a === '-h' || a === '--help') { printHelp(); process.exit(0); }
    else if (a.startsWith('-')) { console.error(`Unknown flag: ${a}`); process.exit(2); }
    else positional.push(a);
  }

  if (positional.length !== 1) {
    printHelp();
    process.exit(2);
  }

  const bundlePath = positional[0];

  let report;
  try {
    report = await verifyBundle(bundlePath, { skipBitcoin, bitcoinRpcUrl });
  } catch (err) {
    console.error(`✗ failed to read bundle: ${(err as Error).message}`);
    process.exit(2);
  }

  if (printJson) {
    process.stdout.write(JSON.stringify(report, null, 2) + '\n');
  } else {
    printHumanReport(report);
  }

  if (report.events_failed > 0) process.exit(1);
  if (report.events_pending > 0) process.exit(3);
  process.exit(0);
}

function printHelp() {
  console.log([
    'symphoria-verify: verify a Symphoria investigation export ZIP.',
    '',
    'Usage:',
    '  symphoria-verify <bundle.zip> [options]',
    '',
    'Options:',
    '  --skip-bitcoin        Skip OpenTimestamps to Bitcoin checks',
    '  --bitcoin-rpc <url>   Use a specific Bitcoin RPC for OTS verification',
    '  --json                Emit machine-readable JSON instead of human report',
    '  -h, --help            Show this help',
    '',
    'Exit codes: 0 OK, 1 FAILED, 2 bundle error, 3 some pending.',
  ].join('\n'));
}

function printHumanReport(r: Awaited<ReturnType<typeof verifyBundle>>) {
  const COL_GREEN = '\x1b[32m';
  const COL_RED = '\x1b[31m';
  const COL_YEL = '\x1b[33m';
  const COL_DIM = '\x1b[2m';
  const COL_RST = '\x1b[0m';

  console.log(`Symphoria evidence verification`);
  console.log(`  bundle:        ${r.bundle_path}`);
  console.log(`  investigation: ${r.investigation_id}`);
  console.log(`  format:        ${r.format_version}`);
  console.log(`  events:        ${r.events_total}`);

  // Anchoring lifecycle summary ,  distinct from per-check counts because
  // it tells the user WHY some events lack proofs ("you just toggled
  // anchoring on" vs. "anchoring isn't enabled at all").
  if (r.anchoring) {
    const a = r.anchoring;
    const reasonStr = a.reasons.length ? ` (${a.reasons.join(', ')})` : '';
    console.log(`  anchoring:     ${a.active ? `${COL_GREEN}active${COL_RST}${reasonStr}` : `${COL_DIM}off${COL_RST}`}`);
    if (a.summary.queued > 0) {
      console.log(`  ${COL_YEL}↻${COL_RST} ${a.summary.queued} events queued for the next Merkle batch`);
    }
    if (a.summary.pending > 0) {
      console.log(`  ${COL_YEL}↻${COL_RST} ${a.summary.pending} events pending Bitcoin block confirmation`);
    }
    if (a.summary.confirmed > 0) {
      console.log(`  ${COL_GREEN}✓${COL_RST} ${a.summary.confirmed} events confirmed in Bitcoin`);
    }
    if (a.next_steps) {
      console.log(`  ${COL_DIM}${a.next_steps}${COL_RST}`);
    }
  }
  console.log('');

  const passes = {
    hash: r.results.filter(x => x.hash_check === 'pass').length,
    sig: r.results.filter(x => x.signature_check === 'pass').length,
    sigSkipped: r.results.filter(x => x.signature_check === 'skip').length,
    merkle: r.results.filter(x => x.merkle_check === 'pass').length,
    merkleSkipped: r.results.filter(x => x.merkle_check === 'skip').length,
    btc: r.results.filter(x => x.bitcoin_check === 'pass').length,
    btcPending: r.results.filter(x => x.bitcoin_check === 'pending').length,
    btcSkipped: r.results.filter(x => x.bitcoin_check === 'skip').length,
  };

  const ok = (n: number, t: number, label: string) => {
    const color = n === t ? COL_GREEN : (n === 0 ? COL_RED : COL_YEL);
    console.log(`  ${color}✓${COL_RST} ${n}/${t} ${label}`);
  };
  const partial = (n: number, suffix: string) => {
    if (n > 0) console.log(`  ${COL_DIM}· ${n} ${suffix}${COL_RST}`);
  };

  ok(passes.hash, r.events_total, 'content hashes match the manifest');
  ok(passes.sig, r.events_total - passes.sigSkipped, 'Ed25519 signatures verify');
  partial(passes.sigSkipped, 'events without a signature (pre-signing era)');
  ok(passes.merkle, r.events_total - passes.merkleSkipped, 'Merkle paths reconstruct');
  partial(passes.merkleSkipped, 'events not yet anchored');
  if (passes.btcSkipped < r.events_total) {
    ok(passes.btc, r.events_total - passes.btcSkipped - passes.btcPending, 'OpenTimestamps proofs confirmed against Bitcoin');
    partial(passes.btcPending, 'events still in OTS mempool (not yet confirmed)');
  } else {
    console.log(`  ${COL_DIM}· bitcoin check skipped (--skip-bitcoin)${COL_RST}`);
  }

  if (r.warnings.length > 0) {
    console.log('');
    console.log(`${COL_YEL}Warnings:${COL_RST}`);
    for (const w of r.warnings) console.log(`  - ${w}`);
  }

  if (r.events_failed > 0) {
    console.log('');
    console.log(`${COL_RED}Failures (${r.events_failed} events):${COL_RST}`);
    for (const e of r.results) {
      if (e.failures.length === 0) continue;
      console.log(`  ${e.stream} seq=${e.seq} (${e.type})`);
      for (const f of e.failures) console.log(`    - ${f}`);
    }
  }

  console.log('');
  if (r.events_failed > 0) {
    console.log(`${COL_RED}FAIL ,  ${r.events_failed} event(s) did not verify.${COL_RST}`);
  } else if (r.events_pending > 0) {
    console.log(`${COL_YEL}PASS (with ${r.events_pending} pending OTS confirmations).${COL_RST}`);
  } else {
    console.log(`${COL_GREEN}PASS ,  investigation is tamper-evident.${COL_RST}`);
  }
}

main().catch(err => {
  console.error('Unexpected error:', err);
  process.exit(2);
});
