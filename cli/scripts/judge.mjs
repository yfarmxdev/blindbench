#!/usr/bin/env node
// The README's "do X, see Y" steps, run one after another and checked.
//   npm run judge              every step (the live ones read testnet, NEAR AI
//                              Cloud, Intel, NVIDIA and NEAR Intents; no key, no account)
//   npm run judge -- --offline only the steps that need no network
// Exit code 0 means every step that ran exited cleanly and printed what the README says it prints.
// The browser and wallet steps of the README (6c, 6d) are not exercised here.
import { spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync, existsSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const CLI = join(dirname(fileURLToPath(import.meta.url)), '..'), ROOT = join(CLI, '..');
const offline = process.argv.includes('--offline');
const CONTRACT = process.env.BLINDBENCH_CONTRACT ?? 'blindbench-hnxot5.testnet';
const env = { ...process.env, BLINDBENCH_CONTRACT: CONTRACT, FORCE_COLOR: '0', NO_COLOR: '1' };
const has = (cmd) => spawnSync(cmd, ['--version'], { stdio: 'ignore', shell: process.platform === 'win32' }).status === 0;
const sh = (cmd, args, cwd = CLI, timeout = 600000) => {
  const r = spawnSync(cmd, args, { cwd, env, encoding: 'utf8', timeout, maxBuffer: 64 << 20, shell: process.platform === 'win32' });
  return { code: r.status, out: `${r.stdout ?? ''}${r.stderr ?? ''}`.replace(/\x1b\[[0-9;]*m/g, '') };
};
const bb = (...args) => sh(process.execPath, ['blindbench.mjs', ...args]);
const rows = [];
let failed = 0;
function step(id, what, run) {
  const t = Date.now();
  let r;
  try { r = run(); } catch (e) { r = { fail: e.message ?? String(e) }; }
  const status = r?.skip ? 'SKIP' : r?.fail ? 'FAIL' : 'ok';
  if (status === 'FAIL') failed += 1;
  rows.push([id, status, what, r?.skip ?? r?.fail ?? r?.saw ?? '']);
  console.log(`${status === 'ok' ? '✓' : status === 'SKIP' ? '-' : '✗'} ${id.padEnd(3)} ${what}  (${((Date.now() - t) / 1000).toFixed(1)}s)${r?.skip ? `\n      skipped: ${r.skip}` : r?.fail ? `\n      FAILED: ${r.fail}` : r?.saw ? `\n      ${r.saw}` : ''}`);
}
/** Every pattern must appear in the output; returns the first match as what was seen. */
const printed = (r, ...patterns) => {
  for (const p of patterns) if (!p.test(r.out)) return { fail: `expected ${p}, got:\n${r.out.trim().split('\n').slice(-12).join('\n')}` };
  return { saw: r.out.match(patterns[0])[0].trim() };
};
/** A step that should succeed: the command must exit 0 as well as print what is expected. */
const expect = (r, ...patterns) => (r.code !== 0 ? { fail: `exit code ${r.code}:\n${r.out.trim().split('\n').slice(-12).join('\n')}` } : printed(r, ...patterns));

console.log(`BlindBench judge checks${offline ? ' (offline steps only)' : ''}\n`);

step('1', 'contract unit tests', () => {
  if (!has('cargo')) return { skip: 'Rust (cargo) is not installed' };
  return expect(sh('cargo', ['test'], join(ROOT, 'contract'), 1800000), /test result: ok\. \d+ passed; 0 failed/);
});
step('2', 'CLI test suite', () => expect(sh(process.execPath, ['--test', ...readdirSync(join(CLI, 'test')).filter((f) => f.endsWith('.test.mjs')).map((f) => join('test', f))], CLI), /# pass \d+/, /# fail 0\b/));
step('3', 'offline demo: commit, pay, run, certify, pay out', () => expect(bb('demo'), /expert\.near: 6 NEAR from 12 paid runs/, /bounty #0 won/, /verifies against root/));
const demoEv = join(ROOT, '.blindbench', 'evidence', 'ds1-demo_strong.json');
step('4', 'verify a demo evidence bundle', () => expect(bb('verify', demoEv), /3\/3 enclave signatures valid/, /3 item leaves hash up to dataset root/, /3\/3 judge calls signed/));
step('4t', 'a tampered bundle is caught', () => {
  if (!existsSync(demoEv)) return { fail: 'no demo evidence (step 3 failed)' };
  const b = JSON.parse(readFileSync(demoEv, 'utf8')), bad = join(ROOT, '.blindbench', 'evidence', 'tampered.json');
  b.items[0].response_sha256 = b.items[0].response_sha256.replace(/^./, (c) => (c === '0' ? '1' : '0'));
  writeFileSync(bad, JSON.stringify(b));
  const r = bb('verify', bad);
  return r.code === 0 ? { fail: 'verify exited 0 on tampered evidence' } : printed(r, /signature does not verify/);
});
step('4k', 'evidence signed by a key with no hardware quote is refused', () => {
  if (!existsSync(demoEv)) return { fail: 'no demo evidence (step 3 failed)' };
  const b = JSON.parse(readFileSync(demoEv, 'utf8')), bad = join(ROOT, '.blindbench', 'evidence', 'self-vouched.json');
  b.attestation.simulated = false; if (b.judge_attestation) b.judge_attestation.simulated = false;
  writeFileSync(bad, JSON.stringify(b));
  const r = bb('verify', bad);
  return r.code === 0 ? { fail: 'verify exited 0 on self-vouched evidence' } : printed(r, /NOT hardware-backed: no hardware quote is published for this key/);
});
step('4h', 'published hardware quotes verify offline to Intel\'s root', () => expect(sh(process.execPath, ['--test', 'test/hardware.test.mjs'], CLI), /# pass 5\b/, /# fail 0\b/));

if (!offline) {
  step('5', 'NEAR Intents: live quote, USDC on Base to NEAR', () => expect(bb('pay-quote', '--from', 'nep141:base-0x833589fcd6edb6e08f4c7c32d4f71b54bda02913.omft.near', '--amount', '2000000', '--recipient', 'intents.near', '--refund-to', '0x4838B106FCe9647Bdf1E7877BF73cE8B0BAD5f97'), /2\.0 in -> [0-9.]+ wNEAR/));
  step('6', `live contract ${CONTRACT}: datasets`, () => expect(bb('datasets'), /#5\s+exact/, /#4\s+tests/));
  step('6', 'live contract: leaderboard of the coding set', () => {
    return expect(bb('leaderboard', '4'), /TEE-signed 12\/12\s+cert #\d+/);
  });
  step('6b', 'every published certificate: evidence, hardware quotes and chain agree', () => {
    const r = bb('verify', '--all');
    return r.code !== 0 ? { fail: r.out.trim().split('\n').slice(-8).join('\n') } : expect(r, /\d+ of \d+ certificates verified against their evidence, the chain and Intel TDX quotes/);
  });
  step('6e', 'live hardware proof of a NEAR AI Cloud enclave (Intel + NVIDIA), no key', () => expect(bb('attest', '--model', 'deepseek-ai/DeepSeek-V4.1-Flash-1017'),
    /PCK chain ends at Intel's SGX Root CA/, /binds this signing key and our fresh nonce/, /platform TCB \w+/, /NVIDIA attestation service: \d+ GPUs/));
}

const skipped = rows.filter((r) => r[1] === 'SKIP').length, passed = rows.length - failed - skipped;
console.log(`\n${passed} passed, ${failed} failed, ${skipped} skipped${failed ? '' : skipped ? ': every step that ran passed' : ': every step passed'}`);
if (process.env.GITHUB_STEP_SUMMARY) writeFileSync(process.env.GITHUB_STEP_SUMMARY, `### BlindBench judge checks\n\n| Step | Result | Check | Saw |\n|---|---|---|---|\n${rows.map((r) => `| ${r[0]} | ${r[1]} | ${r[2]} | ${String(r[3]).split('\n')[0].replace(/\|/g, '\\|').slice(0, 160)} |`).join('\n')}\n`, { flag: 'a' });
process.exit(failed ? 1 : 0);
