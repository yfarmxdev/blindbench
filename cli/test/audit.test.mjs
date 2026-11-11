// Checks added after an outside code review: input handling at the edges of the CLI.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { loadSet, loadSalts, commitment, merkleProof, verifyProof, leafOf } from '../lib/dataset.mjs';
import { toYocto, returnedId } from '../lib/near.mjs';
import { keyFor, intFlag } from '../lib/util.mjs';

const CLI = fileURLToPath(new URL('../blindbench.mjs', import.meta.url));
const setFile = (items) => {
  const f = join(mkdtempSync(join(tmpdir(), 'bb-audit-')), 'set.jsonl');
  writeFileSync(f, [{ _meta: { name: 't', grading: 'exact', description: 't' } }, ...items].map((x) => JSON.stringify(x)).join('\n'));
  return f;
};

test('amounts in NEAR: only plain non-negative decimals convert', () => {
  assert.equal(toYocto('0.5'), '500000000000000000000000');
  assert.equal(toYocto(2), '2000000000000000000000000');
  for (const bad of ['-0.5', '-1.5', '1.2.3', '1e3', '', 'abc', '0.' + '1'.repeat(25)]) assert.throws(() => toYocto(bad), /not an amount/, bad);
});

test('the API key goes to NEAR AI Cloud or localhost only, and never over plain http', () => {
  assert.equal(keyFor('https://cloud-api.near.ai/v1', 'k'), 'k');
  assert.equal(keyFor('http://127.0.0.1:8099/v1', 'k'), 'k');
  assert.throws(() => keyFor('https://example.org/v1', 'k'), /another host/);
  assert.equal(keyFor('https://example.org/v1', 'k', { allowCustom: true }), 'k');
  assert.equal(keyFor('https://example.org/v1', undefined), undefined);
  assert.throws(() => keyFor('http://example.org/v1', 'k', { allowCustom: true }), /must be https/);
  assert.throws(() => keyFor('https://user:pw@cloud-api.near.ai/v1', 'k'), /credentials/);
  // A look-alike host is not NEAR AI Cloud.
  assert.throws(() => keyFor('https://cloud-api.near.ai.example.org/v1', 'k'), /another host/);
});

test('item ids are safe file names and unique; salts are never read off the prototype', () => {
  for (const id of ['../../etc/passwd', 'a/b', '.hidden', 'a b', '']) assert.throws(() => loadSet(setFile([{ id, prompt: 'p', answer: 'a' }])), /id/, id);
  assert.throws(() => loadSet(setFile([{ id: 'a', prompt: 'p', answer: '1' }, { id: 'a', prompt: 'q', answer: '2' }])), /used twice/);
  const set = loadSet(setFile([{ id: 'constructor', prompt: 'p', answer: 'a' }, { id: 'toString', prompt: 'q', answer: 'b' }]));
  const { salts } = loadSalts(set);
  assert.match(salts.constructor, /^[0-9a-f]{64}$/);
  assert.match(salts.toString, /^[0-9a-f]{64}$/);
});

test('prove needs the committed salts and never creates them', () => {
  const f = setFile([{ id: 'a', prompt: 'p', answer: '1' }, { id: 'b', prompt: 'q', answer: '2' }]);
  const dir = mkdtempSync(join(tmpdir(), 'bb-audit-out-'));
  const r = spawnSync(process.execPath, [CLI, 'prove', f, 'a'], { cwd: dir, encoding: 'utf8' });
  assert.notEqual(r.status, 0);
  assert.match(r.stderr, /no salt for a/);
  assert.equal(existsSync(f.replace(/\.jsonl$/, '.salts.json')), false, 'no salts file was written');
});

test('a proof is only valid at its own index', () => {
  const set = loadSet(setFile(['a', 'b', 'c', 'd', 'e'].map((id) => ({ id, prompt: id, answer: id }))));
  const { salts } = loadSalts(set);
  const com = commitment(set);
  for (let i = 0; i < 5; i++) {
    const proof = merkleProof(com.leaves, i);
    const leaf = leafOf(set.items[i], salts[set.items[i].id]);
    assert.ok(verifyProof(leaf, proof, com.root, i));
    assert.ok(verifyProof(leaf, proof, com.root), 'index is optional');
    assert.equal(verifyProof(leaf, proof, com.root, (i + 1) % 5), false, `index ${i} claimed as another`);
  }
});

test('flags that need a number say so; an unknown command is an error', () => {
  assert.equal(intFlag('7', '--run-id'), 7);
  for (const bad of [true, '', 'x', '1.5', '-1']) assert.throws(() => intFlag(bad, '--run-id'), /whole number/);
  const r = spawnSync(process.execPath, [CLI, 'no-such-command'], { encoding: 'utf8' });
  assert.equal(r.status, 2);
  assert.match(r.stderr, /unknown command/);
  assert.equal(spawnSync(process.execPath, [CLI], { encoding: 'utf8' }).status, 0);
});

test('submit never certifies simulated or unproven evidence, with or without --force', () => {
  const item = { index: 0, sample: 0, score: 1, leaf: 'a'.repeat(64), request_sha256: 'b'.repeat(64), response_sha256: 'c'.repeat(64), signed_text: 'x', signature: '0x00' };
  const bundle = (attestation) => {
    const f = join(mkdtempSync(join(tmpdir(), 'bb-audit-')), 'evidence.json');
    writeFileSync(f, JSON.stringify({ model: 'demo/strong', grading: 'exact', score_bps: 10000, dataset_root: 'd'.repeat(64), items: [item], attestation }));
    return f;
  };
  // No contract and no network are configured: both are refused before anything is looked up or sent.
  const env = { ...process.env, BLINDBENCH_CONTRACT: 'nowhere.testnet', NEAR_RPC_URL: 'http://127.0.0.1:9' };
  const submit = (file, ...flags) => spawnSync(process.execPath, [CLI, 'submit', file, '--run-id', '1', ...flags], { encoding: 'utf8', env });
  const key = '0x' + '12'.repeat(20);
  for (const flags of [[], ['--force']]) {
    const sim = submit(bundle({ simulated: true, level: 'model-enclave', signing_addresses: [key] }), ...flags);
    assert.equal(sim.status, 1, sim.stderr);
    assert.match(sim.stderr, /not submitted: this evidence came from the simulated enclave/);
    const bare = submit(bundle({ simulated: false, level: 'model-enclave', signing_addresses: [key] }), ...flags);
    assert.equal(bare.status, 1, bare.stderr);
    assert.match(bare.stderr, /not submitted: a signing key in this evidence has no valid hardware proof/);
  }
});

test('a call that returned no id is not printed as done', () => {
  assert.equal(returnedId({ value: 7, url: 'u' }, 'request_run'), 7);
  assert.equal(returnedId({ value: 0, url: 'u' }, 'commit_dataset'), 0);
  for (const value of [null, undefined, '7', -1, 1.5, true]) assert.throws(() => returnedId({ value, url: 'https://explorer/txns/abc' }, 'fulfill_run'), /returned no id\. Inspect https:\/\/explorer\/txns\/abc/);
});

test('the local web server answers a malformed request and keeps running', async () => {
  const { spawn } = await import('node:child_process');
  const port = 18000 + Math.floor(Math.random() * 1000);
  const p = spawn(process.execPath, [CLI, 'web', '--port', String(port)], { stdio: ['ignore', 'pipe', 'pipe'] });
  try {
    await new Promise((ok, no) => { p.stdout.on('data', ok); p.on('exit', () => no(new Error('server exited'))); setTimeout(() => no(new Error('server did not start')), 10000); });
    const get = (path) => fetch(`http://127.0.0.1:${port}${path}`).then((r) => r.status);
    assert.equal(await get('/%E0%A4%A'), 400);
    assert.equal(await get('/..%2f..%2fpackage.json'), 404);
    assert.equal(await get('/'), 200);
    const r = await fetch(`http://127.0.0.1:${port}/`);
    assert.equal(r.headers.get('x-content-type-options'), 'nosniff');
  } finally { p.kill(); }
});
