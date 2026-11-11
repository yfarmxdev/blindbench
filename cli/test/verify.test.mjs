// What `verify` must catch beyond a bad signature: an answer signed by another
// model's enclave, a run that skipped or swapped items, a forged judge
// signature, and evidence that does not say what the certificate says.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Wallet } from 'ethers';
import { loadSet } from '../lib/dataset.mjs';
import { checkSignature, signedTextMatches } from '../lib/tee.mjs';
import { runEval, verifyBundle, certificateMismatches } from '../lib/runner.mjs';
import { failureText } from '../lib/near.mjs';
import { startMock } from '../mock/tee-server.mjs';
import { sha256 } from '../lib/util.mjs';

const EX = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'examples');

test('a model-enclave signature must name the model the evidence claims', async () => {
  const w = Wallet.createRandom();
  const h = { requestSha256: sha256('req'), responseSha256: sha256('resp') };
  const pair = `${h.requestSha256}:${h.responseSha256}`;
  const sign = async (text) => ({ text, signature: await w.signMessage(text), signing_address: w.address });
  const attestedAddresses = [w.address.toLowerCase()];
  assert.equal(checkSignature(await sign(`lab/big:${pair}`), { ...h, model: 'lab/big', attestedAddresses }).ok, true);
  assert.equal(checkSignature(await sign(pair), { ...h, model: 'lab/big', attestedAddresses }).kind, 'gateway');
  // same enclave key, same bytes, but the signed text names a different model
  assert.equal(checkSignature(await sign(`lab/small:${pair}`), { ...h, model: 'lab/big', attestedAddresses }).ok, false);
  assert.equal(signedTextMatches(`x:lab/big:${pair}`, { ...h, model: 'lab/big' }), false);
});

test('verify: leaves must hash up to the root, judge signatures must hold, certificate fields must match', async () => {
  const mock = await startMock(0);
  try {
    const set = loadSet(join(EX, 'smart-contract-bugs.jsonl'));
    const r = await runEval({ set, model: 'demo/strong', endpoint: mock.url, judge: 'demo/judge' });
    const v = await verifyBundle(r.bundle);
    assert.deepEqual(v.problems, []);
    assert.equal(v.root_ok, true);
    assert.equal(v.items, set.items.length);
    assert.equal(v.signed_items, set.items.length);
    assert.equal(v.judge.total, set.items.length);
    assert.equal(v.judge.valid, v.judge.total);

    // a run that left an item out (and re-averaged the score) no longer covers the committed set
    const short = structuredClone(r.bundle);
    short.items.pop();
    short.score_bps = Math.round(short.items.reduce((s, it) => s + it.score, 0) / short.items.length * 10000);
    assert.ok((await verifyBundle(short)).problems.some((p) => p.includes('dataset_root')));
    // an item swapped for one that is not in the set
    const swapped = structuredClone(r.bundle);
    swapped.items[0].leaf = sha256('an easier question');
    assert.ok((await verifyBundle(swapped)).problems.some((p) => p.includes('dataset_root')));
    // a judge verdict whose signature does not cover the recorded bytes
    const judged = structuredClone(r.bundle);
    judged.items[0].judge.response_sha256 = sha256('a kinder verdict');
    assert.ok((await verifyBundle(judged)).problems.some((p) => p.includes('judge signature')));
    // the model's answer relabelled as another model's
    const renamed = structuredClone(r.bundle);
    renamed.model = 'demo/weak';
    assert.ok((await verifyBundle(renamed)).problems.some((p) => p.includes('signature')));

    const cert = { evidence_hash: r.evidence_hash, dataset_root: r.bundle.dataset_root, model: 'demo/strong', score_bps: r.score_bps, items: set.items.length, judge_model: 'demo/judge', tee: r.tee };
    assert.deepEqual(certificateMismatches(cert, r.bundle, v, { allowSimulated: true }), []);
    assert.deepEqual(certificateMismatches(cert, r.bundle, v), ['the evidence came from the simulated enclave']);
    assert.ok(certificateMismatches({ ...cert, model: 'demo/medium' }, r.bundle, v).some((d) => d.startsWith('model')));
    assert.ok(certificateMismatches({ ...cert, tee: { ...r.tee, signed_responses: 2 } }, r.bundle, v).some((d) => d.startsWith('signed answers')));
    assert.ok(certificateMismatches({ ...cert, tee: { ...r.tee, attestation_hash: sha256('other report') } }, r.bundle, v).some((d) => d.startsWith('attestation')));
    assert.deepEqual(certificateMismatches(null, r.bundle, v), ['no such certificate']);
  } finally { mock.server.close(); }
});

test('a contract panic is reported with its message, not as a success', () => {
  const failure = { ActionError: { index: 0, kind: { FunctionCallError: { ExecutionError: 'Smart contract panicked: run is not pending' } } } };
  assert.equal(failureText(failure), 'run is not pending');
  assert.equal(failureText({ Other: 1 }), '{"Other":1}');
});

test('verify refuses evidence that is malformed, unjudged, self-judged or carries a bad judge signature', async () => {
  const mock = await startMock(0);
  try {
    const set = loadSet(join(EX, 'smart-contract-bugs.jsonl'));
    const r = await runEval({ set, model: 'demo/strong', endpoint: mock.url, judge: 'demo/judge' });
    const has = async (b, text) => assert.ok((await verifyBundle(b)).problems.some((p) => p.includes(text)), `expected a problem with "${text}"`);
    const edit = (fn) => { const b = structuredClone(r.bundle); fn(b); return b; };
    // a judge signature that fails is a problem whatever the record says about itself
    await has(edit((b) => { b.items[0].judge.signature_valid = false; b.items[0].judge.response_sha256 = '0'.repeat(64); (b.items[0].judge.passes?.[0]?.calls?.[0] ?? b.items[0].judge.passes?.[0] ?? {}).response_sha256 = '0'.repeat(64); }), 'a judge signature does not verify');
    // judge evidence dropped from an answer
    await has(edit((b) => { b.items[0].judge = null; }), 'no signed judge call');
    // the model named as its own judge
    await has(edit((b) => { b.judge_model = b.model; }), 'graded its own answers');
    // scores that are not numbers used to slip past the mean check as NaN
    await has(edit((b) => { delete b.items[0].score; }), 'score is not a number');
    await has(edit((b) => { b.items[0].score = 'NaN'; }), 'score is not a number');
    await has(edit((b) => { b.score_bps = null; }), 'score_bps is not a whole number');
    // the same answer listed twice, an entry with no index, an empty bundle, not a bundle
    await has(edit((b) => { b.items.push(structuredClone(b.items[0])); }), 'appears twice');
    await has(edit((b) => { delete b.items[1].index; }), 'no item index');
    await has(edit((b) => { b.items = []; }), 'lists no items');
    assert.ok((await verifyBundle(null)).problems.length);
    assert.ok((await verifyBundle({ items: 'x' })).problems.length);
    // a breakdown that is not the certificate's
    const v = await verifyBundle(r.bundle);
    const cert = { evidence_hash: v.evidence_hash, dataset_root: r.bundle.dataset_root, model: r.bundle.model, score_bps: r.bundle.score_bps, items: v.items, judge_model: r.bundle.judge_model, breakdown: [{ label: 'easy', items: 1, score_bps: 10000 }] };
    assert.ok(certificateMismatches(cert, { ...r.bundle, breakdown: [] }, v, { allowSimulated: true }).some((m) => m.startsWith('breakdown')));
  } finally { mock.server.close(); }
});

test('a run where the model would grade its own answers is refused', async () => {
  const mock = await startMock(0);
  try {
    const set = loadSet(join(EX, 'smart-contract-bugs.jsonl'));
    await assert.rejects(runEval({ set, model: 'demo/strong', judge: 'demo/strong', endpoint: mock.url }), /would grade its own answers/);
  } finally { mock.server.close(); }
});
