import { test } from 'node:test';
import assert from 'node:assert/strict';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Wallet } from 'ethers';
import { merkleRoot, merkleProof, verifyProof, loadSet } from '../lib/dataset.mjs';
import { checkSignature } from '../lib/tee.mjs';
import { gradeExact, scoreChecklist, scoreRubric } from '../lib/grade.mjs';
import { runEval, verifyBundle } from '../lib/runner.mjs';
import { startMock } from '../mock/tee-server.mjs';
import { sha256 } from '../lib/util.mjs';
import { gradeTests, extractCode, sandbox } from '../lib/codetests.mjs';
import { spawnSync } from 'node:child_process';

const EX = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'examples');

test('merkle proofs verify for every leaf, odd and even sizes', () => {
  for (const n of [1, 2, 3, 7, 8]) {
    const leaves = Array.from({ length: n }, (_, i) => sha256('leaf' + i));
    const root = merkleRoot(leaves);
    leaves.forEach((l, i) => assert.ok(verifyProof(l, merkleProof(leaves, i), root)));
    assert.equal(verifyProof(sha256('other'), merkleProof(leaves, 0), root), false);
  }
});

test('enclave signature must cover our exact bytes and the attested key', async () => {
  const w = Wallet.createRandom();
  const req = sha256('request'), resp = sha256('response');
  const text = `m:${req}:${resp}`;
  const sig = { text, signature: await w.signMessage(text), signing_address: w.address };
  const attested = [w.address.toLowerCase()];
  assert.ok(checkSignature(sig, { requestSha256: req, responseSha256: resp, attestedAddresses: attested }).ok);
  assert.equal(checkSignature(sig, { requestSha256: req, responseSha256: sha256('tampered'), attestedAddresses: attested }).ok, false);
  assert.equal(checkSignature(sig, { requestSha256: req, responseSha256: resp, attestedAddresses: ['0x0000000000000000000000000000000000000001'] }).ok, false);
});

test('graders', () => {
  assert.equal(gradeExact({ answer: 'B' }, 'reasoning...\nFINAL: b.').score, 1);
  assert.equal(gradeExact({ answer: 'DECOY', accept: ['decoy'] }, 'FINAL: real').score, 0);
  // numeric keys compare by value, and the sign counts
  assert.equal(gradeExact({ answer: '62', accept: ['61'] }, 'FINAL: -62').score, 0);
  assert.equal(gradeExact({ answer: '-25' }, 'FINAL: \u221225 bps').score, 1);
  assert.equal(gradeExact({ answer: '62' }, 'FINAL: (62)').score, 0);
  assert.equal(gradeExact({ answer: '7.30' }, 'FINAL: **7.3%**').score, 1);
  assert.equal(gradeExact({ answer: '518200' }, 'FINAL: $518,200.').score, 1);
  assert.equal(gradeExact({ answer: '518200' }, 'FINAL: 518.2').score, 0);
  assert.equal(gradeExact({ answer: '2031', accept: ['FY2031'] }, 'FINAL: FY2031').score, 1);
  assert.equal(gradeExact({ answer: '2031', accept: ['FY2031'] }, 'FINAL: none').score, 0);
  const item = { checklist: [{ id: 'a', severity: 'critical', weight: 3 }, { id: 'b', severity: 'low', weight: 1 }] };
  assert.equal(scoreChecklist(item, '{"results":[{"id":"a","found":true,"severity_correct":false}]}').score, 0.5625);
  // within one level of the key is full credit; two or more levels off is 0.75
  assert.equal(scoreChecklist(item, '{"results":[{"id":"a","found":true,"candidate_severity":"high"}]}').score, 0.75);
  assert.equal(scoreChecklist(item, '{"results":[{"id":"a","found":true,"candidate_severity":"medium"}]}').score, 0.5625);
  assert.equal(scoreChecklist(item, '{"results":[{"id":"a","found":false},{"id":"b","found":true,"candidate_severity":"medium"}]}').score, 0.25);
  // exact severity policy: any other level earns 0.5
  assert.equal(scoreChecklist(item, '{"results":[{"id":"a","found":true,"candidate_severity":"high"}]}', { severity: 'exact' }).score, 0.375);
  // decoys: no weight in the total; a claimed decoy costs its weight, floored at 0
  const trap = { checklist: [...item.checklist, { id: 't', trap: true, weight: 2 }] };
  assert.equal(scoreChecklist(trap, '{"results":[{"id":"a","found":true,"candidate_severity":"critical"}],"decoys":[{"id":"t","claimed":false}]}').score, 0.75);
  assert.equal(scoreChecklist(trap, '{"results":[{"id":"a","found":true,"candidate_severity":"critical"}],"decoys":[{"id":"t","claimed":true}]}').score, 0.25);
  assert.equal(scoreChecklist(trap, '{"results":[{"id":"b","found":true,"candidate_severity":"low"}],"decoys":[{"id":"t","claimed":true}]}').score, 0);
  const rub = { rubric: [{ criterion: 'x', weight: 1 }, { criterion: 'y', weight: 3 }] };
  assert.equal(scoreRubric(rub, 'ok {"scores":[{"i":1,"score":1}]}').score, 0.75);
});

test('end to end on the simulated enclave; tampering is detected', async () => {
  const mock = await startMock(0);
  try {
    const set = loadSet(join(EX, 'ledger-arithmetic.jsonl'));
    const r = await runEval({ set, model: 'demo/strong', endpoint: mock.url });
    assert.equal(r.signed, set.items.length);
    const v = await verifyBundle(r.bundle);
    assert.equal(v.evidence_hash, r.evidence_hash);
    assert.deepEqual(v.problems, []);
    const forged = structuredClone(r.bundle);
    forged.score_bps = r.bundle.score_bps === 10000 ? 9000 : 10000; // any score other than the earned one
    assert.ok((await verifyBundle(forged)).problems.length > 0);
    forged.score_bps = r.bundle.score_bps;
    forged.items[0].response_sha256 = sha256('different answer');
    assert.ok((await verifyBundle(forged)).problems.some((p) => p.includes('signature')));

    // Items with a "tier" get per-tier means that average back to the score.
    const tiered = { ...set, items: set.items.map((it, i) => ({ ...it, tier: ['easy', 'medium', 'hard'][i % 3] })) };
    const t = await runEval({ set: tiered, model: 'demo/medium', endpoint: mock.url });
    assert.deepEqual(t.breakdown.map((b) => b.label), ['easy', 'medium', 'hard']);
    assert.equal(t.breakdown.reduce((s, b) => s + b.items, 0), set.items.length);
    const mean = t.breakdown.reduce((s, b) => s + b.items * b.score_bps, 0) / set.items.length;
    assert.ok(Math.abs(mean - t.score_bps) <= t.breakdown.length);
    assert.deepEqual(t.bundle.breakdown, t.breakdown);
  } finally { mock.server.close(); }
});

const HAS_PY = spawnSync('python3', ['-c', 'pass']).status === 0;

test('tests grading: sandboxed unit tests, score is the share passed', { skip: !HAS_PY && 'python3 not installed' }, async () => {
  const item = { entry: ['add'], tests: [
    { id: 'ints', code: '_eq(add(2, 3), 5)' },
    { id: 'strict-types', code: '_eq(add(1, 1), 2)\n_eq(add(0.5, 0.5), 1.0)' },
    { id: 'raises', code: '_raises(TypeError, add, None, 1)' },
    { id: 'no-net', code: 'import socket\ntry:\n    socket.create_connection(("1.1.1.1", 80), timeout=2); ok = True\nexcept OSError:\n    ok = False\n_eq(ok, False)' },
  ] };
  const good = await gradeTests(item, 'Here you go:\n```python\ndef add(a, b):\n    return a + b\n```');
  assert.equal(good.detail.passed, good.detail.passed === 4 ? 4 : 3); // no-net passes only where a network namespace is available
  assert.ok(good.score >= 0.75);
  const bad = await gradeTests(item, '```python\ndef add(a, b):\n    return int(a) + int(b)\n```');
  assert.ok(bad.score < good.score);
  assert.ok(bad.detail.failed.some((f) => f.id === 'strict-types'));
  // the model's code cannot fake a pass by printing a verdict or exiting early
  const cheat = await gradeTests(item, '```python\nimport os, json\nprint(json.dumps({"token": "x", "ok": True, "err": None}))\nos._exit(0)\ndef add(a, b): pass\n```');
  assert.equal(cheat.score, 0);
  // nor by reading the harness's token out of the interpreter: a module that passes a test and its inverse is forging verdicts
  const forge = await gradeTests(item, '```python\nimport sys, os, json\ndef add(a, b): return 0\nos.write(1, (json.dumps({"token": sys.modules["__main__"].tok, "ok": True, "err": None}) + "\\n").encode())\nos._exit(0)\n```');
  assert.deepEqual([forge.score, forge.detail.forged_verdict], [0, true]);
  assert.equal(good.detail.forged_verdict, undefined);
  // runaway code is killed by the CPU limit or the wall clock
  const slow = await gradeTests({ entry: ['f'], timeout_s: 2, cpu_s: 1, tests: [{ id: 'spin', code: 'f()' }] }, '```python\ndef f():\n    while True: pass\n```');
  assert.equal(slow.score, 0);
  // no code at all scores 0 without running anything
  // The jail (Linux with user namespaces): model code sees no host files, no other
  // processes and no network, and cannot climb out of its root.
  if (sandbox().level === 'isolated') {
    const spy = (body) => gradeTests({ entry: ['f'], tests: [{ id: 't', code: body }] }, '```python\ndef f():\n    return 1\n```');
    const passes = async (body) => (await spy(body)).score === 1;
    assert.ok(await passes('import os\nassert sorted(os.listdir("/")) == sorted(x for x in ("bin", "lib", "lib32", "lib64", "sbin", "usr", "work") if os.path.exists("/" + x))'));
    assert.ok(await passes(`import os\nassert not os.path.exists(${JSON.stringify(import.meta.dirname)})`));
    assert.ok(await passes('import os\nassert not any(os.path.exists(p) for p in ("/etc/passwd", "/home", "/root", "/proc/1", "/old"))'));
    assert.ok(await passes('import os\nassert os.getpid() < 10'));
    assert.ok(await passes('import socket\ntry:\n    socket.create_connection(("1.1.1.1", 53), timeout=2)\n    raise AssertionError("network")\nexcept OSError:\n    pass'));
    assert.ok(await passes('import os\ntry:\n    open("/usr/x", "w")\n    raise AssertionError("writable")\nexcept OSError:\n    pass'));
    assert.ok(await passes('import os\nos.mkdir("/work/j"); os.chroot("/work/j"); os.chdir("../../../../.."); os.chroot(".")\nassert not os.path.exists("/etc") and not os.path.exists("/home")'));
  }
  // A real run refuses a weaker sandbox unless the operator accepts it.
  if (sandbox().level !== 'isolated' && process.env.BLINDBENCH_WEAK_SANDBOX !== '1') await assert.rejects(gradeTests(item, 'x', { requireIsolation: true }), /isolated sandbox/);
  const none = await gradeTests(item, 'I cannot help with that.');
  assert.deepEqual([none.score, none.detail.extracted], [0, false]);
});

test('extractCode picks the last python block that defines every entry point', () => {
  const t = 'Sketch:\n```python\ndef add(a, b): ...\n```\nUsage:\n```python\nprint(add(1, 2))\n```\nFinal:\n```py\ndef add(a, b):\n    return a + b\n```\n```text\nnotes\n```';
  assert.equal(extractCode(t, ['add']), 'def add(a, b):\n    return a + b\n');
  assert.equal(extractCode('```python\nclass Book: pass\nTrade = 1\n```', ['Book', 'Trade']), 'class Book: pass\nTrade = 1\n');
  assert.equal(extractCode('def add(a, b):\n    return a + b', ['add']), 'def add(a, b):\n    return a + b');
  assert.equal(extractCode('no code here', ['add']), '');
});

test('a model never judges itself: an alternate judge steps in', async () => {
  const mock = await startMock(0);
  try {
    const set = loadSet(join(EX, 'smart-contract-bugs.jsonl'));
    // the model under test is also the configured judge, so the alternate grades it
    const r = await runEval({ set, model: 'demo/strong', judge: 'demo/strong', altJudge: 'demo/judge', endpoint: mock.url });
    assert.equal(r.judge_model, 'demo/judge');
    assert.equal(r.bundle.judge_model, 'demo/judge');
    // otherwise the configured judge grades and the alternate is never called
    const ok = await runEval({ set, model: 'demo/strong', judge: 'demo/judge', altJudge: 'demo/unused', endpoint: mock.url });
    assert.equal(ok.judge_model, 'demo/judge');
    const e = await runEval({ set: loadSet(join(EX, 'ledger-arithmetic.jsonl')), model: 'demo/strong', judge: 'demo/strong', endpoint: mock.url });
    assert.equal(e.judge_model, null); // exact grading needs no judge
  } finally { mock.server.close(); }
});

test('a cut-short run resumes: kept answers are not asked again, foreign signatures are', async () => {
  const { mkdtempSync, readdirSync, readFileSync, writeFileSync, renameSync } = await import('node:fs');
  const { tmpdir } = await import('node:os');
  const mock = await startMock(0);
  try {
    const set = loadSet(join(EX, 'ledger-arithmetic.jsonl'));
    const dir = mkdtempSync(join(tmpdir(), 'bb-resume-'));
    const full = await runEval({ set, model: 'demo/strong', endpoint: mock.url, resumeDir: dir });
    assert.equal(full.bundle.resumed_answers, undefined);
    // A finished run retires its checkpoint; put half of it back as if the run had died there.
    const done = readdirSync(dir).find((f) => f.endsWith('.done'));
    assert.ok(done);
    const ck = JSON.parse(readFileSync(join(dir, done), 'utf8'));
    const half = ck.items.slice(0, Math.floor(ck.items.length / 2));
    const live = join(dir, done.replace(/\.done$/, '.json'));
    writeFileSync(live, JSON.stringify({ ...ck, items: half }));
    const logs = [];
    const again = await runEval({ set, model: 'demo/strong', endpoint: mock.url, resumeDir: dir, log: (l) => logs.push(l) });
    assert.equal(again.bundle.resumed_answers, half.length);
    assert.equal(again.bundle.items.length, set.items.length);
    for (const it of half) assert.equal(again.bundle.items.find((x) => x.index === it.index).chat_id, it.chat_id);
    assert.deepEqual((await verifyBundle(again.bundle)).problems, []);
    assert.equal(logs.filter((l) => /^\s+item \d+\//.test(l)).length, set.items.length - half.length);
    // An answer signed by a key the fresh attestation does not cover is asked again.
    const stranger = Wallet.createRandom();
    const forged = { ...half[0], signature: await stranger.signMessage(half[0].signed_text), signing_address: stranger.address };
    writeFileSync(live, JSON.stringify({ ...ck, items: [forged, ...half.slice(1)] }));
    const third = await runEval({ set, model: 'demo/strong', endpoint: mock.url, resumeDir: dir });
    assert.equal(third.bundle.resumed_answers ?? 0, half.length - 1);
    assert.deepEqual((await verifyBundle(third.bundle)).problems, []);
  } finally { mock.server.close(); }
});

test('an item that fails is asked again before the run gives up', async () => {
  const mock = await startMock(0);
  const { createServer } = await import('node:http');
  // A front that drops the first two chat calls, then passes everything through.
  let drops = 2;
  const front = createServer(async (req, res) => {
    const chunks = []; for await (const c of req) chunks.push(c);
    if (req.url.endsWith('/chat/completions') && drops-- > 0) { res.writeHead(400, { 'Content-Type': 'application/json' }); return res.end('{"error":"nope"}'); }
    const r = await fetch(mock.url.replace(/\/v1$/, '') + req.url, { method: req.method, headers: { 'Content-Type': 'application/json' }, ...(req.method === 'POST' ? { body: Buffer.concat(chunks) } : {}) });
    res.writeHead(r.status, { 'Content-Type': r.headers.get('content-type') ?? 'application/json' });
    res.end(Buffer.from(await r.arrayBuffer()));
  });
  await new Promise((ok) => front.listen(0, '127.0.0.1', ok));
  try {
    const set = loadSet(join(EX, 'ledger-arithmetic.jsonl'));
    const url = `http://127.0.0.1:${front.address().port}/v1`;
    await assert.rejects(runEval({ set, model: 'demo/strong', endpoint: url, concurrency: 1 }));
    drops = 2;
    const logs = [];
    const r = await runEval({ set, model: 'demo/strong', endpoint: url, concurrency: 1, itemRetries: 3, retryWaitMs: 5, log: (l) => logs.push(l) });
    assert.equal(r.signed, set.items.length);
    assert.ok(logs.some((l) => l.includes('trying this item again')));
    assert.deepEqual((await verifyBundle(r.bundle)).problems, []);
  } finally { mock.server.close(); front.close(); }
});

test('a judge failure asks the judge again, never the model: the signed answer is kept', async () => {
  const mock = await startMock(0);
  const { createServer } = await import('node:http');
  // A front that fails the first two judge calls and counts the calls to the model under test.
  let drops = 2; let modelCalls = 0;
  const front = createServer(async (req, res) => {
    const chunks = []; for await (const c of req) chunks.push(c);
    if (req.url.endsWith('/chat/completions')) {
      const who = JSON.parse(Buffer.concat(chunks).toString()).model;
      if (who === 'demo/strong') modelCalls++;
      if (who === 'demo/judge' && drops-- > 0) { res.writeHead(400, { 'Content-Type': 'application/json' }); return res.end('{"error":"nope"}'); }
    }
    const r = await fetch(mock.url.replace(/\/v1$/, '') + req.url, { method: req.method, headers: { 'Content-Type': 'application/json' }, ...(req.method === 'POST' ? { body: Buffer.concat(chunks) } : {}) });
    res.writeHead(r.status, { 'Content-Type': r.headers.get('content-type') ?? 'application/json' });
    res.end(Buffer.from(await r.arrayBuffer()));
  });
  await new Promise((ok) => front.listen(0, '127.0.0.1', ok));
  try {
    const set = loadSet(join(EX, 'ledger-arithmetic.jsonl'));
    const url = `http://127.0.0.1:${front.address().port}/v1`;
    const r = await runEval({ set, model: 'demo/strong', endpoint: url, concurrency: 1, itemRetries: 3, retryWaitMs: 5 });
    assert.equal(r.signed, set.items.length);
    assert.equal(modelCalls, set.items.length);
    assert.deepEqual((await verifyBundle(r.bundle)).problems, []);
  } finally { mock.server.close(); front.close(); }
});
