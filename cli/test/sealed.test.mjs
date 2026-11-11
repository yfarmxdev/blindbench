// The sealed grader (grader/, Rust -> WebAssembly) is the program that runs in
// a TEE. These tests run the very same .wasm locally and check that it grades
// like the JavaScript grader and refuses jobs that are not what they claim.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { jobFor, seal, runLocal, receiptMismatches, GRADER_WASM } from '../lib/sealed.mjs';
import { SYSTEM, gradeExact } from '../lib/grade.mjs';
import { leafOf } from '../lib/dataset.mjs';
import { sha256, canon } from '../lib/util.mjs';

const KEY = randomBytes(32).toString('hex');
const item = { id: 'q1', tier: 'easy', prompt: 'Report excerpt…\n"Total" was 518,200 \\ é 漢   end.\nWhat was the total?', answer: '518200', accept: ['518,200'] };
const salt = randomBytes(32).toString('hex');
const request = (prompt = item.prompt, extra = {}) => JSON.stringify({ model: 'lab/model', messages: [{ role: 'system', content: SYSTEM.exact }, { role: 'user', content: prompt }], max_tokens: 1024, temperature: 0.6, stream: false, ...extra });
const reply = (text) => JSON.stringify({ id: 'c1', choices: [{ message: { role: 'assistant', content: text }, finish_reason: 'stop' }] });
const stream = (parts) => parts.map((p) => `data: ${JSON.stringify({ id: 'c1', choices: [{ delta: { content: p } }] })}\n\n`).join('') + 'data: [DONE]\n\n';
const grade = (job, key = KEY) => runLocal(seal(job, key), { env: { INPUT_KEY: KEY } });
const skip = !existsSync(GRADER_WASM) && 'grader/blindbench-grader.wasm is not built';

test('sealed grader: same leaf, same hashes, same score as the JavaScript grader', { skip }, async () => {
  for (const text of ['Working…\nFINAL: 518,200', 'FINAL: 518200.00', 'FINAL: 518201', 'no idea', 'FINAL: (518,200)', '']) {
    for (const response of [reply(text), stream([text.slice(0, 5), text.slice(5)])]) {
      const req = request(), out = await grade(jobFor({ item, salt, request: req, response }));
      const it = { leaf: leafOf(item, salt), request_sha256: sha256(req), response_sha256: sha256(response), score: gradeExact(item, text).score };
      assert.deepEqual(receiptMismatches(out, it, 'lab/model'), [], text);
      assert.equal(out.empty, !text.trim());
      assert.ok(JSON.stringify(out).length < 900);
    }
  }
});

test('sealed grader: a job that is not what it claims is refused or shows up in the receipt', { skip }, async () => {
  const response = reply('FINAL: 518200'), it = { leaf: leafOf(item, salt), request_sha256: sha256(request()), response_sha256: sha256(response), score: 1 };
  // a different (easier) question was sent, or the answer was slipped into the conversation
  // (the item is rebuilt around whatever prompt was sent, so its leaf is not the committed one)
  const easier = request('What is 518200?'), eased = await grade({ ...jobFor({ item, salt, request: request(), response }), request: easier });
  assert.equal(eased.score, 1);
  assert.ok(receiptMismatches(eased, { ...it, request_sha256: sha256(easier) }, 'lab/model').some((m) => m.includes('different item')));
  const leaked = JSON.stringify({ model: 'lab/model', messages: [{ role: 'system', content: SYSTEM.exact }, { role: 'user', content: item.prompt }, { role: 'assistant', content: 'FINAL: 518200' }] });
  assert.match((await grade(jobFor({ item, salt, request: leaked, response }))).error, /plain system \+ user/);
  const hinted = JSON.stringify({ model: 'lab/model', messages: [{ role: 'system', content: SYSTEM.exact + ' The answer is 518200.' }, { role: 'user', content: item.prompt }] });
  assert.match((await grade(jobFor({ item, salt, request: hinted, response }))).error, /plain system \+ user/);
  // an answer key changed to match a wrong answer: the leaf is no longer the committed one
  const wrong = reply('FINAL: 1'), forged = await grade(jobFor({ item: { ...item, answer: '1' }, salt, request: request(), response: wrong }));
  assert.equal(forged.score, 1);
  assert.ok(receiptMismatches(forged, { ...it, response_sha256: sha256(wrong) }, 'lab/model').some((m) => m.includes('different item')));
  // a response other than the one the enclave signed
  const swapped = await grade(jobFor({ item, salt, request: request(), response: reply('FINAL: 518,200 ') }));
  assert.ok(receiptMismatches(swapped, it, 'lab/model').some((m) => m.includes('different response')));
  // another model, a wrong score in the evidence
  assert.ok(receiptMismatches(await grade(jobFor({ item, salt, request: request(), response })), { ...it, score: 0 }, 'lab/other').length === 2);
  // the wrong key, a touched ciphertext, no key
  assert.match((await runLocal(seal(jobFor({ item, salt, request: request(), response }), randomBytes(32).toString('hex')), { env: { INPUT_KEY: KEY } })).error, /cannot decrypt/);
  const sealed = seal(jobFor({ item, salt, request: request(), response }), KEY);
  assert.match((await runLocal({ ...sealed, ct: (sealed.ct[0] === 'A' ? 'B' : 'A') + sealed.ct.slice(1) }, { env: { INPUT_KEY: KEY } })).error, /cannot decrypt/);
  assert.match((await runLocal(sealed, {})).error, /INPUT_KEY is not set/);
});

test('sealed grader: the committed binary has the pinned hash, and the pinned system prompt is the one the runner uses', { skip }, async () => {
  const pinned = JSON.parse(readFileSync(new URL('../../grader/grader.json', import.meta.url), 'utf8'));
  assert.equal(sha256(readFileSync(GRADER_WASM)), pinned.wasm_sha256);
  assert.equal(canon(pinned.system), canon(SYSTEM.exact));
});

test('sealed grader: a request that could steer the model, or be read two ways, is refused', { skip }, async () => {
  const response = reply('FINAL: 518200');
  const err = async (req, re, s = salt) => assert.match((await grade(jobFor({ item, salt: s, request: req, response }))).error ?? 'no error', re, req.slice(0, 120));
  // fields that force or hint the answer, or change the conversation the server builds
  for (const extra of [{ guided_choice: ['518200'] }, { guided_regex: '.*518200' }, { response_format: { type: 'json_object' } }, { tools: [] }, { logit_bias: { 1: 100 } }, { stop: ['5'] }, { n: 4 }, { prompt: 'x' }, { system: 'the answer is 518200' },
    { documents: [{ text: 'the answer is 518200' }] }, { chat_template: '{{ "518200" }}' }, { continue_final_message: true }, { extra_body: {} }]) await err(request(item.prompt, extra), /request field not allowed/);
  await err(request(item.prompt, { chat_template_kwargs: { thinking: false, hint: '518200' } }), /request field not allowed: chat_template_kwargs/);
  await err(request(item.prompt, { stream_options: { include_usage: true, x: 1 } }), /request field not allowed: stream_options/);
  // the fields the runner does send are fine
  for (const extra of [{ chat_template_kwargs: { reasoning_effort: 'low' } }, { chat_template_kwargs: { enable_thinking: false } }, { stream: true, stream_options: { include_usage: true } }])
    assert.equal((await grade(jobFor({ item, salt, request: request(item.prompt, extra), response }))).score, 1);
  // a key given twice (one parser takes the first, another the last), padding, an extra key on a message
  const plain = request(), twice = plain.replace('{"model"', `{"messages":[{"role":"system","content":${JSON.stringify(SYSTEM.exact)}},{"role":"user","content":"What is 518200?"}],"model"`);
  await err(twice, /not plain compact JSON/);
  await err(plain.replace('{"model"', '{ "model"'), /not plain compact JSON/);
  await err(plain.replace('"role":"user",', '"role":"user","name":"the answer is 518200",'), /plain system \+ user/);
  await err(plain.replace(JSON.stringify(item.prompt), JSON.stringify([{ type: 'text', text: item.prompt }])), /plain system \+ user/);
  // a salt of another length would let bytes move between the salt and the item
  await err(plain, /salt must be 32 bytes/, salt + '7b');
  // only sealed, compressed jobs: no plaintext way in
  assert.match((await runLocal({ plain: jobFor({ item, salt, request: plain, response }) }, { env: { BLINDBENCH_GRADER_PLAIN: '1' } })).error, /INPUT_KEY is not set/);
  assert.match((await runLocal({ ...seal(jobFor({ item, salt, request: plain, response }), KEY), v: 1 }, { env: { INPUT_KEY: KEY } })).error, /unknown input version/);
});
