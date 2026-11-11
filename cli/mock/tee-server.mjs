// SIMULATED NEAR AI Cloud, for the no-keys demo.
//
// Speaks the same API as https://cloud-api.near.ai/v1 for the three calls the
// runner makes: chat/completions, attestation/report and signature/<id>. It
// signs every response with a throwaway secp256k1 key in exactly NEAR AI's
// format ("<model>:<sha256(request)>:<sha256(response)>", EIP-191), so the
// runner's verification code runs unchanged. Nothing here is a real enclave:
// the report says "simulated": true and the runner prints SIMULATED.
//
// The "models" answer from the public demo sets' answer keys with a fixed
// skill level, so the demo leaderboard is deterministic:
//   demo/strong 0.975 demo/medium 0.6   demo/weak 0.25   demo/judge (grader)
import { createServer } from 'node:http';
import { readFileSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Wallet } from 'ethers';
import { sha256, randomHex } from '../lib/util.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const SETS = join(HERE, '..', '..', 'examples');
const SKILL = { 'demo/strong': 0.975, 'demo/medium': 0.6, 'demo/weak': 0.25 };
const wallet = Wallet.createRandom();
const sigs = new Map();

// Index every public demo item by its prompt so a "model" can look itself up.
const byPrompt = new Map();
for (const f of readdirSync(SETS).filter((f) => f.endsWith('.jsonl'))) {
  for (const line of readFileSync(join(SETS, f), 'utf8').split('\n').slice(1).filter(Boolean)) {
    const it = JSON.parse(line);
    byPrompt.set(it.prompt, it);
  }
}

// Deterministic coin: does `model` get `key` right?
// Same difficulty per question for every model, so a stronger model knows a superset.
const knows = (model, key) => parseInt(sha256('difficulty|' + key).slice(0, 8), 16) / 0xffffffff < (SKILL[model] ?? 0);

function answer(model, messages) {
  const user = messages.filter((m) => m.role === 'user').pop()?.content ?? '';
  if (model === 'demo/judge') return judge(user);
  const it = byPrompt.get(user);
  if (!it) return 'I am a simulated model and do not know this task.\nFINAL: unknown';
  if (it.answer !== undefined) return `Working through it.\nFINAL: ${knows(model, it.id) ? it.answer : 'none of the above'}`;
  if (it.checklist) {
    // Real findings are reported when the model "knows" them; a decoy is claimed when it does not.
    const lines = it.checklist.filter((f) => (f.trap ? !knows(model, it.id + f.id) : knows(model, it.id + f.id))).map((f) =>
      `- ${f.finding} (severity: ${f.trap ? 'medium' : knows(model, it.id + f.id + 'sev') ? f.severity : 'low'})`);
    return lines.length ? `Issues found:\n${lines.join('\n')}` : 'No issues found.';
  }
  if (it.rubric) {
    return it.rubric.filter((r, i) => knows(model, it.id + i)).map((r) => `Clause addressing: ${r.criterion}.`).join('\n') || 'Draft agreement.';
  }
  return 'FINAL: unknown';
}

// The judge: exact substring checks against the key it is handed.
// Protocol v2 prompts fence the answer in <answer-NONCE> tags and want a quote.
function judgeV2(prompt) {
  const fence = prompt.match(/\n<(answer-[0-9a-f]+)>\n([\s\S]*)\n<\/\1>/);
  const cand = fence[2];
  const keyM = prompt.match(/Answer key \(known findings[^)]*\):\n(.*)\n/);
  const decM = prompt.match(/Decoys \(things that look wrong but are NOT real issues[^)]*\):\n(.*)\n/);
  const line = (f) => cand.split('\n').find((l) => l.includes(f.finding));
  const results = keyM ? JSON.parse(keyM[1]).map((f) => {
    const l = line(f);
    return { id: f.id, quote: l ? f.finding : '', found: Boolean(l), candidate_severity: (l?.match(/severity: (\w+)/) ?? [])[1] ?? 'none' };
  }) : [];
  const decoys = decM ? JSON.parse(decM[1]).map((f) => ({ id: f.id, quote: line(f) ? f.finding : '', claimed: Boolean(line(f)) })) : undefined;
  return JSON.stringify({ results, decoys, unmatched: 0, unmatched_wrong: 0 });
}

function judge(prompt) {
  if (/\n<answer-[0-9a-f]+>\n/.test(prompt)) return judgeV2(prompt);
  const cand = (prompt.split('<<<\n')[1] ?? '').split('\n>>>')[0];
  const keyM = prompt.match(/Answer key \(known findings\):\n(.*)\n/);
  if (keyM) {
    const key = JSON.parse(keyM[1]);
    const decM = prompt.match(/Decoys \(things that look wrong but are NOT real issues\):\n(.*)\n/);
    const decoys = decM ? JSON.parse(decM[1]).map((f) => ({ id: f.id, claimed: cand.includes(f.finding) })) : undefined;
    return JSON.stringify({ decoys, results: key.map((f) => {
      const line = cand.split('\n').find((l) => l.includes(f.finding));
      return { id: f.id, found: Boolean(line), candidate_severity: (line?.match(/severity: (\w+)/) ?? [])[1] ?? 'none' };
    }) });
  }
  const rub = JSON.parse(prompt.match(/Rubric:\n(.*)\n/)[1]);
  return JSON.stringify({ scores: rub.map((r) => ({ i: r.i, score: cand.includes(r.criterion) ? 1 : 0 })) });
}

const send = (res, code, obj) => {
  const body = typeof obj === 'string' ? obj : JSON.stringify(obj);
  res.writeHead(code, { 'Content-Type': 'application/json' });
  res.end(body);
  return body;
};

export function startMock(port = 0) {
  const server = createServer(async (req, res) => {
    const url = new URL(req.url, 'http://x');
    if (req.method === 'POST' && url.pathname === '/v1/chat/completions') {
      const chunks = [];
      for await (const ch of req) chunks.push(ch);
      const raw = Buffer.concat(chunks).toString();
      const body = JSON.parse(raw);
      const id = 'chatcmpl-sim-' + randomHex(8);
      const resp = JSON.stringify({
        id, object: 'chat.completion', model: body.model,
        choices: [{ index: 0, message: { role: 'assistant', content: answer(body.model, body.messages) }, finish_reason: 'stop' }],
        usage: { prompt_tokens: 0, completion_tokens: 0 },
      });
      const text = `${body.model}:${sha256(raw)}:${sha256(resp)}`;
      sigs.set(id, { text, signature: await wallet.signMessage(text), signing_address: wallet.address, signing_algo: 'ecdsa', signature_kind: 'provider_tee' });
      return send(res, 200, resp);
    }
    if (url.pathname === '/v1/attestation/report') {
      return send(res, 200, {
        simulated: true,
        model_attestations: [{ signing_address: wallet.address, signing_algo: 'ecdsa', request_nonce: url.searchParams.get('nonce'), intel_quote: 'SIMULATED-NOT-A-REAL-QUOTE' }],
      });
    }
    const m = url.pathname.match(/^\/v1\/signature\/(.+)$/);
    if (m) return sigs.has(m[1]) ? send(res, 200, sigs.get(m[1])) : send(res, 404, { error: 'not found' });
    send(res, 404, { error: 'not found' });
  });
  return new Promise((ok) => server.listen(port, '127.0.0.1', () => ok({ server, url: `http://127.0.0.1:${server.address().port}/v1`, address: wallet.address })));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const { url } = await startMock(Number(process.env.PORT || 8787));
  console.log(`simulated NEAR AI Cloud on ${url}`);
}
