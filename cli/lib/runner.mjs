// The runner: score one model on one private set and build the evidence.
//
// For each item: send it to the model through NEAR AI Cloud, fetch the
// enclave's signature for that exact request/response, check it against the
// attested key, grade the answer (with the judge model for checklist/rubric,
// itself TEE-signed), and record only hashes in the evidence bundle.
import { chat } from './llm.mjs';
import { attest, fetchSignature, checkSignature, signedTextMatches } from './tee.mjs';
import { proofStore, proveReport } from './attest.mjs';
import { proveKeys } from '../../web/tdx.mjs';
import { SYSTEM, gradeExact, judgePrompt, judgePromptV2, scoreChecklist, scoreChecklistV2, checklistVerdict, combineGradings, scoreChecklistByKeywords, scoreRubric } from './grade.mjs';
import { commitment, loadSalts, merkleRoot } from './dataset.mjs';
import { gradeTests } from './codetests.mjs';
import { canon, sha256, randomHex } from './util.mjs';
import { mkdirSync, writeFileSync, existsSync, readFileSync, renameSync } from 'node:fs';
import { verifyMessage } from 'ethers';

// Private debugging only: BLINDBENCH_DEBUG_DIR keeps plaintext answers and
// judge verdicts on the runner's disk. Never part of the evidence bundle.
const DEBUG_DIR = process.env.BLINDBENCH_DEBUG_DIR;
// BLINDBENCH_RESUME_DIR: keep each finished item (hashes, signatures and score,
// never plaintext) on the runner's disk, so a run cut short by the network
// picks up where it stopped instead of paying for every answer again.
const RESUME_DIR = process.env.BLINDBENCH_RESUME_DIR;
const BODIES_DIR = process.env.BLINDBENCH_BODIES_DIR;
const sleep = (ms) => new Promise((ok) => setTimeout(ok, ms));

// BLINDBENCH_JUDGE_MAX_TOKENS raises the judge's output budget for a judge that reasons at
// length before its verdict (the evidence records the value used).
const JUDGE_MAX_TOKENS = Math.max(1024, Math.floor(Number(process.env.BLINDBENCH_JUDGE_MAX_TOKENS)) || 16384);
export const SAMPLING = { max_tokens: 32768, temperature: 0.6, judge_max_tokens: JUDGE_MAX_TOKENS, judge_temperature: 0 };

// Per-model request settings, recorded in every evidence bundle. DeepSeek V4.1
// otherwise reasons past 32k tokens on long documents and never answers.
export const MODEL_PARAMS = {
  'deepseek-ai/DeepSeek-V4.1-Flash-1017': { chat_template_kwargs: { reasoning_effort: 'low' } },
};

// How to switch reasoning off per model (each checked against NEAR AI Cloud).
// Long-document sets (100k+ characters) run with thinking off for every model:
// with it on, models reason past their output budget and never answer.
export const THINKING_OFF = {
  'deepseek-ai/DeepSeek-V4.1-Flash-1017': { chat_template_kwargs: { thinking: false } },
  'moonshotai/kimi-k3': { chat_template_kwargs: { thinking: false } },
  'moonshotai/kimi-k2.6': { chat_template_kwargs: { thinking: false } },
  'deepseek/deepseek-v3.2': {},
  'qwen/qwen3.5-397b-a17b': { chat_template_kwargs: { enable_thinking: false } },
  'Qwen/Qwen3.8-27B': { chat_template_kwargs: { enable_thinking: false } },
  'Qwen/Qwen3.6-35B-A3B-FP8': { chat_template_kwargs: { enable_thinking: false } },
};

// samples: answers per item (k). The item score is the mean of its k answers, the
// set score the mean over items (mean@k), and every answer is signed and kept in
// the evidence, one entry per answer. k >= 2 also gives a rerun error bar.
// judgePasses: gradings per answer (checklist sets); passes vote per finding.
// judgeProtocol: 'v1' (default) or 'v2' (quoted evidence, nonce-fenced answer,
// shuffled key). A set can ask for v2 with "_meta.judge_protocol": "v2".
export async function runEval({ set, model, endpoint, apiKey, judge, altJudge, log = () => {}, concurrency = Number(process.env.BLINDBENCH_CONCURRENCY) || 3, maxTokens = SAMPLING.max_tokens, thinking = true, samples = 1, judgePasses = 1, judgeProtocol, judgeBatch, itemRetries, retryWaitMs = 30000, resumeDir = RESUME_DIR }) {
  // Against the live service an item that fails (gateway 5xx, dropped stream)
  // is asked again after a wait; the local mock fails fast.
  itemRetries ??= endpoint.includes('127.0.0.1') ? 0 : 3;
  samples = Math.max(1, Math.floor(samples));
  USAGE = { model: { calls: 0, prompt_tokens: 0, completion_tokens: 0, reasoning_tokens: 0 }, judge: { calls: 0, prompt_tokens: 0, completion_tokens: 0, reasoning_tokens: 0 } };
  judgePasses = Math.max(1, Math.floor(judgePasses));
  judgeProtocol ??= set.meta.judge_protocol ?? 'v1';
  // A model never grades its own answers: with --alt-judge, that judge steps in.
  if (judge && altJudge && judge === model) { log(`${model} is the judge model, so ${altJudge} judges this run instead`); judge = altJudge; }
  if (set.meta.grading === 'tests' || set.meta.grading === 'exact') judge = undefined;
  if (judge && judge === model) throw new Error(`${model} would grade its own answers: name another judge with --alt-judge <model>`);
  if (!thinking && !(model in THINKING_OFF) && !endpoint.includes('127.0.0.1')) throw new Error(`no known way to switch thinking off for ${model}`);
  const sampling = { ...SAMPLING, max_tokens: maxTokens, thinking, model_params: thinking ? MODEL_PARAMS[model] ?? {} : THINKING_OFF[model] ?? {}, judge_params: MODEL_PARAMS[judge] ?? {}, samples, ...(judge ? { judge_passes: judgePasses, judge_protocol: judgeProtocol, ...(judgeBatch ? { judge_batch: judgeBatch } : {}) } : {}) };
  const mode = set.meta.grading;
  const com = commitment(set);
  if (mode === 'rubric' && !judge) throw new Error('rubric grading needs --judge <model>');

  const att = await attest({ endpoint, apiKey, model });
  if (!att.nonceEchoed) throw new Error('attestation did not echo our nonce (stale or replayed report)');
  const judgeAtt = judge ? await attest({ endpoint, apiKey, model: judge }) : null;
  log(`attested ${model}: ${att.level}${att.provider ? ' (' + att.provider + ')' : ''}, signing key ${att.signingAddresses[0]}${att.simulated ? ' (SIMULATED)' : ''}`);
  // Hardware proof before any question is sent: every quote in both reports must
  // verify to Intel's root and bind the signing key and our nonce. The key proofs
  // are returned so the caller can publish them next to the evidence.
  const keyProofs = [], rawReports = [];
  for (const [a, m] of att.simulated ? [] : [[att, model], ...(judgeAtt ? [[judgeAtt, judge]] : [])]) {
    const { proofs, lines } = await proveReport(a.report, { nonce: a.nonce, model: m });
    keyProofs.push(...proofs); rawReports.push({ report_sha256: a.reportSha256, raw: a.raw });
    for (const l of lines) log(`  hardware ✓ ${l.role} key ${l.rec.signing_address}: TDX quote to Intel's root, TCB ${l.rec.tcb?.tcb_status ?? 'not checked'}${l.gpu ? `, ${l.gpu.gpus} GPUs pass` : ''}${l.notes.length ? ' (' + l.notes.join('; ') + ')' : ''}`);
  }

  const items = [];
  // Resume: items a cut-short run of this exact set, model, judge and sampling
  // already finished. An item is kept only if its signatures recover to keys
  // in the attestation fetched just now; anything else is asked again.
  const ckFile = resumeDir ? `${resumeDir}/${sha256(canon({ root: com.root, model, judge: judge ?? null, mode, sampling, endpoint })).slice(0, 24)}.json` : null;
  let resumed = 0;
  if (ckFile && existsSync(ckFile)) {
    const lower = (xs) => (xs ?? []).map((a) => String(a).toLowerCase());
    const keys = [...lower(att.signingAddresses), ...lower(att.gatewayAddresses)];
    const judgeKeys = judgeAtt ? [...lower(judgeAtt.signingAddresses), ...lower(judgeAtt.gatewayAddresses)] : [];
    const signer = (rec) => { try { return verifyMessage(rec.signed_text, rec.signature).toLowerCase(); } catch { return null; } };
    const ck = JSON.parse(readFileSync(ckFile, 'utf8'));
    for (const it of ck.items ?? []) {
      if (it.leaf !== com.leaves[it.index] || (it.sample ?? 0) >= samples) continue;
      if (it.signature_valid && !keys.includes(signer(it))) continue;
      const calls = it.judge ? (it.judge.passes ?? [it.judge]).flatMap((p) => p.calls ?? [p]) : [];
      if (calls.some((c) => c.signature_valid && !judgeKeys.includes(signer(c)))) continue;
      items.push(it);
    }
    resumed = items.length;
    if (resumed && ck.usage) USAGE = ck.usage;
    log(`resuming: ${resumed} of ${set.items.length * samples} answers kept from the earlier attempt${resumed < (ck.items ?? []).length ? ` (${ck.items.length - resumed} dropped: enclave key changed)` : ''}`);
  }
  const checkpoint = () => {
    if (!ckFile) return;
    mkdirSync(resumeDir, { recursive: true });
    writeFileSync(ckFile + '.tmp', JSON.stringify({ model, dataset_root: com.root, usage: USAGE, items }));
    renameSync(ckFile + '.tmp', ckFile);
  };
  // An answer that is already signed is kept across retries of its item, so a
  // judge hiccup re-asks the judge and never the model.
  const answered = new Map();
  const answerOne = async (item, i, r) => {
    const messages = [{ role: 'system', content: SYSTEM[mode] }, { role: 'user', content: item.prompt }];
    // A set can switch thinking off for one long item ("thinking": false on it).
    const think = item.thinking ?? thinking;
    if (!think && !(model in THINKING_OFF) && !endpoint.includes('127.0.0.1')) throw new Error(`no known way to switch thinking off for ${model}`);
    const params = think === thinking ? sampling.model_params : think ? MODEL_PARAMS[model] ?? {} : THINKING_OFF[model] ?? {};
    // An item can cap its own output ("max_tokens"), e.g. a huge-prompt item that
    // runs with thinking off, without starving the thinking models on the rest.
    let curParams = params;
    const ask = async (stream) => addUsage('model', await chat({ endpoint, apiKey, model, maxTokens: item.max_tokens ?? sampling.max_tokens, temperature: sampling.temperature, params: curParams, stream, messages, failFast: !stream }));
    let res;
    if (att.level === 'model-enclave') {
      // Non-streamed first, for the model enclave's own signature; if the long
      // request keeps dropping, stream it and accept the attested gateway's.
      try { res = await ask(false); }
      catch (e) { log(`  ${item.id ?? i}: ${e.message}; retrying streamed (gateway-signed)`); res = await ask(true); }
    } else res = await ask(true);
    // A reasoning model can spend the whole output budget thinking and return
    // nothing. One more try with thinking off, so the item scores the model's
    // answer rather than its silence; the item records that it happened.
    let emptyRetry = false;
    if (!res.text.trim() && res.finishReason === 'length' && think && model in THINKING_OFF) {
      log(`  ${item.id ?? i}: empty answer at the token limit (${res.usage?.completion_tokens ?? '?'} tok); asking again with thinking off`);
      emptyRetry = true;
      curParams = THINKING_OFF[model];
      res = await ask(att.level !== 'model-enclave');
    }
    let sig = await fetchSignature({ endpoint, apiKey, model, chatId: res.id });
    if (sig.unsupported) {
      // No signature to fetch for that response: ask once more (a fresh chat id
      // usually gets a signed path); if it happens again the item stays, unsigned.
      log(`  ${item.id ?? i}: no per-response signature (${sig.message.slice(0, 60)}); asking again`);
      res = await ask(att.level !== 'model-enclave');
      sig = await fetchSignature({ endpoint, apiKey, model, chatId: res.id });
    }
    // BLINDBENCH_BODIES_DIR: keep the exact request and response of every signed
    // answer (named by the response hash), so the answers can later be graded again
    // inside an enclave. These files hold the questions: keep the directory private.
    if (BODIES_DIR && sha256(res.rawResponse) === res.responseSha256) {
      mkdirSync(BODIES_DIR, { recursive: true });
      writeFileSync(`${BODIES_DIR}/${res.responseSha256}.json`, JSON.stringify({ request: res.rawRequest, response: res.rawResponse }));
    }
    const check = sig.unsupported ? { ok: false, why: 'no per-response signature (encrypted channel)' }
      : checkSignature(sig, { ...res, model, attestedAddresses: [...att.signingAddresses, ...(att.gatewayAddresses ?? [])] });
    return { res, sig, check, think, emptyRetry };
  };
  const scoreOne = async (item, i, r) => {
    const key = `${i}:${r}`;
    if (!answered.has(key)) answered.set(key, await answerOne(item, i, r));
    const { res, sig, check, think, emptyRetry } = answered.get(key);

    let g;
    let judgeEv = null;
    if (mode === 'exact') g = gradeExact(item, res.text);
    else if (mode === 'tests') g = await gradeTests(item, res.text, { requireIsolation: !endpoint.includes('127.0.0.1') });
    else if (judge) {
      // An empty answer scores 0 without spending a judge call.
      if (!res.text.trim()) g = { score: 0, detail: { empty_answer: true, finish_reason: res.finishReason } };
      else {
        ({ g, judgeEv } = await judgeAnswer({ endpoint, apiKey, judge, judgeAtt, item, answer: res.text, mode, sampling, severity: set.meta.severity, label: item.id ?? i, passes: judgePasses, protocol: judgeProtocol, batch: judgeBatch, log }));
      }
    } else g = scoreChecklistByKeywords(item, res.text);
    if (DEBUG_DIR) {
      mkdirSync(DEBUG_DIR, { recursive: true });
      writeFileSync(`${DEBUG_DIR}/${item.id ?? i}-${model.replace(/[^\w.-]+/g, '_')}${samples > 1 ? `-s${r}` : ''}.json`, JSON.stringify({ model, judge, sample: r, usage: res.usage, answer: res.text, judge_text: judgeEv ? judgeEv._text : null, detail: g.detail, score: g.score }, null, 2));
    }

    items.push({
      index: i,
      ...(samples > 1 ? { sample: r } : {}),
      leaf: com.leaves[i],
      request_sha256: res.requestSha256,
      response_sha256: res.responseSha256,
      chat_id: res.id,
      signature: sig.signature,
      signed_text: sig.text,
      signing_address: sig.signing_address,
      thinking: think && !emptyRetry,
      empty_retry: emptyRetry, // first answer was empty at the token limit; this one came with thinking off
      empty: !res.text.trim(),
      finish_reason: res.finishReason ?? null,
      usage: usageOf(res.usage),
      signature_kind: check.kind ?? null, // provider_tee = model enclave key, gateway = attested NEAR AI gateway key
      signature_valid: check.ok,
      score: Math.round(g.score * 10000) / 10000,
      judge: judgeEv && (({ _text, _usage, ...pub }) => pub)(judgeEv),
    });
    checkpoint();
    answered.delete(key);
    log(`  item ${i + 1}/${set.items.length}${samples > 1 ? ` sample ${r + 1}/${samples}` : ''} (${item.id}): score ${g.score.toFixed(2)} ${check.ok ? 'signed ✓' : 'UNSIGNED ✗ ' + check.why}${res.text.trim() ? '' : ' (EMPTY ANSWER, finish ' + res.finishReason + ')'} out ${res.usage?.completion_tokens ?? '?'} tok`);
  };
  // A few items in flight at once: reasoning models can take minutes per answer.
  const have = new Set(items.map((it) => `${it.index}:${it.sample ?? 0}`));
  const queue = set.items.flatMap((item, i) => Array.from({ length: samples }, (_, r) => [item, i, r])).filter(([, i, r]) => !have.has(`${i}:${r}`));
  // One item failing for good stops new items from starting, lets the ones in
  // flight finish (and be kept for a resume), then fails the run.
  let fatal = null;
  const workers = Array.from({ length: Math.min(concurrency, queue.length) }, async () => {
    while (queue.length && !fatal) {
      const [item, i, r] = queue.shift();
      for (let tries = 0; ; tries++) {
        try { await scoreOne(item, i, r); break; }
        catch (e) {
          if (tries >= itemRetries || fatal) { fatal ??= e; break; }
          const wait = retryWaitMs * 2 ** tries;
          log(`  ${item.id ?? i}: ${String(e.message).slice(0, 160)}; trying this item again in ${Math.round(wait / 1000)} s`);
          await sleep(wait);
        }
      }
    }
  });
  await Promise.all(workers);
  if (fatal) throw fatal;
  items.sort((a, b) => a.index - b.index || (a.sample ?? 0) - (b.sample ?? 0));
  // Per item: the mean of its samples. An item counts as signed only if every sample is.
  const byItem = set.items.map((_, i) => items.filter((it) => it.index === i));
  const itemMean = byItem.map((xs) => xs.reduce((s, it) => s + it.score, 0) / xs.length);
  const signed = byItem.filter((xs) => xs.every((it) => it.signature_valid)).length;
  const empty = items.filter((it) => it.empty).length;
  const retried = items.filter((it) => it.empty_retry).length;

  const score_bps = Math.round((itemMean.reduce((s, x) => s + x, 0) / set.items.length) * 10000);
  const n = set.items.length;
  const sd = (xs) => { const m = xs.reduce((s, x) => s + x, 0) / xs.length; return xs.length > 1 ? Math.sqrt(xs.reduce((s, x) => s + (x - m) ** 2, 0) / (xs.length - 1)) : 0; };
  const stats = {
    items: n,
    samples,
    // spread of item scores: how well the set measures the skill (Miller 2024)
    item_se_bps: n > 1 ? Math.round(sd(itemMean) / Math.sqrt(n) * 10000) : null,
    // spread between samples of the same item: would a rerun give the same certificate?
    rerun_se_bps: samples > 1 ? Math.round(Math.sqrt(byItem.reduce((s, xs) => s + sd(xs.map((it) => it.score)) ** 2 / xs.length, 0)) / n * 10000) : null,
  };
  // Per-tier means when the set's items carry a "tier" (easy / medium / hard).
  const TIER_ORDER = ['easy', 'medium', 'hard'];
  const tiers = [...new Set(set.items.map((it) => it.tier).filter(Boolean))]
    .sort((a, b) => ((TIER_ORDER.indexOf(a) + 1 || 99) - (TIER_ORDER.indexOf(b) + 1 || 99)) || a.localeCompare(b));
  const breakdown = tiers.length && set.items.every((it) => it.tier) ? tiers.map((label) => {
    const idx = set.items.map((it, i) => (it.tier === label ? i : -1)).filter((i) => i >= 0);
    return { label, items: idx.length, score_bps: Math.round((idx.reduce((s, i) => s + itemMean[i], 0) / idx.length) * 10000) };
  }) : [];
  const bundle = {
    version: 'blindbench-evidence/1',
    dataset_root: com.root,
    grading: mode,
    usage: USAGE, // token totals for the model under test and the judge (what the run cost)
    model,
    judge_model: judge ?? null,
    endpoint,
    sampling,
    attestation: { level: att.level, provider: att.provider ?? null, provider_verdict: att.providerVerdict ?? null, signing_addresses: att.signingAddresses, gateway_addresses: att.gatewayAddresses ?? [], signing_algo: att.signingAlgo, nonce: att.nonce, report_sha256: att.reportSha256, simulated: att.simulated },
    judge_attestation: judgeAtt && { level: judgeAtt.level, signing_addresses: judgeAtt.signingAddresses, gateway_addresses: judgeAtt.gatewayAddresses ?? [], report_sha256: judgeAtt.reportSha256, simulated: judgeAtt.simulated },
    items,
    score_bps,
    ...(samples > 1 || judgePasses > 1 ? { stats } : {}),
    ...(breakdown.length ? { breakdown } : {}),
    // answers carried over from an attempt the network cut short (same enclave keys)
    ...(resumed ? { resumed_answers: resumed } : {}),
  };
  const evidence_hash = sha256(canon(bundle));
  // The run is whole: retire its checkpoint so a later run starts fresh.
  if (ckFile && existsSync(ckFile)) renameSync(ckFile, ckFile.replace(/\.json$/, '.done'));
  const tee = { signing_address: att.signingAddresses[0], signing_algo: 'ecdsa', attestation_hash: att.reportSha256, signed_responses: signed };
  return { bundle, evidence_hash, keyProofs, rawReports, score_bps, breakdown, tee, signed, empty, retried, items: set.items.length, judge_model: judge ?? null, stats, usage: USAGE };
}

// The judge, at temperature 0; if its reply is not parseable, one retry at 0.6.
// Its call is TEE-signed like any other, and the signature goes in the evidence.
// With passes > 1 the answer is graded that many times (v2 shuffles the key each
// pass) and the passes vote per finding; every pass is signed and kept.
// Token accounting: reasoning tokens are billed as completion tokens, so a run's
// cost is prompt_tokens * input price + completion_tokens * output price per model.
let USAGE = null;
function usageOf(u) {
  if (!u) return null;
  return { prompt_tokens: u.prompt_tokens ?? 0, completion_tokens: u.completion_tokens ?? 0, reasoning_tokens: u.completion_tokens_details?.reasoning_tokens ?? 0 };
}
function addUsage(who, res) {
  const u = usageOf(res.usage);
  if (USAGE && u) { const t = USAGE[who]; t.calls++; t.prompt_tokens += u.prompt_tokens; t.completion_tokens += u.completion_tokens; t.reasoning_tokens += u.reasoning_tokens; }
  return res;
}

async function judgeCall({ endpoint, apiKey, judge, judgeAtt, sampling, messages }) {
  const jr = addUsage('judge', await chat({ endpoint, apiKey, model: judge, messages, maxTokens: sampling.judge_max_tokens, temperature: sampling.judge_temperature, params: sampling.judge_params, stream: judgeAtt.level !== 'model-enclave' }));
  const jsig = await fetchSignature({ endpoint, apiKey, model: judge, chatId: jr.id });
  const jcheck = jsig.unsupported ? { ok: false, why: 'no per-response signature (encrypted channel)' }
    : checkSignature(jsig, { ...jr, model: judge, attestedAddresses: [...judgeAtt.signingAddresses, ...(judgeAtt.gatewayAddresses ?? [])] });
  return { jr, ev: { _text: jr.text, _usage: jr.usage, request_sha256: jr.requestSha256, response_sha256: jr.responseSha256, signature: jsig.signature, signed_text: jsig.text, signature_valid: jcheck.ok } };
}

// v2 can grade the key in batches (batch = findings per call; decoys get their
// own call). One finding per call is what HealthBench, PaperBench and EVMbench
// do; it costs one judge call per finding.
async function judgeOnce({ endpoint, apiKey, judge, judgeAtt, item, answer, mode, sampling, severity, label, protocol, nonce, pass, batch, log = () => {} }) {
  const v2 = mode === 'checklist' && protocol === 'v2';
  const real = v2 ? item.checklist.filter((f) => !f.trap) : [], traps = v2 ? item.checklist.filter((f) => f.trap) : [];
  const chunks = v2 && batch && batch < real.length + traps.length
    ? [...Array.from({ length: Math.ceil(real.length / batch) }, (_, c) => real.slice(c * batch, (c + 1) * batch)), ...(traps.length ? [traps] : [])]
    : [undefined];
  const replies = [];
  const evs = [];
  for (const only of chunks) {
    const messages = v2 ? judgePromptV2(item, answer, { nonce, pass, only }) : judgePrompt(item, answer, mode);
    // A judge that reasons up to its token limit leaves a verdict that is cut off or missing.
    // It gets the rule a model's empty answer gets: one more ask with thinking off (recorded
    // on the judge call). Any other unusable reply is asked again at temperature 0.6.
    let cutOff = false;
    for (let attempt = 0; ; attempt++) {
      const quiet = attempt > 0 && cutOff && judge in THINKING_OFF;
      const s = !attempt ? sampling : quiet ? { ...sampling, judge_params: THINKING_OFF[judge] } : { ...sampling, judge_temperature: 0.6 };
      const { jr, ev } = await judgeCall({ endpoint, apiKey, judge, judgeAtt, sampling: s, messages });
      try {
        if (mode === 'checklist') {
          try { checklistVerdict(jr.text); } catch (e) {
            cutOff = jr.finishReason === 'length';
            throw new Error(cutOff ? 'judge verdict cut off at its token limit' : /incomplete/.test(e.message) ? e.message : 'judge did not return JSON');
          }
          replies.push(jr.text);
        } else replies.push(jr.text);
        evs.push({ ...ev, attempt, ...(quiet ? { thinking: false } : {}), ...(v2 ? { protocol: 'v2', pass, ...(only ? { graded: only.map((f) => f.id) } : {}) } : {}) });
        break;
      } catch (e) {
        if (attempt >= 1) throw new Error(`judge ${judge} gave no usable verdict for ${label}: ${e.message}`);
        if (cutOff && judge in THINKING_OFF) log(`  ${label}: judge verdict cut off at its token limit; asking the judge again with thinking off`);
      }
    }
  }
  let g;
  try {
    if (mode !== 'checklist') g = scoreRubric(item, replies[0]);
    else if (!v2) g = scoreChecklist(item, replies[0], { severity, answer });
    else if (replies.length === 1) g = scoreChecklistV2(item, replies[0], answer, { severity });
    else {
      // merge the batch replies into one verdict, then score it as a whole
      const parsed = replies.map((t) => scoreChecklistV2.parse(t));
      const merged = { results: parsed.flatMap((j) => j.results ?? []), decoys: parsed.flatMap((j) => j.decoys ?? []) };
      g = scoreChecklistV2(item, JSON.stringify(merged), answer, { severity });
    }
  } catch (e) { throw new Error(`judge ${judge} gave no usable verdict for ${label}: ${e.message}`); }
  const pub = ({ _text, _usage, ...rest }) => rest;
  const judgeEv = evs.length === 1 ? evs[0] : { ...evs[0], _text: evs.map((e) => e._text).join('\n---\n'), calls: evs.map(pub) };
  return { judgeEv, g };
}

async function judgeAnswer({ passes = 1, protocol = 'v1', batch = 0, ...a }) {
  const nonce = randomHex(8);
  const runs = [];
  for (let pass = 0; pass < passes; pass++) runs.push(await judgeOnce({ ...a, protocol, nonce, pass, batch }));
  if (runs.length === 1) return runs[0];
  const pub = ({ _text, _usage, ...rest }) => rest;
  const g = a.mode === 'checklist' ? combineGradings(a.item, runs.map((r) => r.g), { severity: a.severity })
    : { score: runs.reduce((s, r) => s + r.g.score, 0) / runs.length, detail: runs.map((r) => r.g.detail) };
  // judgeEv keeps the first pass's fields for older readers, plus every pass.
  return { g, judgeEv: { ...runs[0].judgeEv, _text: runs.map((r) => r.judgeEv._text).join('\n---\n'), passes: runs.map((r) => pub(r.judgeEv)), agreement: g.agreement ?? null } };
}

/**
 * Grade answers produced outside BlindBench (e.g. a closed reference model)
 * with the same TEE judge. Never a certificate: the answers are not signed.
 */
export async function gradeAnswers({ set, answers, judge, endpoint, apiKey, label = 'reference', log = () => {}, judgePasses = 1, judgeProtocol, judgeBatch }) {
  judgeProtocol ??= set.meta.judge_protocol ?? 'v1';
  judgeBatch ??= set.meta.judge_batch ?? 0;
  const mode = set.meta.grading;
  if (mode !== 'exact' && mode !== 'tests' && !judge) throw new Error('needs --judge <model>');
  if (mode === 'exact' || mode === 'tests') judge = undefined;
  const judgeAtt = judge ? await attest({ endpoint, apiKey, model: judge }) : null;
  const sampling = { ...SAMPLING, judge_params: MODEL_PARAMS[judge] ?? {} };
  const out = [];
  await Promise.all(set.items.map(async (item, i) => {
    const answer = answers[item.id];
    if (answer == null) { log(`  ${item.id}: no answer file, skipped`); return; }
    let g, judgeEv = null;
    if (mode === 'exact') g = gradeExact(item, answer);
    else if (mode === 'tests') g = await gradeTests(item, answer, { requireIsolation: true });
    else ({ g, judgeEv } = await judgeAnswer({ endpoint, apiKey, judge, judgeAtt, item, answer, mode, sampling, severity: set.meta.severity, label: item.id, passes: judgePasses, protocol: judgeProtocol, batch: judgeBatch, log }));
    out[i] = { id: item.id, score: g.score, detail: g.detail, penalty: g.penalty ?? 0, judge_text: judgeEv?._text ?? null, judge_signature_valid: judgeEv?.signature_valid ?? null, ...(g.agreement != null ? { judge_agreement: g.agreement } : {}), ...(g.overturned != null ? { quotes_overturned: g.overturned, unmatched: g.unmatched, unmatched_wrong: g.unmatched_wrong } : {}) };
    log(`  ${item.id}: score ${g.score.toFixed(2)}${judgeEv ? (judgeEv.signature_valid ? ' (judge signed ✓)' : ' (judge UNSIGNED ✗)') : ''}`);
  }));
  const graded = out.filter(Boolean);
  return { label, judge, judge_protocol: judge ? judgeProtocol : null, judge_passes: judge ? judgePasses : null, judge_batch: judge ? judgeBatch : null, uncertified: true, items: graded, score: graded.length ? graded.reduce((s, x) => s + x.score, 0) / graded.length : 0 };
}

/**
 * Recheck a bundle offline, with nothing but the bundle itself:
 *  - every answer's signature recovers to a key from the attestation, over exactly
 *    the request/response hashes recorded (and, for a model enclave, names the model);
 *  - the per-item leaves hash up to the dataset root, so the run covered the whole
 *    committed set and nothing else;
 *  - every judge call that claims a signature carries a valid one from the judge's keys;
 *  - the score is the mean of the item scores.
 * The caller compares evidence_hash (and the fields below) with the onchain certificate.
 */
export async function verifyBundle(bundle, { proofFor = proofStore() } = {}) {
  const { verifyMessage } = await import('ethers');
  const problems = [];
  // The bundle is untrusted input: check its shape before any arithmetic on it.
  const shape = bundleShapeProblems(bundle);
  if (shape.length) return { evidence_hash: sha256(canon(bundle ?? null)), hardware: 'unproven', keys: [], valid: 0, total: 0, items: 0, signed_items: 0, root_ok: false, judge: { valid: 0, total: 0 }, problems: shape };
  if (bundle.judge_model && bundle.judge_model === bundle.model) problems.push('the model graded its own answers');
  // The signing keys are named by the bundle itself, so on their own they prove
  // nothing: each one needs a published hardware quote (see attest.mjs). Only the
  // offline demo's simulated enclave is let through, and it is labelled as such.
  const simulated = Boolean(bundle.attestation?.simulated);
  const keyRows = simulated ? [] : [
    ...(await proveKeys(bundle.attestation, bundle.model, proofFor)).map((r) => ({ ...r, of: 'model' })),
    ...(bundle.judge_attestation ? (await proveKeys(bundle.judge_attestation, bundle.judge_model, proofFor)).map((r) => ({ ...r, of: 'judge' })) : []),
  ];
  for (const r of keyRows) if (!r.ok) problems.push(`${r.of} signing key ${r.address} is not hardware-backed: ${r.why}`);
  if (!simulated && !keyRows.some((r) => r.of === 'model')) problems.push('the evidence names no signing key');
  if (bundle.judge_attestation?.simulated && !simulated) problems.push('the judge ran in the simulated enclave');
  const lower = (xs) => (xs ?? []).map((a) => String(a).toLowerCase());
  const keys = [...lower(bundle.attestation?.signing_addresses), ...lower(bundle.attestation?.gateway_addresses)];
  const judgeKeys = [...lower(bundle.judge_attestation?.signing_addresses), ...lower(bundle.judge_attestation?.gateway_addresses)];
  const sigOk = (rec, model, allowed) => {
    if (!signedTextMatches(rec.signed_text, { requestSha256: rec.request_sha256, responseSha256: rec.response_sha256, model })) return false;
    try { return allowed.includes(verifyMessage(rec.signed_text, rec.signature).toLowerCase()); } catch { return false; }
  };
  let valid = 0;
  const judge = { valid: 0, total: 0 };
  // index -> { leaf, scores, signed } (several entries per index when the run drew several samples)
  const groups = new Map();
  for (const it of bundle.items) {
    const ok = sigOk(it, bundle.model, keys);
    if (ok) valid += 1; else problems.push(`item ${it.index}: signature does not verify`);
    const g = groups.get(it.index) ?? { leaf: it.leaf, scores: [], signed: true };
    if (g.leaf !== it.leaf) problems.push(`item ${it.index}: samples disagree on the item's leaf`);
    g.scores.push(it.score); g.signed &&= ok;
    groups.set(it.index, g);
    // Judge calls: one per answer, or one per pass and per batch of findings.
    const calls = it.judge ? (it.judge.passes ?? [it.judge]).flatMap((p) => p.calls ?? [p]) : [];
    for (const call of calls) {
      judge.total += 1;
      const jok = sigOk(call, bundle.judge_model, judgeKeys);
      if (jok) judge.valid += 1; else problems.push(`item ${it.index}: a judge signature does not verify`);
    }
    // A judged set needs the judge's signed call for every answer; an empty answer scores 0 unjudged.
    if (bundle.judge_model && !calls.length && !(it.empty === true && it.score === 0)) problems.push(`item ${it.index}: no signed judge call for this answer`);
    if (!bundle.judge_model && calls.length) problems.push(`item ${it.index}: judge calls in a run that names no judge`);
  }
  // Leaves in item order must hash up to the committed root.
  const idx = [...groups.keys()].sort((a, b) => a - b);
  let rootOk = idx.every((v, i) => v === i) && idx.every((i) => /^[0-9a-f]{64}$/.test(groups.get(i).leaf ?? ''));
  if (rootOk) rootOk = merkleRoot(idx.map((i) => groups.get(i).leaf)) === bundle.dataset_root;
  if (!rootOk) problems.push('item leaves do not hash up to dataset_root');
  // Several samples per item: the score is the mean over items of each item's mean.
  const k = bundle.sampling?.samples ?? 1;
  if ([...groups.values()].some((g) => g.scores.length !== k)) problems.push(`every item should have ${k} samples`);
  const means = [...groups.values()].map((g) => g.scores.reduce((s, x) => s + x, 0) / g.scores.length);
  const mean = means.reduce((s, x) => s + x, 0) / means.length;
  if (!(Math.abs(Math.round(mean * 10000) - bundle.score_bps) <= 1)) problems.push('score_bps does not equal the mean of item scores');
  return { evidence_hash: sha256(canon(bundle)), hardware: simulated ? 'simulated' : keyRows.every((r) => r.ok) && keyRows.length ? 'proven' : 'unproven', keys: keyRows, valid, total: bundle.items.length, items: groups.size, signed_items: [...groups.values()].filter((g) => g.signed).length, root_ok: rootOk, judge, problems };
}

/** Shape checks on an evidence bundle, shared with the page's verifier (web/index.html keeps a copy). */
export function bundleShapeProblems(b) {
  if (!b || typeof b !== 'object' || !Array.isArray(b.items)) return ['the evidence is not a bundle with a list of items'];
  if (!b.items.length) return ['the evidence lists no items'];
  const out = [], seen = new Set();
  if (typeof b.model !== 'string' || !b.model) out.push('the evidence names no model');
  if (!Number.isInteger(b.score_bps) || b.score_bps < 0 || b.score_bps > 10000) out.push('score_bps is not a whole number from 0 to 10000');
  const k = b.sampling?.samples ?? 1;
  if (!Number.isInteger(k) || k < 1) out.push('sampling.samples is not a positive whole number');
  b.items.forEach((it, n) => {
    if (!it || typeof it !== 'object') return out.push(`entry ${n}: not an object`);
    if (!Number.isInteger(it.index) || it.index < 0) return out.push(`entry ${n}: no item index`);
    const sample = it.sample ?? 0;
    if (!Number.isInteger(sample) || sample < 0) out.push(`item ${it.index}: sample is not a whole number`);
    if (seen.has(`${it.index}:${sample}`)) out.push(`item ${it.index}: sample ${sample} appears twice`);
    seen.add(`${it.index}:${sample}`);
    if (typeof it.score !== 'number' || !Number.isFinite(it.score) || it.score < 0 || it.score > 1) out.push(`item ${it.index}: score is not a number from 0 to 1`);
    for (const key of ['leaf', 'request_sha256', 'response_sha256']) if (typeof it[key] !== 'string') out.push(`item ${it.index}: no ${key}`);
  });
  return out.slice(0, 20);
}

/** Does a verified bundle say what an onchain certificate says? Returns the list of differences. */
export function certificateMismatches(cert, bundle, v, { allowSimulated = false } = {}) {
  const out = [];
  const differ = (what, a, b) => { if (a !== b) out.push(`${what}: certificate has ${a}, evidence has ${b}`); };
  if (!cert) return ['no such certificate'];
  differ('evidence hash', cert.evidence_hash, v.evidence_hash);
  differ('dataset root', cert.dataset_root, bundle.dataset_root);
  differ('model', cert.model, bundle.model);
  differ('score_bps', cert.score_bps, bundle.score_bps);
  differ('items', cert.items, v.items);
  differ('judge model', cert.judge_model ?? null, bundle.judge_model ?? null);
  const parts = (xs) => JSON.stringify((xs ?? []).map((p) => [p.label, p.items, p.score_bps]));
  differ('breakdown', parts(cert.breakdown), parts(bundle.breakdown));
  // A certificate on a real chain must rest on real hardware; only the offline demo ledger may not.
  if (bundle.attestation?.simulated && !allowSimulated) out.push('the evidence came from the simulated enclave');
  if (cert.tee) {
    differ('signing key', String(cert.tee.signing_address).toLowerCase(), String(bundle.attestation?.signing_addresses?.[0]).toLowerCase());
    differ('signed answers', cert.tee.signed_responses, v.signed_items);
    differ('attestation hash', cert.tee.attestation_hash, bundle.attestation?.report_sha256);
  }
  return out;
}

export { loadSalts };
