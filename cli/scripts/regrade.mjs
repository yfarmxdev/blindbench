#!/usr/bin/env node
// Re-grade answers that are already on disk (no new model answers), to measure
// the judge: run-to-run agreement at temperature 0, agreement between two judges,
// and the effect of judge protocol v2. PRIVATE debugging tool: it reads plaintext
// answers from a BLINDBENCH_DEBUG_DIR and writes plaintext verdicts.
//
//   node scripts/regrade.mjs <set.jsonl> --debug <dir> --out <dir> --judge <model>
//        [--protocol v1|v2] [--batch b] [--passes n] [--models a,b]
//
// Each pass is written to <out>/<judge>-<protocol>[-b<batch>]-p<n>/<item>-<model>.json in the
// runner's debug format, so gradings of the same answer can be compared across passes and judges.
import { readFileSync, readdirSync, mkdirSync, writeFileSync, existsSync } from 'node:fs';
import { join, basename } from 'node:path';
import { loadSet } from '../lib/dataset.mjs';
import { gradeAnswers } from '../lib/runner.mjs';
import { keyFor, intFlag } from '../lib/util.mjs';

const args = process.argv.slice(2);
const opt = {};
const rest = [];
for (let i = 0; i < args.length; i++) args[i].startsWith('--') ? (opt[args[i].slice(2)] = args[++i]) : rest.push(args[i]);
const need = (v, what) => { if (v == null) { console.error(`missing ${what}`); process.exit(2); } return v; };
const set = loadSet(need(rest[0], '<set.jsonl>'));
const debug = need(opt.debug, '--debug <dir>');
const out = need(opt.out, '--out <dir>');
const judge = need(opt.judge, '--judge <model>');
const protocol = opt.protocol ?? 'v1';
if (!['v1', 'v2'].includes(protocol)) { console.error('--protocol is v1 or v2'); process.exit(2); }
const batch = intFlag(opt.batch ?? 0, '--batch');
const passes = intFlag(opt.passes ?? 1, '--passes', { min: 1 });
const endpoint = process.env.NEARAI_ENDPOINT ?? 'https://cloud-api.near.ai/v1';
const apiKey = keyFor(endpoint, process.env.NEARAI_API_KEY, { allowCustom: process.env.NEARAI_KEY_ANY_ENDPOINT === '1' });
const onlyModels = opt.models ? new Set(opt.models.split(',')) : null;

// answers[model][item] = text
const answers = {};
const ids = set.items.map((it) => it.id).sort((a, b) => b.length - a.length);
for (const f of readdirSync(debug).filter((f) => f.endsWith('.json'))) {
  const item = ids.find((i) => f.startsWith(i + '-'));
  if (!item) continue;
  const d = JSON.parse(readFileSync(join(debug, f), 'utf8'));
  if (!d.answer || (onlyModels && !onlyModels.has(d.model))) continue;
  if (d.model === judge) continue; // a model never judges itself
  if (d.sample > 0) continue; // first sample only
  (answers[d.model] ??= {})[item] = d.answer;
}
const models = Object.keys(answers).sort();
console.log(`re-grading ${models.length} model(s) x ${set.items.length} item(s), judge ${judge}, protocol ${protocol}${batch ? ` batch ${batch}` : ''}, ${passes} pass(es)`);

for (let p = 0; p < passes; p++) {
  const dir = join(out, `${judge.replace(/[^\w.-]+/g, '_')}-${protocol}${batch ? `-b${batch}` : ''}-p${p}`);
  mkdirSync(dir, { recursive: true });
  for (const m of models) {
    const todo = Object.fromEntries(Object.entries(answers[m]).filter(([item]) => !existsSync(join(dir, `${item}-${m.replace(/[^\w.-]+/g, '_')}.json`))));
    if (!Object.keys(todo).length) continue;
    const r = await gradeAnswers({ set, answers: todo, judge, endpoint, apiKey, label: m, judgeProtocol: protocol, judgeBatch: batch, log: (l) => console.log(`  [p${p}] ${m}${l}`) });
    for (const it of r.items) {
      writeFileSync(join(dir, `${it.id}-${m.replace(/[^\w.-]+/g, '_')}.json`), JSON.stringify({ model: m, judge, protocol, batch, pass: p, answer: todo[it.id], judge_text: it.judge_text, detail: it.detail, score: it.score, ...(it.quotes_overturned != null ? { quotes_overturned: it.quotes_overturned, unmatched: it.unmatched, unmatched_wrong: it.unmatched_wrong } : {}) }, null, 1));
    }
  }
  console.log(`pass ${p} written to ${dir}`);
}
