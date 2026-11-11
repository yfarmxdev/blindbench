#!/usr/bin/env node
// BlindBench CLI. Run with no arguments for help.
import { readFileSync, writeFileSync, mkdirSync, existsSync, statSync, realpathSync } from 'node:fs';
import { join, dirname, basename } from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadSet, commitment, merkleProof, verifyProof, leafOf, loadSalts } from './lib/dataset.mjs';
import { runEval, verifyBundle, certificateMismatches, gradeAnswers } from './lib/runner.mjs';
import { servePolicy } from './lib/serve-policy.mjs';
import { view, call, toYocto, fromYocto, returnedId } from './lib/near.mjs';
import { quote } from './lib/intents.mjs';
import { parseArgs, pct, c, keyFor, intFlag } from './lib/util.mjs';
const tokensLine = (u) => (u ? `\n  tokens: model ${u.model.prompt_tokens} in / ${u.model.completion_tokens} out (${u.model.reasoning_tokens} reasoning)` + (u.judge.calls ? `, judge ${u.judge.prompt_tokens} in / ${u.judge.completion_tokens} out over ${u.judge.calls} calls` : '') : '');

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, '..');
const { pos, opt } = parseArgs(process.argv.slice(2));
const [cmd, ...rest] = pos;
const network = opt.network ?? process.env.NEAR_NETWORK ?? 'testnet';
const contract = opt.contract ?? process.env.BLINDBENCH_CONTRACT;
const endpoint = opt.endpoint ?? process.env.NEARAI_ENDPOINT ?? 'https://cloud-api.near.ai/v1';
let apiKey;
try { apiKey = keyFor(endpoint, process.env.NEARAI_API_KEY, { allowCustom: Boolean(opt['send-key-to-endpoint']) || process.env.NEARAI_KEY_ANY_ENDPOINT === '1' }); } catch (e) { console.error(c.r(e.message)); process.exit(1); }
const OUT = join(ROOT, '.blindbench');
// Keep what proves a run's signing keys: key proofs go next to the published
// evidence (web/attestations/), the full reports the certificate hashes stay local.
async function keepProofs(r) {
  if (!r.keyProofs?.length) return;
  const { saveProofs } = await import('./lib/attest.mjs');
  saveProofs(r.keyProofs);
  mkdirSync(join(OUT, 'attestations'), { recursive: true });
  for (const x of r.rawReports) writeFileSync(join(OUT, 'attestations', `${x.report_sha256}.json`), x.raw);
}
const need = (v, what) => { if (!v) { console.error(c.r(`missing ${what}`)); process.exit(2); } return v; };

// The certificate takes its model and root from the run, not from the evidence, so before
// anything is certified or paid out the evidence must be shown to be for that run.
async function mustBelongToRun(runId, { model, root, items, grading }) {
  const target = await view(network, need(contract, 'BLINDBENCH_CONTRACT'), 'get_run', { run_id: runId });
  if (!target) throw new Error(`run #${runId} does not exist on ${contract}`);
  const tds = await view(network, contract, 'get_dataset', { dataset_id: target.dataset_id });
  const wrong = [
    target.status !== 'Pending' && `run #${runId} is ${target.status}, not pending`,
    target.model !== model && `run #${runId} asked for ${target.model}, the evidence is for ${model}`,
    tds.root !== root && `run #${runId} is on dataset #${tds.id} (root ${tds.root.slice(0, 12)}…), the evidence is for root ${String(root).slice(0, 12)}…`,
    tds.items !== items && `dataset #${tds.id} has ${tds.items} items, the evidence has ${items}`,
    tds.grading !== grading && `dataset #${tds.id} is graded as ${tds.grading}, the evidence as ${grading}`,
  ].filter(Boolean);
  if (wrong.length) throw new Error(`not submitted: this evidence does not belong to that run\n  ${wrong.join('\n  ')}`);
}
// A bundle may be certified onchain only when every signing key in it has a valid hardware
// proof. --force lets other problems through; it never lets through evidence from the
// simulated enclave or a key with no proof.
function certifiable(v, { force = false } = {}) {
  v.problems.forEach((p) => console.log(c.r('  ' + p)));
  const why = v.hardware === 'simulated' ? 'this evidence came from the simulated enclave, which only the local demo ledger accepts'
    : v.hardware !== 'proven' ? 'a signing key in this evidence has no valid hardware proof'
    : v.problems.length && !force ? 'the bundle has problems (--force overrides these, not a missing hardware proof)' : null;
  if (why) { console.error(c.r(`not submitted: ${why}`)); process.exitCode = 1; }
  return !why;
}

const HELP = `
${c.b('BlindBench')}: private AI evals, scored in a NEAR AI TEE, certified on NEAR.

  ${c.b('npm run demo')}                              full flow offline, no keys (simulated TEE + local ledger)
  web      [--port 8080]                       serve the web page (live contract, or the demo with ?snapshot=)

  commit   <set.jsonl> --price <NEAR>          commit a private set (only its Merkle root goes onchain)
  request  <dataset_id> <model> --deposit <NEAR> pay for a model to be scored
  run      <set.jsonl> --model <id> [--judge <id> --alt-judge <id>] [--samples k] [--judge-passes j] [--judge-protocol v2 --judge-batch b] [--run-id <n> --submit]
                                               score a model in the TEE; with --submit, fulfil the run onchain
                                               (--alt-judge grades when the model under test is the judge)
  serve    <set.jsonl> --dataset-id <n> [--judge <id> --alt-judge <id>] [--samples k] [--judge-passes j]
           --models a,b --max-runs n [--requesters x.near,y.near --max-per-requester n --max-tries n --reset-limits]
                                               fulfil pending paid runs for a set you hold. --models and --max-runs
                                               are required: each run spends your inference credit. A failed run is
                                               not retried unless --max-tries says so; counts survive a restart
  grade    <set.jsonl> --answers <dir> [--judge <id>]
                                               score answers made elsewhere (a closed reference model) with the
                                               same grader; a report, never a certificate
  leaderboard <dataset_id>                     read certificates from NEAR (no account needed)
  cert     <certificate_id>                    show one certificate
  datasets                                     list committed datasets
  submit   <evidence.json> --run-id <n>        certify a run from an evidence bundle made earlier
  verify   <evidence.json> [--cert <id>]       recheck every enclave signature, the Merkle root and the score;
                                               with --cert, compare all of it with the onchain certificate
  verify   --cert <id>                         the same, using the evidence published under web/evidence/
  verify   --all                               every certificate on the contract that has published evidence
  attest   [--model <id>] [--save] [--offline] check the hardware proof of a NEAR AI Cloud enclave, live and with no
                                               key: Intel TDX quote to Intel's root, key and nonce binding, Intel's
                                               TCB verdict, NVIDIA's GPU verdict; --save publishes the key proof
  prove    <set.jsonl> <item_id>               reveal ONE item with a Merkle proof (dispute resolution)
  check-proof <proof.json> --root <hex>        verify a revealed item against a committed root
  pay-quote --from <1Click assetId> --amount <units> --recipient <near account> --refund-to <addr>
                                               NEAR Intents quote: any chain asset -> NEAR for request_run (dry)

  env: NEARAI_API_KEY, BLINDBENCH_CONTRACT, NEAR_NETWORK (testnet), NEAR_ACCOUNT_ID, NEAR_PRIVATE_KEY, NEAR_RPC_URL
       NEARAI_ENDPOINT or --endpoint <url> picks another inference endpoint; the API key is sent
       only to cloud-api.near.ai or localhost unless --send-key-to-endpoint is given
`;

function printBoard(rows, datasets = {}) {
  if (!rows.length) return console.log(c.d('  (no certificates yet)'));
  const wide = Math.max(28, ...rows.map((r) => r.model.length));
  rows.forEach((r, i) => {
    const bar = '█'.repeat(Math.round(r.score_bps / 500)).padEnd(20, '·');
    const tee = r.tee ? c.g('TEE-signed ' + r.tee.signed_responses + '/' + r.items) : c.y('no TEE');
    console.log(`  ${String(i + 1).padStart(2)}. ${r.model.padEnd(wide)} ${bar} ${pct(r.score_bps).padStart(7)}  ${tee}  cert #${r.id}`);
  });
}

async function cmdDemo() {
  const { startMock } = await import('./mock/tee-server.mjs');
  const { Ledger } = await import('./lib/ledger.mjs');
  const mock = await startMock(0);
  const L = new Ledger();
  mkdirSync(join(OUT, 'evidence'), { recursive: true });
  const say = (s) => console.log(s);
  say(c.b('\nBlindBench demo') + c.d('  (offline: SIMULATED NEAR AI enclave + local ledger; see README for the live testnet path)\n'));

  const sets = ['ledger-arithmetic', 'smart-contract-bugs', 'contract-drafting', 'privacy-chain-tracing'].map((n) => loadSet(join(ROOT, 'examples', `${n}.jsonl`)));
  const ids = [];
  say(c.b('1. Experts commit private eval sets. Only a Merkle root goes onchain.'));
  for (const set of sets) {
    const com = commitment(set);
    const id = L.commit_dataset('expert.near', { root: com.root, items: com.items, description: set.meta.description, price: 0.5, grading: com.grading });
    ids.push(id);
    say(`   dataset #${id}  ${set.meta.name.padEnd(42)} ${com.grading.padEnd(9)} root ${com.root.slice(0, 16)}…  0.5 NEAR/run`);
  }
  L.post_bounty('sponsor.near', { dataset_id: ids[1], threshold_bps: 8000 }, 10);
  say(`   bounty: ${c.b('10 NEAR')} to the first model scoring ≥ 80% on dataset #${ids[1]}\n`);

  say(c.b('2. Model builders pay to be scored, then the runner scores each model inside the enclave.'));
  const models = ['demo/strong', 'demo/medium', 'demo/weak'];
  for (const [si, set] of sets.entries()) {
    for (const model of models) {
      const runId = L.request_run(`${model.split('/')[1]}-lab.near`, { dataset_id: ids[si], model }, 0.5);
      const judge = ['exact', 'tests'].includes(set.meta.grading) ? undefined : 'demo/judge';
      const r = await runEval({ set, model, endpoint: mock.url, judge });
      const ver = await verifyBundle(r.bundle);
      const file = join(OUT, 'evidence', `ds${ids[si]}-${model.replace('/', '_')}.json`);
      writeFileSync(file, JSON.stringify(r.bundle, null, 1));
      const { id, won } = L.fulfill_run('expert.near', { run_id: runId, score_bps: r.score_bps, evidence_hash: r.evidence_hash, tee: r.tee, judge_model: judge, breakdown: r.breakdown });
      say(`   #${ids[si]} ${model.padEnd(12)} ${pct(r.score_bps).padStart(7)}  ${ver.valid}/${ver.total} answers enclave-signed ${ver.problems.length ? c.r('✗') : c.g('✓')}  cert #${id}  evidence ${r.evidence_hash.slice(0, 12)}…`);
      for (const b of won) say(c.g(`      🏆 bounty #${b.id} won: ${b.reward} NEAR to ${b.winner}`));
    }
  }

  say(c.b('\n3. Leaderboards (what the contract\'s leaderboard() returns):'));
  for (const [si, set] of sets.entries()) {
    say(`   ${set.meta.name}`);
    printBoard(L.leaderboard(ids[si]));
  }
  say(c.b('\n4. The expert earned without revealing a single question:'));
  say(`   expert.near: ${L.balances['expert.near']} NEAR from ${L.runs.length} paid runs`);

  say(c.b('\n5. Anyone can recheck a certificate from its evidence bundle:'));
  const file = join(OUT, 'evidence', `ds${ids[1]}-demo_strong.json`);
  const bundle = JSON.parse(readFileSync(file, 'utf8'));
  const v = await verifyBundle(bundle);
  const cert = L.certificates.find((x) => x.dataset_id === ids[1] && x.model === 'demo/strong');
  say(`   ${basename(file)}: ${v.valid}/${v.total} signatures recover to the attested enclave key, hash ${v.evidence_hash === cert.evidence_hash ? c.g('matches cert #' + cert.id) : c.r('DOES NOT match')}`);
  say(`   the bundle holds hashes and signatures only. grep it for a question and you will not find one.`);

  say(c.b('\n6. Dispute? The owner can reveal ONE item with a Merkle proof, keeping the rest secret:'));
  const set = sets[0];
  const com = commitment(set);
  const { salts } = loadSalts(set);
  const proof = merkleProof(com.leaves, 2);
  const ok = verifyProof(leafOf(set.items[2], salts[set.items[2].id]), proof, com.root);
  say(`   item "${set.items[2].id}" + salt + ${proof.length}-step proof ${ok ? c.g('verifies against root ' + com.root.slice(0, 16) + '…') : c.r('FAILS')}`);
  // Snapshot of the local ledger in the contract's view shapes, for the web page.
  const certFiles = {};
  for (const [si] of sets.entries()) for (const model of models) {
    const cert = L.certificates.find((x) => x.dataset_id === ids[si] && x.model === model);
    if (cert) certFiles[cert.id] = `ds${ids[si]}-${model.replace('/', '_')}.json`;
  }
  const snap = {
    simulated: true,
    stats: [L.datasets.length, L.runs.length, L.certificates.length],
    datasets: L.datasets.map((d) => ({ ...d, price: toYocto(d.price), earned: toYocto(d.earned), reveal_uri: null })),
    leaderboards: Object.fromEntries(ids.map((id) => [id, L.leaderboard(id).map((x) => ({ ...x, runner: 'expert.near', evidence_url: `/local/evidence/${certFiles[x.id]}` }))])),
    bounties: L.bounties.map((b) => ({ ...b, reward: toYocto(b.reward), winning_certificate: b.winning_certificate ?? null })),
  };
  writeFileSync(join(OUT, 'demo-snapshot.json'), JSON.stringify(snap, null, 1));
  say(c.d(`\nEvidence bundles written to ${join(OUT, 'evidence')}/`));
  say(c.d(`See it in the browser: node blindbench.mjs web, then open http://localhost:8080/?snapshot=/local/demo-snapshot.json`));
  mock.server.close();
}

async function main() {
  switch (cmd) {
    case 'demo': return cmdDemo();

    case 'web': {
      // Static server for the web page (web/) and the local demo output (/local -> .blindbench/).
      const { createServer } = await import('node:http');
      const { extname, resolve, sep } = await import('node:path');
      const types = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.mjs': 'text/javascript', '.json': 'application/json', '.md': 'text/plain; charset=utf-8', '.png': 'image/png', '.svg': 'image/svg+xml' };
      const port = intFlag(opt.port ?? 8080, '--port', { min: 1, max: 65535 });
      const roots = [['/local/', resolve(OUT)], ['/', resolve(ROOT, 'web')]];
      // The same response headers the hosted page gets (web/_headers, the block for every path),
      // so the content security policy is in force when the page is tried here. The HTTPS-only
      // header is left out: this server speaks plain HTTP to this machine.
      const hosted = {};
      { const lines = readFileSync(resolve(ROOT, 'web', '_headers'), 'utf8').split('\n'); let on = false;
        for (const l of lines) { if (!/^\s/.test(l)) { on = l.trim() === '/*'; continue; } const m = on && /^\s+([A-Za-z-]+):\s*(.+?)\s*$/.exec(l); if (m && m[1] !== 'Strict-Transport-Security') hosted[m[1]] = m[2]; } }
      createServer((req, res) => {
        // A malformed request gets a 400 or 404; it must never stop the server.
        try {
          const path = decodeURIComponent(new URL(req.url, 'http://x').pathname);
          const [prefix, dir] = roots.find(([p]) => path.startsWith(p));
          // .blindbench also holds run evidence, serve counts and debug output: only the demo's files are served.
          if (prefix === '/local/' && !/^(demo-snapshot\.json|evidence\/[A-Za-z0-9._-]+\.json)$/.test(path.slice(prefix.length))) { res.writeHead(404); return res.end('not found'); }
          const file = resolve(dir, '.' + sep + (path.slice(prefix.length) || 'index.html'));
          // The real path must stay inside the folder too, so a symlink cannot lead out of it.
          const inside = (f, d) => f === d || f.startsWith(d + sep);
          if (!inside(file, dir) || !existsSync(file) || !statSync(file).isFile() || !inside(realpathSync(file), realpathSync(dir))) { res.writeHead(404); return res.end('not found'); }
          res.writeHead(200, { ...hosted, 'Content-Type': types[extname(file)] ?? 'application/octet-stream', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' });
          res.end(readFileSync(file));
        } catch { if (!res.headersSent) res.writeHead(400); res.end('bad request'); }
      }).listen(port, '127.0.0.1', () => console.log(`BlindBench web on http://localhost:${port}/  (live testnet contract)\n  local demo: http://localhost:${port}/?snapshot=/local/demo-snapshot.json  (run "node blindbench.mjs demo" first)`));
      return new Promise(() => {});
    }

    case 'commit': {
      const set = loadSet(need(rest[0], '<set.jsonl>'));
      const com = commitment(set);
      const price = toYocto(opt.price ?? '0.1');
      console.log(`root ${com.root} | ${com.items} items | ${com.grading}`);
      console.log(c.d(`salts kept privately in ${set.path.replace(/\.jsonl$/, '')}.salts.json (never commit it)`));
      // The contract takes at most 280 bytes. Refuse a longer one here rather than cut it mid-sentence.
      const description = String(set.meta.description ?? '');
      const bytes = Buffer.byteLength(description);
      if (bytes > 280) throw new Error(`_meta.description is ${bytes} bytes; the contract allows 280. Shorten it and commit again.`);
      if (opt['dry-run']) return;
      const r = await call(network, need(contract, 'BLINDBENCH_CONTRACT'), 'commit_dataset', {
        root: com.root, items: com.items, description, price, grading: com.grading,
        require_tee: !opt['allow-non-tee'],
      });
      return console.log(c.g(`dataset #${returnedId(r, 'commit_dataset')} committed`) + `  ${r.url}`);
    }

    case 'request': {
      const r = await call(network, need(contract, 'BLINDBENCH_CONTRACT'), 'request_run',
        { dataset_id: intFlag(need(rest[0], '<dataset_id>'), '<dataset_id>'), model: need(rest[1], '<model>') }, { deposit: toYocto(need(opt.deposit, '--deposit')) });
      return console.log(c.g(`run #${returnedId(r, 'request_run')} requested`) + `  ${r.url}`);
    }

    case 'grade': {
      // Grade answers made outside BlindBench (a closed reference model, say)
      // with the same TEE judge. Prints a report; never a certificate.
      const set = loadSet(need(rest[0], '<set.jsonl>'));
      const dir = need(opt.answers, '--answers <dir with <item-id>.md files>');
      if (!apiKey && endpoint.includes('near.ai')) need(null, 'NEARAI_API_KEY');
      const answers = {};
      for (const it of set.items) for (const f of [`${it.id}.md`, `${it.id}.answer.md`, `${it.id}.txt`]) if (existsSync(join(dir, f))) { answers[it.id] = readFileSync(join(dir, f), 'utf8'); break; }
      const label = opt.label ?? basename(dir);
      console.log(`grading ${Object.keys(answers).length}/${set.items.length} answers from ${dir} as "${label}" (reference only, not certified)`);
      const r = await gradeAnswers({ set, answers, judge: opt.judge, endpoint, apiKey, label, log: console.log, judgePasses: intFlag(opt['judge-passes'] ?? 1, '--judge-passes', { min: 1 }), judgeProtocol: opt['judge-protocol'], ...(opt['judge-batch'] != null ? { judgeBatch: intFlag(opt['judge-batch'], '--judge-batch', { min: 1 }) } : {}) });
      const file = opt.out ?? join(dir, `grade-${basename(rest[0]).replace(/\.jsonl$/, '')}.json`);
      writeFileSync(file, JSON.stringify(r, null, 1));
      return console.log(`\n${label}: ${pct(Math.round(r.score * 10000))} over ${r.items.length} item(s), judged by ${opt.judge}\n  ${file}`);
    }

    case 'run': {
      const set = loadSet(need(rest[0], '<set.jsonl>'));
      const model = need(opt.model, '--model');
      if (!apiKey && endpoint.includes('near.ai')) need(null, 'NEARAI_API_KEY');
      // --submit: check that this set and model are what the run asked for before any inference credit is spent.
      const submitTo = opt.submit ? intFlag(need(opt['run-id'], '--run-id <n>'), '--run-id') : null;
      if (opt.submit) { const com = commitment(set); await mustBelongToRun(submitTo, { model, root: com.root, items: com.items, grading: com.grading }); }
      const r = await runEval({ set, model, endpoint, apiKey, judge: opt.judge, altJudge: opt['alt-judge'], log: console.log, ...(opt['max-tokens'] != null ? { maxTokens: intFlag(opt['max-tokens'], '--max-tokens', { min: 1 }) } : {}), thinking: !opt['no-think'],
        samples: intFlag(opt.samples ?? 1, '--samples', { min: 1 }), judgePasses: intFlag(opt['judge-passes'] ?? 1, '--judge-passes', { min: 1 }), judgeProtocol: opt['judge-protocol'], ...(opt['judge-batch'] != null ? { judgeBatch: intFlag(opt['judge-batch'], '--judge-batch', { min: 1 }) } : {}) });
      mkdirSync(join(OUT, 'evidence'), { recursive: true });
      const file = join(OUT, 'evidence', `${basename(set.path, '.jsonl')}-${model.replace(/\W+/g, '_')}-${Date.now()}.json`);
      await keepProofs(r);
      writeFileSync(file, JSON.stringify(r.bundle, null, 1));
      const eb = r.stats?.rerun_se_bps != null ? ` ±${pct(Math.round(1.96 * r.stats.rerun_se_bps))} rerun, ±${pct(Math.round(1.96 * r.stats.item_se_bps))} items (95%, k=${r.stats.samples})` : '';
      console.log(c.b(`\n${model}: ${pct(r.score_bps)}`) + eb + (r.breakdown.length ? `  (${r.breakdown.map((t) => `${t.label} ${pct(t.score_bps)}`).join(', ')})` : '') + `  signed ${r.signed}/${r.items}` + (r.empty ? c.y(`  empty ${r.empty}`) : '') + (r.retried ? `  retried-without-thinking ${r.retried}` : '') + `  evidence ${r.evidence_hash}\n  ${file}` + tokensLine(r.usage));
      if (opt.submit) {
        // The same gate as `submit`: the bundle just written must verify, rest on hardware-backed keys, and still belong to the run.
        const v = await verifyBundle(r.bundle);
        if (!certifiable(v)) return;
        await mustBelongToRun(submitTo, { model: r.bundle.model, root: r.bundle.dataset_root, items: v.items, grading: r.bundle.grading });
        const out = await call(network, need(contract, 'BLINDBENCH_CONTRACT'), 'fulfill_run', { input: {
          run_id: submitTo, score_bps: r.score_bps, evidence_hash: r.evidence_hash, tee: r.tee, judge_model: r.judge_model, breakdown: r.breakdown.length ? r.breakdown : null } });
        console.log(c.g(`certificate #${returnedId(out, 'fulfill_run')} issued`) + `  ${out.url}`);
      }
      return;
    }

    case 'serve': {
      const set = loadSet(need(rest[0], '<set.jsonl>'));
      const dsId = intFlag(need(opt['dataset-id'], '--dataset-id'), '--dataset-id');
      const me = need(process.env.NEAR_ACCOUNT_ID, 'NEAR_ACCOUNT_ID');
      const root = commitment(set).root;
      const ds = await view(network, need(contract, 'BLINDBENCH_CONTRACT'), 'get_dataset', { dataset_id: dsId });
      if (!ds) throw new Error(`no dataset #${dsId} on ${contract}`);
      if (ds.root !== root) throw new Error(`local set root ${root} != onchain root ${ds.root}`);
      // Every fulfilled run spends the operator's inference credit: see lib/serve-policy.mjs.
      // The counts are kept on disk per network, contract and set, so restarting does not hand out a fresh allowance.
      const stateFile = join(OUT, `serve-${network}-${contract}-${dsId}.json`.replace(/[^A-Za-z0-9._-]/g, '_'));
      let state = null;
      if (opt['reset-limits']) console.log(c.y('  --reset-limits: starting the run counts from zero'));
      else if (existsSync(stateFile)) { try { state = JSON.parse(readFileSync(stateFile, 'utf8')); } catch { throw new Error(`${stateFile} is not readable JSON; fix or delete it, or pass --reset-limits`); } }
      const policy = servePolicy(opt, { state, save: (s) => { mkdirSync(OUT, { recursive: true }); writeFileSync(stateFile, JSON.stringify(s)); } });
      console.log(`serving dataset #${dsId} as ${me}; polling every 30s\n  limits: ${policy.describe()}\n  counts kept in ${stateFile}`);
      for (;;) {
        const pending = (await view(network, contract, 'list_pending_runs', { runner: me })).filter((r) => r.dataset_id === dsId);
        for (const run of pending) {
          const why = policy.refuse(run);
          if (why) { if (policy.firstTime(run, why)) console.log(c.d(`run #${run.id} left pending: ${why}`)); continue; }
          policy.start(run);
          console.log(`run #${run.id}: ${run.model} for ${run.requester}`);
          // One failed run (an unknown model id, a provider outage) must not stop the others.
          // It stays pending and is not tried again unless --max-tries allows it; the
          // requester can cancel after 24 hours.
          try {
            const r = await runEval({ set, model: run.model, endpoint, apiKey, judge: opt.judge, altJudge: opt['alt-judge'], log: console.log, ...(opt['max-tokens'] != null ? { maxTokens: intFlag(opt['max-tokens'], '--max-tokens', { min: 1 }) } : {}), thinking: !opt['no-think'],
              samples: intFlag(opt.samples ?? 1, '--samples', { min: 1 }), judgePasses: intFlag(opt['judge-passes'] ?? 1, '--judge-passes', { min: 1 }), judgeProtocol: opt['judge-protocol'], ...(opt['judge-batch'] != null ? { judgeBatch: intFlag(opt['judge-batch'], '--judge-batch', { min: 1 }) } : {}) });
            // Evidence goes to disk before the certificate goes onchain, so it cannot be lost in between.
            mkdirSync(OUT, { recursive: true });
            writeFileSync(join(OUT, `run-${run.id}.evidence.json`), JSON.stringify(r.bundle, null, 1));
            await keepProofs(r);
            // The same gate as `submit`: nothing is certified unless the bundle verifies on hardware-backed keys.
            if (!certifiable(await verifyBundle(r.bundle))) throw new Error('the evidence did not pass verification; it is kept on disk and the run stays pending');
            const out = await call(network, contract, 'fulfill_run', { input: { run_id: run.id, score_bps: r.score_bps, evidence_hash: r.evidence_hash, tee: r.tee, judge_model: r.judge_model, breakdown: r.breakdown.length ? r.breakdown : null } });
            console.log(c.g(`  certificate #${returnedId(out, 'fulfill_run')}: ${pct(r.score_bps)}`) + `  ${out.url}`);
          } catch (e) { console.error(c.r(`  run #${run.id} not fulfilled: ${e.message}`)); }
        }
        await new Promise((ok) => setTimeout(ok, 30000));
      }
    }

    case 'leaderboard': {
      const id = intFlag(need(rest[0], '<dataset_id>'), '<dataset_id>');
      const ds = await view(network, need(contract, 'BLINDBENCH_CONTRACT'), 'get_dataset', { dataset_id: id });
      if (!ds) throw new Error(`no dataset #${id} on ${contract}`);
      console.log(c.b(`dataset #${id}`) + `  ${ds.description}\n  root ${ds.root} | ${ds.items} items | ${ds.grading} | ${fromYocto(ds.price)} NEAR/run | earned ${fromYocto(ds.earned)} NEAR`);
      return printBoard(await view(network, contract, 'leaderboard', { dataset_id: id }));
    }
    case 'cert': {
      const id = intFlag(need(rest[0], '<certificate_id>'), '<certificate_id>');
      const cert = await view(network, need(contract, 'BLINDBENCH_CONTRACT'), 'get_certificate', { certificate_id: id });
      if (!cert) throw new Error(`no certificate #${id} on ${contract}`);
      return console.log(JSON.stringify(cert, null, 2));
    }
    case 'datasets': {
      for (const d of await view(network, need(contract, 'BLINDBENCH_CONTRACT'), 'list_datasets', {})) {
        console.log(`#${d.id}  ${d.grading.padEnd(9)} ${String(d.items).padStart(4)} items  ${fromYocto(d.price)} NEAR  ${d.runs_completed} runs  ${d.description}`);
      }
      return;
    }

    // Grade a finished exact-graded run again inside a TEE (OutLayer), one item per
    // execution, from the signed bodies the runner kept (BLINDBENCH_BODIES_DIR).
    case 'seal-grade': {
      const { jobFor, seal, runLocal, receiptMismatches, GRADER_WASM } = await import('./lib/sealed.mjs');
      const { execute } = await import('./lib/outlayer.mjs');
      const { sha256 } = await import('./lib/util.mjs');
      const set = loadSet(need(rest[0], '<set.jsonl>'));
      const bundle = JSON.parse(readFileSync(need(opt.evidence, '--evidence <bundle.json>'), 'utf8'));
      const bodies = need(opt.bodies, '--bodies <dir>'), key = need(process.env.BLINDBENCH_GRADER_KEY, 'BLINDBENCH_GRADER_KEY (the input key stored as the grader\'s secret)');
      const pinned = JSON.parse(readFileSync(join(ROOT, 'grader', 'grader.json'), 'utf8'));
      // --local: run the pinned .wasm on this machine only (no enclave, no transaction), to check a bundle before paying.
      const wasmUrl = opt.local ? null : need(opt['wasm-url'], '--wasm-url <public URL of grader/blindbench-grader.wasm>');
      const secrets = opt.local ? null : { account: opt['secrets-account'] ?? need(process.env.NEAR_ACCOUNT_ID, 'NEAR_ACCOUNT_ID'), profile: opt['secrets-profile'] ?? 'blindbench' };
      if (bundle.grading !== 'exact') throw new Error('sealed grading covers exact-graded sets');
      if (commitment(set).root !== bundle.dataset_root) throw new Error('this set is not the one the evidence was made on');
      const salts = loadSalts(set, { create: false }).salts, v = await verifyBundle(bundle), evidence_hash = v.evidence_hash;
      const outFile = join(ROOT, 'web', 'grading', `${evidence_hash}.json`);
      const done = existsSync(outFile) ? JSON.parse(readFileSync(outFile, 'utf8')) : { version: 'blindbench-grading/1', evidence_hash, network, contract: null, grader: pinned.grader, wasm_sha256: pinned.wasm_sha256, wasm_url: wasmUrl, secrets, receipts: [] };
      mkdirSync(dirname(outFile), { recursive: true });
      for (const it of bundle.items) {
        if (done.receipts.some((r) => r.index === it.index && (r.sample ?? 0) === (it.sample ?? 0))) continue;
        const f = join(bodies, `${it.response_sha256}.json`);
        if (!existsSync(f)) throw new Error(`no kept bodies for item ${it.index} (${f})`);
        const { request, response } = JSON.parse(readFileSync(f, 'utf8'));
        const sealed = seal(jobFor({ item: set.items[it.index], salt: salts[set.items[it.index].id], request, response }), key);
        // Parity first: the same .wasm on this machine must agree with the evidence before anything is paid for.
        const local = receiptMismatches(await runLocal(sealed, { wasm: GRADER_WASM, env: { INPUT_KEY: key } }), it, bundle.model);
        if (local.length) throw new Error(`item ${it.index}: the grader disagrees with the evidence before the enclave run: ${local.join('; ')}`);
        if (opt.local) { console.log(`  item ${it.index}: ${c.g('✓')} local grader agrees with the evidence`); continue; }
        const ex = await execute(network, { wasmUrl, wasmSha256: pinned.wasm_sha256, input: sealed, secrets }, { deposit: toYocto(opt.deposit ?? '1') });
        const bad = receiptMismatches(ex.output, it, bundle.model);
        console.log(`  item ${it.index}: ${bad.length ? c.r('✗ ' + bad.join('; ')) : c.g('✓') + ` enclave score ${ex.output.score}, leaf and signed hashes match`}  ${ex.url}`);
        if (bad.length) throw new Error(`item ${it.index}: the enclave's receipt does not match the evidence`);
        done.receipts.push({ index: it.index, ...(it.sample != null ? { sample: it.sample } : {}), tx: ex.tx, signer: ex.signer, input_sha256: sha256(JSON.stringify(sealed)), output: ex.output });
        writeFileSync(outFile, JSON.stringify(done, null, 1));
      }
      if (opt.local) { console.log(c.y(`${bundle.items.length} items checked with the grader on this machine: nothing ran in an enclave`)); return; }
      console.log(c.g(`${done.receipts.length}/${bundle.items.length} items graded in the enclave`) + c.d(`  receipts: web/grading/${evidence_hash}.json`));
      return;
    }

    case 'attest': {
      const { fetchReport, proveReport, saveProofs } = await import('./lib/attest.mjs');
      const models = opt.model ? String(opt.model).split(',') : [null];
      for (const model of models) {
        const { report, nonce, report_sha256 } = await fetchReport({ endpoint, apiKey, model });
        console.log(c.b(`\n${model ?? 'gateway'}`) + c.d(`  report sha256 ${report_sha256}, our nonce ${nonce.slice(0, 16)}…`));
        if (report.simulated) { console.log(c.y('  this endpoint is the SIMULATED enclave: it has no hardware quote')); process.exitCode = 1; continue; }
        const { proofs, lines } = await proveReport(report, { nonce, model, online: !opt.offline });
        for (const { role, model: name, rec, gpu, notes } of lines) {
          const ok = c.g('✓');
          console.log(`  ${c.b(role === 'gateway' ? 'gateway enclave' : `model enclave (${name})`)}  key ${rec.signing_address}`);
          console.log(`    ${ok} Intel TDX quote: signed by the attestation key, certified by the Quoting Enclave, PCK chain ends at Intel's SGX Root CA`);
          console.log(`    ${ok} the quote binds this signing key and our fresh nonce; the TD is not in debug mode`);
          console.log(`    ${rec.compose_bound ? ok : c.r('✗')} MRCONFIGID names the compose file (sha256 ${rec.compose_hash}), ${rec.images.length} images pinned by digest`);
          console.log(`    ${rec.rtmr_replayed?.slice(0, 3).every(Boolean) ? ok : c.y('!')} boot event log replays to RTMR0-2${rec.rtmr_replayed?.[3] ? ' and RTMR3' : c.d(' (RTMR3 is extended at run time by events the report does not list)')}`);
          if (rec.tcb) console.log(`    ${rec.tcb.tcb_status === 'UpToDate' ? ok : c.y('!')} Intel collateral (signed by Intel): platform TCB ${rec.tcb.tcb_status}, Quoting Enclave ${rec.tcb.qe_status}${rec.tcb.advisories.length ? ', advisories ' + rec.tcb.advisories.join(' ') : ''}`);
          if (gpu) console.log(`    ${ok} NVIDIA attestation service: ${gpu.gpus} GPUs (${gpu.arch}) pass, token signed by NVIDIA, same nonce`);
          notes.forEach((n) => console.log(c.y('    ! ' + n)));
          console.log(c.d(`    MRTD ${rec.mrtd.slice(0, 32)}…  app ${rec.app_id}  os image ${rec.os_image_hash?.slice(0, 16)}…`));
        }
        for (const m of (report.model_attestations ?? []).filter((x) => !x.intel_quote)) console.log(c.d(`  ${m.model ?? model}: runs in a third-party TEE (${m.provider}); the attested gateway checked it (verified ${m.verified}, TCB ${m.tcb_status}, GPUs ${m.gpu_verdict}) and signs its answers`));
        if (opt.save) { saveProofs(proofs); console.log(c.d(`  saved ${proofs.length} key proof(s) under web/attestations/`)); }
      }
      return;
    }

    case 'verify': {
      // --all: every certificate on the contract whose evidence is published in this repo.
      if (opt.all) {
        // The contract returns at most 100 certificates per call: read page after page until one comes back short.
        const certs = [];
        for (;;) {
          const page = await view(network, need(contract, 'BLINDBENCH_CONTRACT'), 'list_certificates', { from_index: certs.length, limit: 100 });
          certs.push(...page);
          if (page.length < 100) break;
        }
        let ok = 0, bad = 0, missing = 0;
        for (const cert of certs) {
          const file = join(ROOT, 'web', 'evidence', `${cert.evidence_hash}.json`);
          if (!existsSync(file)) { missing += 1; console.log(c.d(`  #${cert.id} ${cert.model}: evidence not published`)); continue; }
          const bundle = JSON.parse(readFileSync(file, 'utf8')), v = await verifyBundle(bundle), diff = certificateMismatches(cert, bundle, v);
          const good = !v.problems.length && !diff.length && v.hardware === 'proven';
          good ? ok++ : bad++;
          console.log(`  ${good ? c.g('✓') : c.r('✗')} #${cert.id} ${cert.model}, ${pct(cert.score_bps)} on dataset #${cert.dataset_id}: ${v.valid}/${v.total} signatures, ${v.keys.filter((k) => k.ok).length}/${v.keys.length} key quote${v.keys.length === 1 ? '' : 's'} valid, ${good ? 'matches the chain' : [...v.problems, ...diff].join('; ')}`);
        }
        console.log(`${ok} of ${certs.length} certificates verified against their evidence, the chain and Intel TDX quotes${bad ? c.r(`, ${bad} FAILED`) : ''}${missing ? c.d(`, ${missing} without published evidence`) : ''}`);
        if (bad || !ok) process.exitCode = 1;
        return;
      }
      // With --cert and no file, use the evidence published in this repo for that certificate.
      let cert = null, file = rest[0];
      if (opt.cert !== undefined) {
        cert = await view(network, need(contract, 'BLINDBENCH_CONTRACT'), 'get_certificate', { certificate_id: intFlag(opt.cert, '--cert') });
        if (!cert) throw new Error(`no certificate #${opt.cert} on ${contract}`);
        if (!file) {
          file = join(ROOT, 'web', 'evidence', `${cert.evidence_hash}.json`);
          if (!existsSync(file)) throw new Error(`no published evidence for certificate #${opt.cert} (looked for web/evidence/${cert.evidence_hash}.json); pass the evidence file`);
          console.log(c.d(`certificate #${opt.cert}: ${cert.model}, ${pct(cert.score_bps)} on dataset #${cert.dataset_id}; evidence web/evidence/${cert.evidence_hash}.json`));
        }
      }
      const bundle = JSON.parse(readFileSync(need(file, '<evidence.json>'), 'utf8'));
      const v = await verifyBundle(bundle);
      console.log(`${v.valid}/${v.total} enclave signatures valid | evidence hash ${v.evidence_hash}`);
      for (const k of v.keys) console.log(k.ok
        ? `  ${k.warn ? c.y('!') : c.g('✓')} ${k.of === 'judge' ? 'judge\'s ' : ''}${k.role === 'model' ? 'model-enclave' : 'gateway'} key ${k.address}: Intel TDX quote validated for this address, checked to Intel's root (TCB ${k.proof.tcb?.tcb_status}, proof recorded ${String(k.proof.fetched_at).slice(0, 10)}; role${k.role === 'model' ? ' and model name' : ''} as listed in the proof registry)${k.warn ? c.y(`\n      ${k.warn}`) : ''}`
        : `  ${c.r('✗')} ${k.of === 'judge' ? 'judge\'s ' : ''}signing key ${k.address} is NOT hardware-backed: ${k.why}`);
      console.log(`  ${v.root_ok ? c.g('✓') : c.r('✗')} ${v.items} item leaves ${v.root_ok ? 'hash up to' : 'do NOT hash up to'} dataset root ${bundle.dataset_root}`);
      if (v.judge.total) console.log(`  ${v.judge.valid === v.judge.total ? c.g('✓') : c.y('!')} ${v.judge.valid}/${v.judge.total} judge calls signed by a key declared for ${bundle.judge_model}`);
      v.problems.filter((p) => !p.includes('is not hardware-backed')).forEach((p) => console.log(c.r('  ' + p)));
      if (bundle.attestation.simulated) console.log(c.y('  note: this bundle came from the SIMULATED enclave, so its signing key has no hardware quote'));
      if (cert) {
        const diff = certificateMismatches(cert, bundle, v);
        console.log(diff.length ? c.r(`does NOT match certificate #${opt.cert}`) : c.g(`matches onchain certificate #${opt.cert}`) + c.d('  (evidence hash, root, model, score, items, signed answers, attestation)'));
        diff.forEach((d) => console.log(c.r('  ' + d)));
        if (diff.length) process.exitCode = 1;
      }
      if (v.problems.length) process.exitCode = 1;
      return;
    }

    // Submit an evidence bundle that was produced earlier (the runner holds the set, so a
    // run can be graded offline and certified later). The bundle is re-verified first: a
    // bundle whose signatures do not check out is never sent onchain.
    case 'submit': {
      const file = need(rest[0], '<evidence.json>');
      const bundle = JSON.parse(readFileSync(file, 'utf8'));
      const v = await verifyBundle(bundle);
      console.log(`${v.valid}/${v.total} enclave signatures valid | evidence hash ${v.evidence_hash}`);
      if (!certifiable(v, { force: opt.force })) return;
      const runId = intFlag(need(opt['run-id'], '--run-id <n>'), '--run-id');
      // The certificate takes its model and root from the run, not from the evidence,
      // so check that this evidence is for this run before anything is paid out.
      await mustBelongToRun(runId, { model: bundle.model, root: bundle.dataset_root, items: v.items, grading: bundle.grading });
      const out = await call(network, need(contract, 'BLINDBENCH_CONTRACT'), 'fulfill_run', { input: {
        run_id: runId,
        score_bps: bundle.score_bps,
        evidence_hash: v.evidence_hash,
        judge_model: bundle.judge_model ?? null,
        tee: { signing_address: bundle.attestation.signing_addresses[0], signing_algo: bundle.attestation.signing_algo ?? 'ecdsa', attestation_hash: bundle.attestation.report_sha256, signed_responses: v.signed_items },
        breakdown: bundle.breakdown?.length ? bundle.breakdown : null,
      } });
      console.log(c.g(`certificate #${returnedId(out, 'fulfill_run')} issued`) + `  ${out.url}`);
      return;
    }

    case 'prove': {
      const set = loadSet(need(rest[0], '<set.jsonl>'));
      const idx = set.items.findIndex((it) => it.id === rest[1]);
      if (idx < 0) throw new Error(`no item ${rest[1]}`);
      // A proof needs the salts the set was committed with; never make new ones here.
      const { salts } = loadSalts(set, { create: false });
      const com = commitment(set, { create: false });
      const out = { root: com.root, index: idx, item: set.items[idx], salt: salts[set.items[idx].id], proof: merkleProof(com.leaves, idx) };
      const f = `proof-${rest[1]}.json`;
      writeFileSync(f, JSON.stringify(out, null, 1));
      return console.log(`wrote ${f} (reveals this ONE item only)`);
    }
    case 'check-proof': {
      const p = JSON.parse(readFileSync(need(rest[0], '<proof.json>'), 'utf8'));
      if (opt.root === true) throw new Error('--root needs the dataset root');
      const ok = verifyProof(leafOf(p.item, p.salt), p.proof, opt.root ?? p.root, p.index);
      if (ok && !opt.root) console.log(c.y('  checked against the root written in the proof file itself; pass --root <root from the contract> to tie it to a committed set'));
      console.log(ok ? c.g('valid: this item was in the committed set') : c.r('INVALID proof'));
      if (!ok) process.exitCode = 1;
      return;
    }

    case 'pay-quote': {
      const q = await quote({ originAsset: need(opt.from, '--from'), amount: need(opt.amount, '--amount'), recipient: need(opt.recipient, '--recipient'), refundTo: need(opt['refund-to'], '--refund-to'), dry: !opt.live });
      const qq = q.quote ?? q;
      console.log(`${qq.amountInFormatted} in -> ${c.b(qq.amountOutFormatted + ' wNEAR')} to ${opt.recipient} (~$${Number(qq.amountOutUsd).toFixed(2)}, ~${qq.timeEstimate}s)`);
      if (qq.depositAddress) console.log(`deposit address: ${qq.depositAddress}`);
      else console.log(c.d('dry quote: pass --live to get a deposit address. Then unwrap wNEAR (wrap.near near_withdraw) and call request'));
      return;
    }

    case undefined: case 'help': return console.log(HELP);
    default: console.error(c.r(`unknown command: ${pos[0]}`)); console.log(HELP); process.exitCode = 2;
  }
}

main().catch((e) => { console.error(c.r(e.message)); process.exit(1); });
