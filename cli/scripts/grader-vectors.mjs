#!/usr/bin/env node
// Test vectors that tie the sealed grader (grader/, Rust, runs in a TEE) to the
// JavaScript grader (cli/lib/grade.mjs): answer lines in every shape we could
// think of, graded by the JavaScript code. `cargo test` in grader/ replays them.
//   node scripts/grader-vectors.mjs          write grader/vectors.json
//   node scripts/grader-vectors.mjs --check  fail if the file is out of date
import { readFileSync, writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { gradeExact, extractFinal, asNumber } from '../lib/grade.mjs';

const FILE = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'grader', 'vectors.json');
// the same normaliser as grade.mjs (not exported there)
const norm = (s) => String(s).toLowerCase().normalize('NFKC').replace(/(^|[^\p{L}\p{N}])[-−](?=\d)/gu, '$1 minus ').replace(/[^\p{L}\p{N}]+/gu, ' ').trim();

// deterministic pseudo-random choices, so the file is reproducible
let seed = 20261110;
const rnd = () => (seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff;
const pick = (xs) => xs[Math.floor(rnd() * xs.length)];

const keys = [
  { answer: '518200', accept: ['518,200'] }, { answer: '62' }, { answer: '6.58' }, { answer: '71.0' }, { answer: '-12.5', accept: ['(12.5)'] },
  { answer: '0.75' }, { answer: '1,250,000' }, { answer: 'yes' }, { answer: 'Tranche B', accept: ['B'] }, { answer: 'not in compliance', accept: ['breach'] },
  { answer: '2.4x' }, { answer: '150 bps', accept: ['1.5%'] }, { answer: '-62' }, { answer: 'zs1-older', accept: ['zs1 older'] }, { answer: 42 }, { answer: '0' },
];
const numbers = ['518200', '518,200', '518200.0', '518,200.00', '62', '62%', '62.0 %', '-62', '−62', '(62)', '6.58', '6.580', '6.6', '71', '71.0', '71.00', '$1,250,000', 'US$1,250,000', '1250000', '1,250,000.4',
  '12.5', '-12.5', '(12.5)', '- 12.5', '$-12.5', '-$12.5', '.75', '0.75', '0.750', '75%', '2.4x', '2.4 x', '2.4×', '2.40X', '150 bps', '150bps', '150 basis points', '1.5%', '45 days', '1,2345', '12,34', '1,234,56', '0', '-0', '0.0', '42', '42.', '+42', '1e3', '１２３', '٣'];
const words = ['yes', 'Yes.', 'YES', 'no', 'Tranche B', 'tranche b', 'B', 'b.', 'Not in compliance', 'not-in-compliance', 'breach', 'Breach!', 'zs1-older', 'zs1 older', 'ZS1_OLDER', 'café', 'ﬁnal', 'n/a', '', '   ', '-', 'minus 62', 'about 62', '62 percent', 'approximately $518,200'];
const wraps = [(a) => `FINAL: ${a}`, (a) => `final: ${a}`, (a) => `Final:${a}`, (a) => `Some working.\nFINAL: ${a}\n`, (a) => `FINAL: 1\nMore thought.\nFINAL: ${a}`, (a) => `**FINAL:** ${a}`, (a) => `FINAL: **${a}**`, (a) => `FINAL: \`${a}\``,
  (a) => `FINAL:\n${a}`, (a) => `FINAL:   ${a}   `, (a) => `${a}`, (a) => `Working...\n${a}`, (a) => `FINAL: ${a}\r\nthanks`, (a) => `The answer is FINAL: ${a}.`, (a) => `FINAL: ${a}\n\n`, (a) => `Line one\n\nFINAL: (${a})`, (a) => `FINAL:\t${a}`, (a) => `FINAL: ${a} `, (a) => `FINAL: \n`, (a) => `x\nFINAL:`];

const cases = [];
const add = (item, text) => { const final = extractFinal(text); cases.push({ item, text, final, number: asNumber(final), norm: norm(final), score: gradeExact(item, text).score }); };
for (const item of keys) for (const a of [...numbers, ...words]) add(item, pick(wraps)(a));
for (const w of wraps) for (const a of ['62', '(12.5)', 'Tranche B', '']) add(pick(keys), w(a));
for (const item of keys) { add(item, `FINAL: ${item.answer}`); for (const acc of item.accept ?? []) add(item, `reasoning\nFINAL: ${acc}`); }

const strings = ['plain', 'quote " and \\ backslash', 'tab\there', 'line\nbreak\r\n', 'control \u0001\u001f\u007f', 'unicode é ü 漢字    ', 'emoji 😀', '</script>', '\b\f', ''].map((s) => ({ s, json: JSON.stringify(s) }));
const out = JSON.stringify({ note: 'written by cli/scripts/grader-vectors.mjs; do not edit', cases, strings }, null, 0) + '\n';
if (process.argv.includes('--check')) {
  if (readFileSync(FILE, 'utf8') !== out) { console.error('grader/vectors.json is out of date: run node scripts/grader-vectors.mjs'); process.exit(1); }
  console.log(`grader/vectors.json is current (${cases.length} cases)`);
} else { writeFileSync(FILE, out); console.log(`wrote ${cases.length} cases to grader/vectors.json`); }
