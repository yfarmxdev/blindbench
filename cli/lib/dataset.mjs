// Private eval sets: loading, salted commitments and Merkle proofs.
//
// A set is a JSONL file, one item per line:
//   exact:     { id, prompt, answer, accept?: [..] }
//   checklist: { id, prompt, checklist: [{ id, finding, severity, weight, keywords: [..] }] }
//   rubric:    { id, prompt, rubric: [{ criterion, weight }] }
//   tests:     { id, prompt, entry: [names], tests: [{ id, code }] }  (hidden Python unit tests)
// plus a first line { "_meta": { name, grading, description } }.
//
// Each item gets a random 32-byte salt, kept in <set>.salts.json next to the
// set (never committed, never published). leaf = sha256(salt || canon(item)).
// The salt stops anyone brute-forcing short answers ("A", "reentrancy") from a
// published leaf. root = Merkle root over the leaves; only the root goes onchain.
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { canon, sha256, randomHex } from './util.mjs';

const ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const SALT = /^[0-9a-f]{64}$/;

export function loadSet(path) {
  const lines = readFileSync(path, 'utf8').split('\n').map((l) => l.trim()).filter(Boolean);
  const first = JSON.parse(lines[0]);
  if (!first._meta) throw new Error(`${path}: first line must be {"_meta": {...}}`);
  const meta = first._meta;
  if (!['exact', 'checklist', 'rubric', 'tests'].includes(meta.grading)) throw new Error('grading must be exact, checklist, rubric or tests');
  const items = lines.slice(1).map((l, i) => {
    const it = JSON.parse(l);
    if (!it.id || !it.prompt) throw new Error(`${path}: item ${i + 1} needs id and prompt`);
    // Ids become file names (answers, proofs, debug output) and salt keys.
    if (typeof it.id !== 'string' || !ID.test(it.id)) throw new Error(`${path}: item ${i + 1} id must be 1-64 of A-Z a-z 0-9 . _ - and start with a letter or digit`);
    if (meta.grading === 'tests' && !(Array.isArray(it.tests) && it.tests.length)) throw new Error(`${path}: item ${it.id} needs a tests array`);
    return it;
  });
  const seen = new Set();
  for (const it of items) { if (seen.has(it.id)) throw new Error(`${path}: item id ${it.id} is used twice`); seen.add(it.id); }
  return { path, meta, items };
}

export function loadSalts(set, { create = true } = {}) {
  const p = set.path.replace(/\.jsonl$/, '') + '.salts.json';
  // A null-prototype copy, so an id such as "constructor" never finds an inherited value.
  const salts = Object.assign(Object.create(null), existsSync(p) ? JSON.parse(readFileSync(p, 'utf8')) : {});
  let changed = false;
  for (const it of set.items) {
    if (salts[it.id] !== undefined && !(typeof salts[it.id] === 'string' && SALT.test(salts[it.id]))) throw new Error(`${p}: salt for ${it.id} is not 32 bytes of hex`);
    if (!salts[it.id]) {
      if (!create) throw new Error(`no salt for ${it.id}; run commit first`);
      salts[it.id] = randomHex(32);
      changed = true;
    }
  }
  if (changed) writeFileSync(p, JSON.stringify(salts, null, 1));
  return { path: p, salts };
}

export const leafOf = (item, salt) => sha256(Buffer.concat([Buffer.from(salt, 'hex'), Buffer.from(canon(item))]));

const pair = (a, b) => sha256(Buffer.concat([Buffer.from(a, 'hex'), Buffer.from(b, 'hex')]));

export function merkleRoot(leaves) {
  if (!leaves.length) throw new Error('empty set');
  let level = leaves;
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) next.push(pair(level[i], level[i + 1] ?? level[i]));
    level = next;
  }
  return level[0];
}

export function merkleProof(leaves, index) {
  const proof = [];
  let level = leaves;
  let i = index;
  while (level.length > 1) {
    const sib = i % 2 === 0 ? (level[i + 1] ?? level[i]) : level[i - 1];
    proof.push({ side: i % 2 === 0 ? 'right' : 'left', hash: sib });
    const next = [];
    for (let j = 0; j < level.length; j += 2) next.push(pair(level[j], level[j + 1] ?? level[j]));
    level = next;
    i = Math.floor(i / 2);
  }
  return proof;
}

export function verifyProof(leaf, proof, root, index) {
  // With an index, the left/right turns must be the ones that index takes.
  if (index !== undefined) {
    if (!Number.isInteger(index) || index < 0 || index >= 2 ** proof.length) return false;
    if (proof.some((p, d) => (p.side === 'right') !== (((index >> d) & 1) === 0))) return false;
  }
  let h = leaf;
  for (const p of proof) h = p.side === 'right' ? pair(h, p.hash) : pair(p.hash, h);
  return h === root;
}

/** Everything about a set that is safe to publish. */
export function commitment(set, { create = true } = {}) {
  const { salts } = loadSalts(set, { create });
  const leaves = set.items.map((it) => leafOf(it, salts[it.id]));
  return { root: merkleRoot(leaves), leaves, items: set.items.length, grading: set.meta.grading, description: set.meta.description };
}
