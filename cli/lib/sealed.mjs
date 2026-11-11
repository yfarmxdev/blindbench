// Sealed grading: one item of a committed set and one enclave-signed model call
// are encrypted for the grader program (grader/, Rust, compiled to WebAssembly),
// which runs in a TEE and returns the item's leaf, the hashes of the bytes it
// read and the score. See grader/src/main.rs for what it checks.
//
// This file builds the encrypted job, runs the same .wasm locally (node:wasi)
// for tests and for a parity check, and checks a grading receipt against the
// evidence it belongs to.
import { createCipheriv, randomBytes } from 'node:crypto';
import { deflateRawSync } from 'node:zlib';
import { readFileSync, mkdtempSync, rmSync, openSync, closeSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { canon, sha256 } from './util.mjs';
import { leafOf } from './dataset.mjs';

export const GRADER = 'blindbench-exact/1';
export const GRADER_WASM = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'grader', 'blindbench-grader.wasm');

/** What the grader is given for one item, before encryption. */
export function jobFor({ item, salt, request, response }) {
  const whole = canon(item), needle = '"prompt":' + JSON.stringify(item.prompt);
  const at = whole.indexOf(needle);
  if (at < 0 || whole.indexOf(needle, at + 1) >= 0) throw new Error('cannot split the item around its prompt');
  const pre = whole.slice(0, at + '"prompt":'.length), post = whole.slice(at + needle.length);
  return { salt, pre, post, request, response };
}

/** Encrypt a job for the grader: ChaCha20-Poly1305 under the key only the grader's hash can read. */
export function seal(job, keyHex) {
  const nonce = randomBytes(12), c = createCipheriv('chacha20-poly1305', Buffer.from(keyHex, 'hex'), nonce, { authTagLength: 16 });
  // Compressed before sealing (raw DEFLATE): a streamed answer is mostly repeated framing, and the enclave input is paid per byte.
  const ct = Buffer.concat([c.update(deflateRawSync(Buffer.from(JSON.stringify(job), 'utf8'), { level: 9 })), c.final(), c.getAuthTag()]);
  return { v: 2, nonce: nonce.toString('hex'), ct: ct.toString('base64') };
}

/** Run the grader .wasm on this machine, exactly as the TEE runs it: JSON on stdin, JSON on stdout. */
export async function runLocal(input, { wasm = GRADER_WASM, env = {} } = {}) {
  const { WASI } = await import('node:wasi');
  const dir = mkdtempSync(join(tmpdir(), 'bb-grader-'));
  try {
    writeFileSync(join(dir, 'in'), JSON.stringify(input));
    const stdin = openSync(join(dir, 'in'), 'r'), stdout = openSync(join(dir, 'out'), 'w');
    const wasi = new WASI({ version: 'preview1', args: ['grader'], env, stdin, stdout, returnOnExit: true });
    const instance = await WebAssembly.instantiate(await WebAssembly.compile(readFileSync(wasm)), wasi.getImportObject());
    wasi.start(instance);
    closeSync(stdin); closeSync(stdout);
    return JSON.parse(readFileSync(join(dir, 'out'), 'utf8'));
  } finally { rmSync(dir, { recursive: true, force: true }); }
}

/**
 * Does a grader's output say what the evidence says about this item?
 * `it` is the evidence item (leaf, request_sha256, response_sha256, score).
 */
export function receiptMismatches(out, it, model) {
  const bad = [];
  if (out?.error) return [`the grader refused the job: ${out.error}`];
  if (out?.grader !== GRADER) bad.push(`grader is ${out?.grader}, expected ${GRADER}`);
  if (out.leaf !== it.leaf) bad.push('the grader saw a different item (leaf)');
  if (out.request_sha256 !== it.request_sha256) bad.push('the grader saw a different request than the enclave signed');
  if (out.response_sha256 !== it.response_sha256) bad.push('the grader saw a different response than the enclave signed');
  if (out.model !== model) bad.push(`the request was for ${out.model}`);
  if (out.score !== it.score) bad.push(`the grader scored ${out.score}, the evidence says ${it.score}`);
  return bad;
}

export { leafOf, sha256 };
