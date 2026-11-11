// Small shared helpers: canonical JSON, hashing, args, printing.
import { createHash, randomBytes } from 'node:crypto';

/** JSON with sorted keys, so the same object always hashes the same. */
export function canon(v) {
  if (Array.isArray(v)) return '[' + v.map(canon).join(',') + ']';
  if (v && typeof v === 'object') {
    return '{' + Object.keys(v).sort().filter((k) => v[k] !== undefined)
      .map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}';
  }
  return JSON.stringify(v);
}

export const sha256 = (data) => createHash('sha256').update(data).digest('hex');
export const randomHex = (n = 32) => randomBytes(n).toString('hex');

export function parseArgs(argv) {
  const pos = [];
  const opt = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith('--')) {
      const k = a.slice(2);
      const next = argv[i + 1];
      if (next === undefined || next.startsWith('--')) opt[k] = true;
      else { opt[k] = next; i++; }
    } else pos.push(a);
  }
  return { pos, opt };
}

/**
 * Which API key, if any, may go to this inference endpoint. The key belongs to
 * NEAR AI Cloud, so it is sent there (and to a local mock) only. Another host
 * gets it only when the caller says so, and never over plain http.
 */
export function keyFor(endpoint, key, { allowCustom = false } = {}) {
  let u;
  try { u = new URL(endpoint); } catch { throw new Error(`endpoint is not a URL: ${endpoint}`); }
  if (u.username || u.password) throw new Error('endpoint must not carry credentials in the URL');
  const local = ['127.0.0.1', 'localhost', '[::1]'].includes(u.hostname);
  if (u.protocol !== 'https:' && !local) throw new Error(`endpoint must be https (got ${u.protocol}//${u.host})`);
  if (!key) return undefined;
  if (local || u.hostname === 'cloud-api.near.ai' || allowCustom) return key;
  throw new Error(`NEARAI_API_KEY is a NEAR AI Cloud key and ${u.host} is another host. Pass --send-key-to-endpoint (or NEARAI_KEY_ANY_ENDPOINT=1) if that is intended, or unset the key`);
}

/** A whole, non-negative number from a flag, or a clear error. */
export function intFlag(v, name, { min = 0, max = Number.MAX_SAFE_INTEGER } = {}) {
  const n = Number(v);
  if (v === true || v === '' || !Number.isInteger(n) || n < min || n > max) throw new Error(`${name} needs a whole number${min ? ` of at least ${min}` : ''}`);
  return n;
}

export const pct = (bps) => (bps / 100).toFixed(2) + '%';
export const c = {
  b: (s) => `\x1b[1m${s}\x1b[0m`,
  g: (s) => `\x1b[32m${s}\x1b[0m`,
  r: (s) => `\x1b[31m${s}\x1b[0m`,
  y: (s) => `\x1b[33m${s}\x1b[0m`,
  d: (s) => `\x1b[2m${s}\x1b[0m`,
};
