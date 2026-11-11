// What a contract deploy is about to do, decided before anything is signed. Kept free of
// network calls so the rules can be tested: the scripts read the account, ask this, print
// the answer and only then send.
import { createHash } from 'node:crypto';

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
export function base58(bytes) {
  const buf = Buffer.from(bytes);
  let n = BigInt('0x' + (buf.toString('hex') || '0'));
  let s = '';
  while (n > 0n) { s = B58[Number(n % 58n)] + s; n /= 58n; }
  for (const b of buf) { if (b === 0) s = '1' + s; else break; }
  return s;
}

/** A wasm file's hash the two ways NEAR tools print it: hex, and the base58 `code_hash` of an account. */
export function codeHash(wasm) {
  const d = createHash('sha256').update(wasm).digest();
  return { hex: d.toString('hex'), b58: base58(d) };
}

/** The `code_hash` of an account that holds no contract. */
export const NO_CODE = '1'.repeat(32);

/**
 * mode 'init' deploys and calls new() (a fresh account only); mode 'code' replaces the code and
 * keeps the state. Returns { refuse } with the reason, { noop } when the code is already live,
 * { dry } when --send is missing, or { send: true }.
 */
export function deployPlan({ mode, network, account, current, next, flags = {} }) {
  if (!account) return { refuse: 'set NEAR_ACCOUNT_ID to the account that holds the contract' };
  if (network !== 'testnet' && network !== 'mainnet') return { refuse: `unknown network "${network}" (testnet or mainnet)` };
  if (network === 'mainnet' && !flags.mainnet) return { refuse: 'this targets mainnet: add --mainnet to confirm the network' };
  if (typeof current !== 'string' || !current) return { refuse: `could not read the code hash of ${account} on ${network}` };
  const empty = current === NO_CODE;
  if (mode === 'init' && !empty) return { refuse: `${account} already holds a contract (code ${current}). A fresh deploy would call new() on live state. Use scripts/upgrade.mjs to replace the code only` };
  if (mode === 'code' && empty) return { refuse: `${account} holds no contract yet. Use scripts/deploy.mjs for a first deploy` };
  if (mode === 'code' && current === next) return { noop: true };
  if (!flags.send) return { dry: true };
  return { send: true };
}
