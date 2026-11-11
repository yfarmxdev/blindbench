// NEAR access. Views go straight to JSON-RPC (no account, no key, which is
// what a judge needs). Calls use near-api-js with a key from the environment
// (NEAR_ACCOUNT_ID + NEAR_PRIVATE_KEY) or ~/.near-credentials/<network>/<id>.json.
import { readFileSync, existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

// Each network has a list of RPC endpoints, tried in order: if one is down or
// rate-limiting, the next one answers. NEAR_RPC_URL puts your own endpoint first.
const own = process.env.NEAR_RPC_URL ? [process.env.NEAR_RPC_URL] : [];
export const NETWORKS = {
  testnet: { rpcs: [...own, 'https://test.rpc.fastnear.com', 'https://rpc.testnet.near.org'], explorer: 'https://testnet.nearblocks.io' },
  mainnet: { rpcs: [...own, 'https://rpc.mainnet.fastnear.com', 'https://rpc.mainnet.near.org'], explorer: 'https://nearblocks.io' },
};
const net = (network) => NETWORKS[network] ?? (() => { throw new Error(`unknown network "${network}" (testnet or mainnet)`); })();

export async function rpc(network, method, params) {
  let last;
  for (const url of net(network).rpcs) {
    try {
      const r = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 'bb', method, params }), signal: AbortSignal.timeout(20000) });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      return await r.json();
    } catch (e) { last = new Error(`${url}: ${e.message}`); }
  }
  throw new Error(`NEAR RPC unreachable (${last.message})`);
}

export async function view(network, contractId, method, args = {}) {
  const j = await rpc(network, 'query', { request_type: 'call_function', finality: 'final', account_id: contractId, method_name: method, args_base64: Buffer.from(JSON.stringify(args)).toString('base64') });
  if (j.error || j.result?.error) throw new Error(`view ${method}: ${JSON.stringify(j.error ?? j.result.error).slice(0, 300)}`);
  return JSON.parse(Buffer.from(j.result.result).toString() || 'null');
}

function credentials(network) {
  const id = process.env.NEAR_ACCOUNT_ID;
  if (id && process.env.NEAR_PRIVATE_KEY) return { id, key: process.env.NEAR_PRIVATE_KEY };
  if (id) {
    const p = join(homedir(), '.near-credentials', network, `${id}.json`);
    if (existsSync(p)) return { id, key: JSON.parse(readFileSync(p, 'utf8')).private_key };
  }
  throw new Error('set NEAR_ACCOUNT_ID and NEAR_PRIVATE_KEY (or have ~/.near-credentials/<network>/<account>.json)');
}

export async function call(network, contractId, method, args, { deposit = '0', gas = '100000000000000' } = {}) {
  const { Account, JsonRpcProvider, KeyPairSigner } = await import('near-api-js');
  const { id, key } = credentials(network);
  const account = new Account(id, new JsonRpcProvider({ url: net(network).rpcs[0] }), KeyPairSigner.fromSecretKey(key));
  const out = await account.callFunctionRaw({ contractId, methodName: method, args, deposit: BigInt(deposit), gas: BigInt(gas) });
  const tx = out.transaction?.hash ?? out.transaction_outcome?.id;
  const url = `${net(network).explorer}/txns/${tx}`;
  // A transaction can be included and still fail (a contract panic): never report that as a success.
  const failed = out.status?.Failure ?? out.receipts_outcome?.map((r) => r.outcome?.status?.Failure).find(Boolean);
  if (failed) throw new Error(`${method} failed onchain: ${failureText(failed)}  ${url}`);
  // Success is a SuccessValue (an empty one for a method that returns nothing). Anything else
  // is an outcome this code cannot read: say so, and never print it as done.
  const ok = out.status?.SuccessValue;
  if (typeof ok !== 'string') throw new Error(`${method}: the RPC reported neither success nor failure, so the outcome is unknown. Inspect ${url} before sending it again`);
  const value = ok ? JSON.parse(Buffer.from(ok, 'base64').toString() || 'null') : null;
  return { tx, value, url, signer: id };
}

/** The id a call returned (a dataset, run, certificate or bounty number), or an error that says the outcome needs a look. */
export function returnedId(out, method) {
  if (!Number.isSafeInteger(out?.value) || out.value < 0) throw new Error(`${method} went through but returned no id. Inspect ${out?.url} before sending it again`);
  return out.value;
}

/** The contract's panic message out of a NEAR execution failure, when there is one. */
export function failureText(f) {
  const s = JSON.stringify(f);
  const m = s.match(/Smart contract panicked: ([^"\\]+)/);
  return (m ? m[1] : s).slice(0, 300);
}

export const toYocto = (near) => {
  const m = /^(\d+)(?:\.(\d{1,24}))?$/.exec(String(near).trim());
  if (!m) throw new Error(`not an amount in NEAR: "${near}" (use digits, with at most 24 decimals)`);
  return (BigInt(m[1]) * 10n ** 24n + BigInt((m[2] ?? '').padEnd(24, '0'))).toString();
};
export const fromYocto = (y) => {
  const s = BigInt(y).toString().padStart(25, '0');
  return `${s.slice(0, -24)}.${s.slice(-24).replace(/0+$/, '') || '0'}`;
};
