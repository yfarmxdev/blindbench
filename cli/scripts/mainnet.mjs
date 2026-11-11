#!/usr/bin/env node
// One real run on NEAR mainnet, paid through NEAR Intents. Each step is its own
// command and says what it spends; nothing here moves funds on its own account.
//
//   node scripts/mainnet.mjs account                 make a mainnet key and print its account id (free)
//   node scripts/mainnet.mjs plan --from <asset> --amount <units> --refund-to <address on that chain>
//                                                    read-only: balance, deploy cost, a dry Intents quote
//   node scripts/mainnet.mjs quote --from ... --amount ... --refund-to ...
//                                                    a live quote: prints the deposit address to pay into
//   node scripts/mainnet.mjs status <deposit address> where the swap is
//   node scripts/mainnet.mjs unwrap --account <id> --amount <yoctoNEAR|all> [--send]
//                                                    turn delivered wNEAR into NEAR; shows the plan, and signs only with --send
//
// Then, with NEAR_NETWORK=mainnet NEAR_ACCOUNT_ID=<id> BLINDBENCH_CONTRACT=<id>:
//   node scripts/deploy.mjs                          deploy and initialise the contract
//   node blindbench.mjs commit <set.jsonl> --price 0.1
//   node blindbench.mjs request <dataset_id> <model> --deposit 0.1
//   node blindbench.mjs run <set.jsonl> --model <model> --run-id <n> --submit
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { KeyPair } from 'near-api-js';
import { rpc, view, call, fromYocto } from '../lib/near.mjs';
import { quote } from '../lib/intents.mjs';

const NET = 'mainnet', DIR = join(homedir(), '.near-credentials', NET);
const [cmd, ...rest] = process.argv.slice(2);
const opt = Object.fromEntries(rest.flatMap((a, i) => (a.startsWith('--') ? [[a.slice(2), rest[i + 1] && !rest[i + 1].startsWith('--') ? rest[i + 1] : true]] : [])));
const need = (v, what) => v ?? (() => { throw new Error(`missing ${what}`); })();
const saved = () => (existsSync(DIR) ? readdirSync(DIR).filter((f) => /^[0-9a-f]{64}\.json$/.test(f)).map((f) => f.slice(0, -5)) : []);
const accountId = () => process.env.NEAR_ACCOUNT_ID ?? saved()[0] ?? (() => { throw new Error('no mainnet account yet: run the "account" step, or set NEAR_ACCOUNT_ID'); })();
const account = async (id) => (await rpc(NET, 'query', { request_type: 'view_account', finality: 'final', account_id: id })).result ?? null;
const BASE58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const unbase58 = (s) => { let n = 0n; for (const ch of s) n = n * 58n + BigInt(BASE58.indexOf(ch)); return n.toString(16).padStart(64, '0'); };
const swap = () => ({ originAsset: need(opt.from, '--from <asset id, e.g. nep141:base-0x8335…2913.omft.near for USDC on Base>'), amount: need(opt.amount, '--amount <smallest units, e.g. 2000000 for 2 USDC>'), refundTo: need(opt['refund-to'], '--refund-to <your address on the paying chain>') });

switch (cmd) {
  case 'account': {
    // An implicit account: its id is the public key in hex, and it exists once anything is sent to it.
    if (saved().length) { console.log(`account ${saved()[0]} (key already in ${DIR})`); break; }
    const kp = KeyPair.fromRandom('ed25519'), id = unbase58(kp.getPublicKey().toString().replace('ed25519:', ''));
    mkdirSync(DIR, { recursive: true, mode: 0o700 });
    writeFileSync(join(DIR, `${id}.json`), JSON.stringify({ account_id: id, public_key: kp.getPublicKey().toString(), private_key: kp.toString() }), { mode: 0o600 });
    console.log(`account ${id}\nkey saved to ${join(DIR, `${id}.json`)}: back it up before anything is sent to this account`);
    break;
  }
  case 'plan': {
    const id = accountId(), a = await account(id);
    console.log(`account  ${id}: ${a ? `${fromYocto(a.amount)} NEAR` : 'not funded yet'}`);
    const wasm = new URL('../../contract/target/near/blindbench.wasm', import.meta.url);
    const bytes = existsSync(wasm) ? readFileSync(wasm).length : null;
    // Storage is 1 NEAR per 100 KB; the contract's own state adds a little on top.
    console.log(`deploy   ${bytes ? `${(bytes / 1024).toFixed(0)} KB of contract code locks about ${(bytes / 1e5).toFixed(2)} NEAR for storage` : 'contract not built here (cargo near build non-reproducible-wasm); a build of about 300 KB locks about 3 NEAR'}, returned if the contract is ever removed`);
    console.log('fees     deploy, commit, request, certify and unwrap together burn well under 0.1 NEAR of gas');
    const q = await quote({ ...swap(), recipient: id, dry: true }), qq = q.quote ?? q;
    console.log(`intents  ${qq.amountInFormatted} in -> ${qq.amountOutFormatted} wNEAR to ${id} (~$${Number(qq.amountOutUsd).toFixed(2)}, ~${qq.timeEstimate}s): a dry quote, nothing sent`);
    break;
  }
  case 'quote': {
    const id = accountId();
    if (!(await account(id))) throw new Error(`${id} holds no NEAR yet: fund it first, so the delivered wNEAR can be unwrapped`);
    const q = await quote({ ...swap(), recipient: id, dry: false }), qq = q.quote ?? q;
    console.log(`${qq.amountInFormatted} in -> ${qq.amountOutFormatted} wNEAR to ${id}\npay into: ${qq.depositAddress}\nbefore:   ${qq.deadline ?? 'see the quote'}\nNothing has moved. The swap starts when that exact amount arrives at the deposit address.`);
    break;
  }
  case 'status': {
    const r = await fetch(`https://1click.chaindefuser.com/v0/status?depositAddress=${encodeURIComponent(need(rest[0], '<deposit address>'))}`);
    const j = await r.json().catch(() => ({}));
    console.log(`${j.status ?? `HTTP ${r.status}`}${j.swapDetails?.destinationChainTxHashes?.length ? `  delivered in ${j.swapDetails.destinationChainTxHashes.map((t) => t.hash).join(', ')}` : ''}`);
    break;
  }
  case 'unwrap': {
    // This signs a mainnet transaction, so nothing about it is guessed: the account and the
    // amount are named on the command line, and it is sent only with --send.
    const id = typeof opt.account === 'string' ? opt.account : process.env.NEAR_ACCOUNT_ID ?? need(undefined, '--account <id> (or NEAR_ACCOUNT_ID)');
    const bal = await view(NET, 'wrap.near', 'ft_balance_of', { account_id: id });
    if (BigInt(bal) === 0n) { console.log(`no wNEAR on ${id} (yet)`); break; }
    if (opt.amount !== 'all' && !/^[1-9]\d{0,38}$/.test(String(opt.amount ?? ''))) throw new Error(`--amount takes a whole number of yoctoNEAR, or "all" (${id} holds ${bal}, which is ${fromYocto(bal)} wNEAR)`);
    const amount = opt.amount === 'all' ? bal : String(opt.amount);
    if (BigInt(amount) > BigInt(bal)) throw new Error(`${id} holds ${fromYocto(bal)} wNEAR, less than the ${fromYocto(amount)} asked for`);
    console.log(`network  ${NET}\naccount  ${id}\naction   wrap.near near_withdraw: ${fromYocto(amount)} wNEAR -> NEAR (of ${fromYocto(bal)} held)`);
    if (!opt.send) { console.log('Nothing sent. Add --send to sign and send this transaction.'); break; }
    process.env.NEAR_NETWORK = NET; process.env.NEAR_ACCOUNT_ID = id;
    const r = await call(NET, 'wrap.near', 'near_withdraw', { amount }, { deposit: '1' });
    console.log(`unwrapped ${fromYocto(amount)} NEAR  ${r.url}`);
    break;
  }
  default: console.log(readFileSync(new URL(import.meta.url), 'utf8').split('\n').slice(1, 19).map((l) => l.replace(/^\/\/ ?/, '')).join('\n'));
}
