// The one path both contract deploy scripts take: read the target, print what will happen,
// stop unless --send is given, send, then check the outcome and the code hash onchain.
import { readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { NETWORKS, rpc, call } from './near.mjs';
import { codeHash, deployPlan } from './deploy-plan.mjs';

async function liveCode(network, account) {
  const j = await rpc(network, 'query', { request_type: 'view_account', finality: 'final', account_id: account });
  if (j.error || j.result?.error) throw new Error(`cannot read ${account} on ${network}: ${JSON.stringify(j.error ?? j.result.error).slice(0, 200)}`);
  return j.result.code_hash;
}

export async function deployRun({ mode, wasmPath, argv = process.argv.slice(2) }) {
  const flags = { send: argv.includes('--send'), mainnet: argv.includes('--mainnet') };
  const network = process.env.NEAR_NETWORK ?? 'testnet';
  const account = process.env.NEAR_ACCOUNT_ID;
  const wasm = readFileSync(wasmPath);
  const next = codeHash(wasm);
  const current = account && NETWORKS[network] ? await liveCode(network, account) : undefined;
  const plan = deployPlan({ mode, network, account, current, next: next.b58, flags });
  console.log(`network    ${network}`);
  console.log(`target     ${account ?? '(not set)'}`);
  console.log(`code now   ${current ?? '(unread)'}`);
  console.log(`code new   ${next.b58}  sha256 ${next.hex}  ${wasm.length} bytes`);
  console.log(`action     ${mode === 'init' ? 'deploy and call new() on a fresh account' : 'replace the code, keep the state (new() is not called)'}`);
  if (plan.refuse) throw new Error(plan.refuse);
  if (plan.noop) { console.log('status     this code is already live: nothing sent'); return; }
  if (plan.dry) { console.log('status     nothing sent. Check the lines above, then run again with --send'); return; }

  const { Account, JsonRpcProvider, KeyPairSigner } = await import('near-api-js');
  const key = process.env.NEAR_PRIVATE_KEY ?? JSON.parse(readFileSync(join(homedir(), '.near-credentials', network, `${account}.json`), 'utf8')).private_key;
  const signer = new Account(account, new JsonRpcProvider({ url: NETWORKS[network].rpcs[0] }), KeyPairSigner.fromSecretKey(key));
  const d = await signer.deployContract(wasm);
  const tx = d.transaction?.hash ?? d.transaction_outcome?.id;
  const url = `${NETWORKS[network].explorer}/txns/${tx}`;
  const failed = d.status?.Failure ?? d.receipts_outcome?.map((r) => r.outcome?.status?.Failure).find(Boolean);
  if (failed) throw new Error(`deploy failed onchain: ${JSON.stringify(failed).slice(0, 300)}  ${url}`);
  if (typeof d.status?.SuccessValue !== 'string') throw new Error(`deploy: the RPC reported neither success nor failure, so the outcome is unknown. Inspect ${url} before sending it again`);
  console.log(`deployed   ${url}`);

  // The account must now hold exactly the code that was sent. A final-state read can lag a few seconds.
  let seen;
  for (let i = 0; i < 10; i++) {
    seen = await liveCode(network, account);
    if (seen === next.b58) break;
    await new Promise((r) => setTimeout(r, 2000));
  }
  if (seen !== next.b58) throw new Error(`code hash onchain is ${seen}, expected ${next.b58}. Inspect ${url}`);
  console.log(`verified   ${account} holds code ${seen}`);

  if (mode === 'init') {
    const i = await call(network, account, 'new', {}, { gas: '30000000000000' });
    console.log(`initialised ${i.url}`);
  }
  console.log(`status     done: ${account} on ${network} runs ${next.b58}`);
}
