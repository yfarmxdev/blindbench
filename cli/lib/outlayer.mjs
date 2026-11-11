// OutLayer (outlayer.ai): runs a WebAssembly program inside an Intel TDX
// enclave and returns its output into the NEAR transaction that asked for it.
// BlindBench uses it to run the sealed grader (grader/), so a score is
// computed by pinned code in a TEE rather than by the set's owner.
//
// One execution = one transaction to the OutLayer contract:
//   request_execution({ source: { WasmUrl: { url, hash, build_target } },
//                       input_data, secrets_ref, resource_limits, response_format })
// The program is named by the sha256 of its bytes, and the secret holding the
// input key is bound to that hash, so no other program can read a job.
import { call, rpc } from './near.mjs';

export const OUTLAYER = { testnet: 'outlayer.testnet', mainnet: 'outlayer.near' };
export const LIMITS = { max_instructions: 2000000000, max_memory_mb: 128, max_execution_seconds: 60 };

export function executionArgs({ wasmUrl, wasmSha256, input, secrets }) {
  return {
    source: { WasmUrl: { url: wasmUrl, hash: wasmSha256, build_target: 'wasm32-wasip1' } },
    resource_limits: LIMITS,
    input_data: JSON.stringify(input),
    secrets_ref: { profile: secrets.profile, account_id: secrets.account },
    response_format: 'Json',
  };
}

/** Ask OutLayer to run the program on one input. Returns { tx, url, output }. */
export async function execute(network, opts, { deposit } = {}) {
  const args = executionArgs(opts);
  const out = await call(network, OUTLAYER[network], 'request_execution', args, { deposit: deposit ?? '1000000000000000000000000', gas: '300000000000000' });
  return { tx: out.tx, url: out.url, signer: out.signer, output: out.value };
}

/**
 * Read an execution back from the chain, with no account: the transaction must
 * be a request_execution to the OutLayer contract for exactly this program
 * hash, and what it returned is the grader's output.
 */
export async function readExecution(network, tx, signer) {
  const j = await rpc(network, 'EXPERIMENTAL_tx_status', { tx_hash: tx, sender_account_id: signer, wait_until: 'FINAL' });
  if (j.error) throw new Error(`transaction ${tx}: ${JSON.stringify(j.error).slice(0, 200)}`);
  const t = j.result.transaction, fc = t.actions?.[0]?.FunctionCall;
  if (t.receiver_id !== OUTLAYER[network] || fc?.method_name !== 'request_execution') throw new Error(`transaction ${tx} is not an OutLayer execution`);
  const args = JSON.parse(Buffer.from(fc.args, 'base64').toString());
  const ok = j.result.status?.SuccessValue;
  if (ok == null) throw new Error(`transaction ${tx} did not succeed`);
  return { wasm_sha256: args.source?.WasmUrl?.hash ?? null, wasm_url: args.source?.WasmUrl?.url ?? null, secrets: args.secrets_ref ?? null, input: JSON.parse(args.input_data), output: JSON.parse(Buffer.from(ok, 'base64').toString() || 'null'), block_hash: j.result.transaction_outcome?.block_hash ?? null };
}
