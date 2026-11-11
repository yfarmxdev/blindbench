// Code-only deploy of contract/target/near/blindbench.wasm to NEAR_ACCOUNT_ID: new() is not
// called, so every dataset, run, certificate and bounty stays. Use it only when the stored
// state layout is unchanged. Pass a wasm path to deploy another build (for a rollback).
// Prints the network, the target, the code hash now and the new one, and sends nothing
// without --send. Refuses mainnet without --mainnet. After sending it checks the outcome
// and that the account holds exactly the code that was sent.
import { fileURLToPath } from 'node:url';
import { deployRun } from '../lib/deploy-run.mjs';
const argv = process.argv.slice(2);
const given = argv.find((a) => !a.startsWith('--'));
const wasmPath = given ?? fileURLToPath(new URL('../../contract/target/near/blindbench.wasm', import.meta.url));
deployRun({ mode: 'code', wasmPath, argv }).catch((e) => { console.error(`error: ${e.message}`); process.exit(1); });
