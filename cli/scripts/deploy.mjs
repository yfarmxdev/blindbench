// First deploy: put contract/target/near/blindbench.wasm on NEAR_ACCOUNT_ID and call new().
// Prints the network, the target, the code hash now and the new one, and sends nothing
// without --send. Refuses an account that already holds a contract (use upgrade.mjs there)
// and refuses mainnet without --mainnet. After sending it checks the outcome and that the
// account holds exactly the code that was sent.
import { fileURLToPath } from 'node:url';
import { deployRun } from '../lib/deploy-run.mjs';
const wasmPath = fileURLToPath(new URL('../../contract/target/near/blindbench.wasm', import.meta.url));
deployRun({ mode: 'init', wasmPath }).catch((e) => { console.error(`error: ${e.message}`); process.exit(1); });
