import test from 'node:test';
import assert from 'node:assert/strict';
import { base58, codeHash, deployPlan, NO_CODE } from '../lib/deploy-plan.mjs';

test('deploy plan: nothing is sent without --send, live state is never re-initialised, mainnet needs its own flag', () => {
  // base58 as NEAR prints a code hash: 32 zero bytes are the "no contract" hash
  assert.equal(base58(Buffer.alloc(32)), NO_CODE);
  assert.equal(base58(Buffer.from('hello world')), 'StV1DL6CwTryKyV');
  const h = codeHash(Buffer.from('abc'));
  assert.equal(h.hex, 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  assert.equal(h.b58.length >= 43 && h.b58.length <= 44, true);

  const base = { network: 'testnet', account: 'a.testnet', next: 'NEWHASH' };
  // a first deploy
  assert.deepEqual(deployPlan({ ...base, mode: 'init', current: NO_CODE }), { dry: true });
  assert.deepEqual(deployPlan({ ...base, mode: 'init', current: NO_CODE, flags: { send: true } }), { send: true });
  assert.match(deployPlan({ ...base, mode: 'init', current: 'OLDHASH', flags: { send: true } }).refuse, /already holds a contract/);
  // a code-only upgrade
  assert.deepEqual(deployPlan({ ...base, mode: 'code', current: 'OLDHASH' }), { dry: true });
  assert.deepEqual(deployPlan({ ...base, mode: 'code', current: 'OLDHASH', flags: { send: true } }), { send: true });
  assert.deepEqual(deployPlan({ ...base, mode: 'code', current: 'NEWHASH', flags: { send: true } }), { noop: true });
  assert.match(deployPlan({ ...base, mode: 'code', current: NO_CODE, flags: { send: true } }).refuse, /holds no contract/);
  // the target must be named, readable and on a known network
  assert.match(deployPlan({ ...base, account: undefined, mode: 'code', current: 'OLDHASH' }).refuse, /NEAR_ACCOUNT_ID/);
  assert.match(deployPlan({ ...base, mode: 'code', current: undefined, flags: { send: true } }).refuse, /could not read/);
  assert.match(deployPlan({ ...base, network: 'devnet', mode: 'code', current: 'OLDHASH' }).refuse, /unknown network/);
  // mainnet is refused until it is named on the command line, then follows the same rules
  const main = { ...base, network: 'mainnet', account: 'a.near', mode: 'code', current: 'OLDHASH' };
  assert.match(deployPlan({ ...main, flags: { send: true } }).refuse, /--mainnet/);
  assert.deepEqual(deployPlan({ ...main, flags: { mainnet: true } }), { dry: true });
  assert.deepEqual(deployPlan({ ...main, flags: { mainnet: true, send: true } }), { send: true });
});
