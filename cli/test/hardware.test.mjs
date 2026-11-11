// Hardware proof: real Intel TDX quotes from NEAR AI Cloud, saved under
// web/attestations/, are verified offline down to Intel's root; and evidence
// cannot vouch for its own signing key.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Wallet } from 'ethers';
import { verifyKeyProof, verifyQuote, proveKeys, parseQuote, INTEL_SGX_ROOT_PUBKEY } from '../../web/tdx.mjs';
import { verifyBundle } from '../lib/runner.mjs';
import { proofStore, PROOF_DIR } from '../lib/attest.mjs';
import { merkleRoot } from '../lib/dataset.mjs';
import { sha256 } from '../lib/util.mjs';

const WEB = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'web');
const proofs = readdirSync(PROOF_DIR).filter((f) => f.startsWith('0x')).map((f) => JSON.parse(readFileSync(join(PROOF_DIR, f), 'utf8')));
const gateway = proofs.find((p) => p.role === 'gateway'), enclave = proofs.find((p) => p.role === 'model');
const flip = (h, i) => h.slice(0, i) + (h[i] === '0' ? '1' : '0') + h.slice(i + 1);

test('published key proofs verify offline to Intel\'s root, with Intel\'s TCB verdict', async () => {
  assert.ok(proofs.length >= 2);
  for (const p of proofs) {
    const r = await verifyKeyProof(p);
    assert.equal(r.signing_address, p.attestation.signing_address.toLowerCase());
    assert.equal(r.nonce_fresh, true);
    assert.equal(r.compose_bound, true);
    assert.deepEqual(r.rtmr_replayed.slice(0, 3), [true, true, true]);
    assert.equal(r.tcb.tcb_status, 'UpToDate');
    assert.equal(r.tcb.qe_status, 'UpToDate');
  }
});

test('a quote that was touched anywhere is rejected', async () => {
  const at = Date.parse(gateway.fetched_at), q = gateway.attestation.intel_quote;
  const body = 2 * (48 + 520) + 10;           // inside report_data
  const sig = 2 * (48 + 584 + 4) + 10;        // inside the quote signature
  const qe = 2 * (48 + 584 + 4 + 134) + 700;  // inside the Quoting Enclave report
  for (const i of [body, sig, qe]) await assert.rejects(verifyQuote(flip(q, i), { at }));
  // a certificate in the PCK chain
  const pem = parseQuote(q).pck, bad = Buffer.from(q, 'hex');
  const where = bad.indexOf(Buffer.from(pem.slice(0, 200))) + 120;
  bad[where] = bad[where] === 0x41 ? 0x42 : 0x41;
  await assert.rejects(verifyQuote(bad.toString('hex'), { at }));
  // a quote for another key, a stale nonce, expired certificates, forged collateral
  await assert.rejects(verifyKeyProof({ ...gateway, attestation: { ...gateway.attestation, signing_address: '0x' + '11'.repeat(20) } }), /does not bind the signing address/);
  await assert.rejects(verifyKeyProof({ ...gateway, nonce: 'ab'.repeat(32) }), /nonce/);
  await assert.rejects(verifyKeyProof({ ...gateway, fetched_at: '2060-01-01T00:00:00Z' }), /not valid at|expired/);
  const forged = { ...gateway.collateral, tcb: { ...gateway.collateral.tcb, body: gateway.collateral.tcb.body.replace('"UpToDate"', '"UpToDatE"') } };
  await assert.rejects(verifyKeyProof({ ...gateway, collateral: forged }), /not signed by Intel/);
  assert.equal(INTEL_SGX_ROOT_PUBKEY.length, 130);
});

test('a key proof only counts for its own role and model', async () => {
  const addr = enclave.attestation.signing_address.toLowerCase(), store = proofStore();
  const ok = await proveKeys({ level: 'model-enclave', signing_addresses: [addr] }, enclave.model, store);
  assert.equal(ok[0].ok, true);
  const other = await proveKeys({ level: 'model-enclave', signing_addresses: [addr] }, 'someone/else', store);
  assert.match(other[0].why, /enclave/);
  const asGateway = await proveKeys({ level: 'gateway+3p-enclave', signing_addresses: [addr] }, enclave.model, store);
  assert.equal(asGateway[0].ok, false);
  const unknown = await proveKeys({ level: 'gateway+3p-enclave', signing_addresses: ['0x' + '22'.repeat(20)] }, 'm', store);
  assert.match(unknown[0].why, /no hardware quote/);
});

// Evidence an attacker writes from scratch: internally consistent, every
// signature valid, signed by a key the evidence itself declares.
async function selfSigned(attestation, wallet) {
  const leaves = [sha256('a'), sha256('b')], items = [];
  for (const [index, leaf] of leaves.entries()) {
    const request_sha256 = sha256('q' + index), response_sha256 = sha256('r' + index), signed_text = `${request_sha256}:${response_sha256}`;
    items.push({ index, leaf, score: 1, request_sha256, response_sha256, signed_text, signature: await wallet.signMessage(signed_text) });
  }
  return { version: 'blindbench-evidence/1', dataset_root: merkleRoot(leaves), grading: 'exact', model: 'evil/model', judge_model: null, attestation, judge_attestation: null, items, score_bps: 10000 };
}

test('evidence cannot vouch for its own signing key', async () => {
  const w = Wallet.createRandom(), mine = w.address.toLowerCase(), real = gateway.attestation.signing_address.toLowerCase();
  const forged = await selfSigned({ level: 'gateway+3p-enclave', signing_addresses: [mine], gateway_addresses: [], simulated: false }, w);
  const v = await verifyBundle(forged);
  assert.equal(v.valid, 2);          // the signatures themselves are fine
  assert.equal(v.root_ok, true);
  assert.equal(v.hardware, 'unproven');
  assert.ok(v.problems.some((p) => p.includes('not hardware-backed')));
  // naming the real, proven gateway key does not help: the signatures are not its own
  const borrowed = await verifyBundle(await selfSigned({ level: 'gateway+3p-enclave', signing_addresses: [real], gateway_addresses: [], simulated: false }, w));
  assert.equal(borrowed.valid, 0);
  assert.ok(borrowed.problems.length >= 2);
  // nor does listing both
  const both = await verifyBundle(await selfSigned({ level: 'gateway+3p-enclave', signing_addresses: [real], gateway_addresses: [mine], simulated: false }, w));
  assert.ok(both.problems.some((p) => p.includes(mine)));
  // evidence with no key at all proves nothing
  const none = await verifyBundle({ ...forged, attestation: { level: 'gateway+3p-enclave', signing_addresses: [], simulated: false } });
  assert.ok(none.problems.some((p) => p.includes('no signing key')));
});

test('every evidence bundle published for the live contract rests on proven keys', async () => {
  for (const f of readdirSync(join(WEB, 'evidence')).filter((x) => /^[0-9a-f]{64}\.json$/.test(x))) {
    const v = await verifyBundle(JSON.parse(readFileSync(join(WEB, 'evidence', f), 'utf8')));
    assert.equal(v.hardware, 'proven', f);
    assert.deepEqual(v.problems, [], f);
    assert.equal(v.evidence_hash + '.json', f);
  }
});
