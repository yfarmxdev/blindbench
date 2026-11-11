// Hardware proof for NEAR AI Cloud enclave keys.
//
// tee.mjs checks that every answer is signed by the key an attestation report
// names. This file checks the report itself: the Intel TDX quote down to
// Intel's root certificate, that the quote binds the signing key and our nonce,
// Intel's verdict on the platform's TCB level, and NVIDIA's verdict on the GPUs
// (web/tdx.mjs holds the verification; the browser runs the same file).
//
// Proofs are saved as web/attestations/<signing address>.json. `verify` only
// accepts a signing key that has such a proof: an evidence file cannot vouch
// for its own key.
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { verifyQuote, verifyEnclave, fetchCollateral, verifyGpu, slimAttestation } from '../../web/tdx.mjs';
import { randomHex, sha256 } from './util.mjs';

export const PROOF_DIR = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'web', 'attestations');
const base = (e) => e.replace(/\/$/, '');

export async function fetchReport({ endpoint, apiKey, model, nonce = randomHex(32) }) {
  const url = `${base(endpoint)}/attestation/report?${model ? `model=${encodeURIComponent(model)}&` : ''}signing_algo=ecdsa&nonce=${nonce}`;
  let r, raw;
  for (let i = 0; ; i++) {
    try {
      r = await fetch(url, { headers: { Accept: 'application/json', ...(apiKey ? { Authorization: `Bearer ${apiKey}` } : {}) }, signal: AbortSignal.timeout(90000) });
      raw = await r.text();
      if (r.ok || i >= 4 || ![429, 502, 503, 504].includes(r.status)) break;
    } catch (e) { if (i >= 4) throw e; }
    await new Promise((ok) => setTimeout(ok, 5000 * 2 ** i));
  }
  if (!r.ok) throw new Error(`attestation ${model ?? 'gateway'}: HTTP ${r.status} ${raw.slice(0, 200)}`);
  return { raw, report: JSON.parse(raw), nonce, report_sha256: sha256(raw) };
}

/**
 * Verify every enclave in a report. Returns key proofs (ready to save) and a
 * line-by-line account. `online: false` skips Intel's collateral and NVIDIA.
 * Throws if a quote or a key binding fails, or if NVIDIA judged the GPU evidence
 * and it failed; a collateral or GPU service that cannot be reached is reported,
 * not fatal.
 */
export async function proveReport(report, { nonce, model = null, online = true } = {}) {
  const entries = [];
  if (report.gateway_attestation?.intel_quote) entries.push(['gateway', null, report.gateway_attestation]);
  for (const m of report.model_attestations ?? []) if (m.intel_quote && m.signing_address) entries.push(['model', m.model_name ?? model, m]);
  if (!entries.length) throw new Error('the report carries no TDX quote');
  const fetched_at = new Date().toISOString(), proofs = [], lines = [];
  for (const [role, name, att] of entries) {
    let collateral = null, gpu = null;
    const notes = [];
    if (online) {
      try { collateral = await fetchCollateral((await verifyQuote(att.intel_quote)).pck.fmspc); } catch (e) { notes.push(`Intel collateral not checked: ${e.message}`); }
      if (att.nvidia_payload) { try { gpu = await verifyGpu(att.nvidia_payload, { nonce }); } catch (e) { if (e.refused) throw new Error(`the ${role} enclave's GPU evidence was rejected: ${e.message}`); notes.push(`NVIDIA GPU evidence not checked: ${e.message}`); } }
    }
    if (collateral) { const { fetched_at: _, ...c } = collateral; collateral = c; }
    const rec = await verifyEnclave(att, { nonce, collateral });
    proofs.push({ version: 'blindbench-key-proof/1', role, model: name, nonce, fetched_at, attestation: slimAttestation(att), collateral, gpu });
    lines.push({ role, model: name, rec, gpu, notes });
  }
  return { proofs, lines };
}

export function saveProofs(proofs, dir = PROOF_DIR) {
  mkdirSync(dir, { recursive: true });
  const index = existsSync(join(dir, 'index.json')) ? JSON.parse(readFileSync(join(dir, 'index.json'), 'utf8')) : {};
  for (const p of proofs) {
    const a = p.attestation.signing_address.toLowerCase();
    writeFileSync(join(dir, `${a}.json`), JSON.stringify(p));
    index[a] = { role: p.role, model: p.model, fetched_at: p.fetched_at };
  }
  writeFileSync(join(dir, 'index.json'), JSON.stringify(Object.fromEntries(Object.entries(index).sort()), null, 1) + '\n');
}

/** proofFor(address) over a directory of saved key proofs (and, optionally, proofs made just now). */
export function proofStore(dir = PROOF_DIR, extra = []) {
  const live = new Map(extra.map((p) => [p.attestation.signing_address.toLowerCase(), p]));
  return async (address) => {
    if (!/^0x[0-9a-f]{40}$/.test(address)) return null;
    if (live.has(address)) return live.get(address);
    const f = join(dir, `${address}.json`);
    return existsSync(f) ? JSON.parse(readFileSync(f, 'utf8')) : null;
  };
}
