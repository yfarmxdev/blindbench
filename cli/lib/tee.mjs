// NEAR AI Cloud TEE evidence: attestation report + per-response signatures.
//
// Docs: https://docs.near.ai/cloud/verification
//   GET /v1/attestation/report?model=..&signing_algo=ecdsa&nonce=<64 hex>
//       -> model_attestations[].signing_address (the enclave's signing key)
//   GET /v1/signature/<chat_id>?model=..&signing_algo=ecdsa
//       -> { text: "<model>:<sha256(req)>:<sha256(resp)>", signature, signing_address }
// ECDSA signatures are Ethereum EIP-191 personal-sign; we recover the signer.
//
// What this file checks: the report echoes our fresh nonce, every response
// signature recovers to the attested signing address, and the signed text
// commits to exactly the bytes we sent and received.
// The Intel TDX quote and the NVIDIA GPU evidence inside the report are checked
// by attest.mjs (web/tdx.mjs); the runner refuses to start if they fail.
import { verifyMessage } from 'ethers';
import { sha256, randomHex } from './util.mjs';

const base = (e) => e.replace(/\/$/, '');
const headers = (k) => ({ Accept: 'application/json', 'x-no-aliasing': 'true', ...(k ? { Authorization: `Bearer ${k}` } : {}) });

export async function attest({ endpoint, apiKey, model }) {
  const nonce = randomHex(32);
  const url = `${base(endpoint)}/attestation/report?model=${encodeURIComponent(model)}&signing_algo=ecdsa&nonce=${nonce}`;
  // The gateway fetches evidence from the provider on demand and that can be
  // rate-limited (429 behind a 503) when many runs start together: back off.
  let r, raw;
  for (let i = 0; ; i++) {
    try {
      r = await fetch(url, { headers: headers(apiKey), signal: AbortSignal.timeout(60000) });
      raw = await r.text();
      if (r.ok || i >= 5 || ![429, 502, 503, 504].includes(r.status)) break;
    } catch (e) { if (i >= 5) throw e; }
    await new Promise((ok) => setTimeout(ok, 10000 * 2 ** i));
  }
  if (!r.ok) throw new Error(`attestation ${model}: HTTP ${r.status} ${raw.slice(0, 200)}`);
  const report = JSON.parse(raw);
  const models = report.model_attestations ?? (report.signing_address ? [report] : []);
  const own = models.filter((a) => a.signing_address);
  const gw = report.gateway_attestation;
  const reportHash = sha256(raw);
  if (own.length) {
    // NEAR-run model enclave: it signs "<model>:<req>:<resp>" with its own key.
    return {
      level: 'model-enclave',
      nonce,
      nonceEchoed: own.some((a) => (a.request_nonce ?? '').toLowerCase() === nonce),
      signingAddresses: own.map((a) => a.signing_address.toLowerCase()),
      // The attested gateway signs streamed responses for these models too.
      gatewayAddresses: gw?.signing_address && (gw.request_nonce ?? '').toLowerCase() === nonce ? [gw.signing_address.toLowerCase()] : [],
      signingAlgo: 'ecdsa',
      reportSha256: reportHash,
      simulated: Boolean(report.simulated),
      report, raw,
    };
  }
  // Third-party TEE (e.g. Chutes): NEAR AI verifies the provider's enclave and
  // GPU evidence, and its own attested gateway signs "<req>:<resp>".
  const third = models.find((a) => String(a.verified) === 'True' || a.verified === true);
  if (!gw?.signing_address || !third) throw new Error(`attestation ${model}: no verifiable enclave evidence in report`);
  return {
    level: 'gateway+3p-enclave',
    provider: third.provider ?? null,
    providerVerdict: { verified: true, tcb_status: third.tcb_status ?? null, gpu_verdict: third.gpu_verdict ?? null },
    nonce,
    nonceEchoed: (gw.request_nonce ?? '').toLowerCase() === nonce && String(third.nonce ?? '').toLowerCase().startsWith(nonce.slice(0, 32)),
    signingAddresses: [gw.signing_address.toLowerCase()],
    signingAlgo: 'ecdsa',
    reportSha256: reportHash,
    simulated: Boolean(report.simulated),
    report, raw,
  };
}

export async function fetchSignature({ endpoint, apiKey, model, chatId, tries = 6 }) {
  const url = `${base(endpoint)}/signature/${encodeURIComponent(chatId)}?model=${encodeURIComponent(model)}&signing_algo=ecdsa`;
  for (let i = 0; i < tries; i++) {
    // A dropped connection or a gateway 5xx here would otherwise throw away an
    // answer that is already paid for: wait and ask for the signature again.
    let r, j;
    try {
      r = await fetch(url, { headers: headers(apiKey), signal: AbortSignal.timeout(30000) });
      if (r.status === 404) { await new Promise((ok) => setTimeout(ok, 1000 * (i + 1))); continue; }
      if (r.status >= 500 || r.status === 429) throw new Error(`HTTP ${r.status}`);
      j = await r.json();
    } catch (e) {
      if (i >= tries - 1) throw new Error(`signature ${chatId}: ${e.message}`);
      await new Promise((ok) => setTimeout(ok, 5000 * (i + 1)));
      continue;
    }
    // Some model gateways (Kimi K3, at times) deliver a response over an
    // end-to-end encrypted channel with no per-response signature to fetch.
    // The caller decides: re-ask, or record the item as unsigned.
    if (j.error_code === 'SIGNATURE_UNSUPPORTED') return { unsupported: true, text: null, signature: null, signing_address: null, message: j.message ?? '' };
    if (j.error_code) throw new Error(`signature ${chatId}: ${j.error_code} ${j.message ?? ''}`);
    return j;
  }
  throw new Error(`signature ${chatId}: not found after ${tries} tries`);
}

/**
 * The text an enclave signs for one request/response pair. The gateway signs
 * "<req>:<resp>"; a model enclave signs "<model>:<req>:<resp>", and the model it
 * names must be the model the evidence claims (not just any model's enclave).
 */
export function signedTextMatches(text, { requestSha256, responseSha256, model }) {
  const pair = `${requestSha256}:${responseSha256}`;
  if (typeof text !== 'string') return false;
  return text === pair || (model != null ? text === `${model}:${pair}` : text.endsWith(':' + pair));
}

/** True when sig is a valid enclave signature over exactly this request/response. */
export function checkSignature(sig, { requestSha256, responseSha256, attestedAddresses, model }) {
  const text = typeof sig?.text === 'string' ? sig.text : '';
  if (!signedTextMatches(text, { requestSha256, responseSha256, model })) return { ok: false, why: 'signed text does not match our bytes' };
  let recovered;
  try { recovered = verifyMessage(text, sig.signature).toLowerCase(); } catch { return { ok: false, why: 'bad signature' }; }
  if (recovered !== String(sig.signing_address).toLowerCase()) return { ok: false, why: 'signer mismatch' };
  if (!attestedAddresses.includes(recovered)) return { ok: false, why: 'signer is not the attested enclave key' };
  return { ok: true, signer: recovered, kind: sig.signature_kind ?? (text === `${requestSha256}:${responseSha256}` ? 'gateway' : 'provider_tee') };
}
