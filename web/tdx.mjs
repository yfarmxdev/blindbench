// Intel TDX quote verification, written out in full so the whole check can be
// read in one file. No dependencies: it uses WebCrypto, so the same file runs
// in Node 20+ (the CLI) and in the browser (the web page).
//
// A TDX quote (version 4, ECDSA P-256) is checked in this order:
//   1. The PCK certificate chain inside the quote leads to Intel's SGX Root CA,
//      whose public key is pinned below (certificates.trustedservices.intel.com).
//   2. The PCK key signed the Quoting Enclave's report.
//   3. That report commits to the attestation key: sha256(key ‖ auth data).
//   4. The attestation key signed the quote header and the TD report body.
//   5. The TD is not a debug TD.
// What the TD report then proves is up to the caller: report_data (which key the
// enclave holds, and the caller's fresh nonce), MRCONFIGID (which compose file
// the enclave runs) and the RTMRs (replayed from the event log).
//
// With Intel's collateral (verifyCollateral) the platform's TCB level and the
// Quoting Enclave's identity are also judged against Intel's signed lists.
// Not done here: certificate revocation lists.

export const INTEL_SGX_ROOT_PUBKEY =
  '040ba9c4c0c0c86193a3fe23d6b02cda10a8bbd4e88e48b4458561a36e705525f567918e2edc88e40d860bd0cc4ee26aacc988e505a953558c453f6b0904ae7394';
export const INTEL_PCS = 'https://api.trustedservices.intel.com';

const subtle = globalThis.crypto.subtle;
export const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
export const unhex = (s) => {
  s = String(s).replace(/^0x/, '');
  if (s.length % 2 || /[^0-9a-f]/i.test(s)) throw new Error('not hex');
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.substr(2 * i, 2), 16);
  return out;
};
const utf8 = (s) => new TextEncoder().encode(s);
const text = (b) => new TextDecoder().decode(b);
const cat = (...xs) => { const o = new Uint8Array(xs.reduce((n, x) => n + x.length, 0)); let p = 0; for (const x of xs) { o.set(x, p); p += x.length; } return o; };
const same = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);
const digest = async (algo, b) => new Uint8Array(await subtle.digest(algo, b));
export const sha256hex = async (b) => hex(await digest('SHA-256', typeof b === 'string' ? utf8(b) : b));
const u16 = (b, o) => b[o] | (b[o + 1] << 8);
const u32 = (b, o) => (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0;
const b64 = (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/').replace(/\s+/g, '')), (c) => c.charCodeAt(0));

async function p256Verify(pubRaw, sigRaw, data) {
  const key = await subtle.importKey('raw', pubRaw, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
  return subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, sigRaw, data);
}

// ---------- just enough DER / X.509 ----------
function tlv(b, off) {
  if (off + 2 > b.length) throw new Error('DER: truncated');
  let len = b[off + 1], hl = 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n < 1 || n > 4) throw new Error('DER: bad length');
    if (off + 2 + n > b.length) throw new Error('DER: truncated');
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + b[off + 2 + i];
    hl = 2 + n;
  }
  if (off + hl + len > b.length) throw new Error('DER: truncated');
  return { tag: b[off], body: b.subarray(off + hl, off + hl + len), raw: b.subarray(off, off + hl + len), end: off + hl + len };
}
function kids(b) { const out = []; for (let o = 0; o < b.length;) { const t = tlv(b, o); out.push(t); o = t.end; } return out; }
const OID = (dotted) => {
  const p = dotted.split('.').map(Number), out = [p[0] * 40 + p[1]];
  for (const v of p.slice(2)) { const s = [v & 0x7f]; for (let x = Math.floor(v / 128); x > 0; x = Math.floor(x / 128)) s.unshift((x & 0x7f) | 0x80); out.push(...s); }
  return hex(out);
};
const SGX_EXT = OID('1.2.840.113741.1.13.1');
const derTime = (t) => {
  const s = text(t.body), y = t.tag === 0x17 ? (Number(s.slice(0, 2)) < 50 ? '20' : '19') + s.slice(0, 2) : s.slice(0, 4), r = s.slice(t.tag === 0x17 ? 2 : 4);
  return Date.parse(`${y}-${r.slice(0, 2)}-${r.slice(2, 4)}T${r.slice(4, 6)}:${r.slice(6, 8)}:${r.slice(8, 10)}Z`);
};
/** ECDSA signature: DER SEQUENCE { r, s } -> 64 raw bytes. */
function sigRaw(der) {
  const [r, s] = kids(tlv(der, 0).body).map((t) => { let v = t.body; while (v.length > 32 && v[0] === 0) v = v.subarray(1); if (v.length > 32) throw new Error('bad signature'); const o = new Uint8Array(32); o.set(v, 32 - v.length); return o; });
  return cat(r, s);
}
export function parseCert(der) {
  const [tbs, , sig] = kids(tlv(der, 0).body);
  const f = kids(tbs.body), v = f[0].tag === 0xa0 ? 1 : 0;
  const [notBefore, notAfter] = kids(f[v + 3].body).map(derTime);
  if (!Number.isFinite(notBefore) || !Number.isFinite(notAfter)) throw new Error('certificate has an unreadable validity period');
  const spki = kids(f[v + 5].body)[1].body.subarray(1);
  if (spki.length !== 65 || spki[0] !== 4) throw new Error('certificate key is not an uncompressed P-256 point');
  const cert = { tbs: tbs.raw, serial: hex(f[v].body), issuer: hex(f[v + 2].raw), subject: hex(f[v + 4].raw), notBefore, notAfter, publicKey: spki, signature: sigRaw(sig.body.subarray(1)), sgx: null };
  const ext = f.find((x) => x.tag === 0xa3);
  for (const e of ext ? kids(tlv(ext.body, 0).body) : []) {
    const p = kids(e.body);
    if (hex(p[0].body) !== SGX_EXT) continue;
    // SGX extensions: FMSPC, PCE id and the platform's TCB component numbers.
    const sgx = { fmspc: null, pceid: null, comp: [], pcesvn: null };
    const num = (t) => t.body.reduce((n, x) => n * 256 + x, 0);
    for (const row of kids(tlv(p[p.length - 1].body, 0).body)) {
      const [id, val] = kids(row.body), oid = hex(id.body);
      if (oid === SGX_EXT + '04') sgx.fmspc = hex(val.body);
      else if (oid === SGX_EXT + '03') sgx.pceid = hex(val.body);
      else if (oid === SGX_EXT + '02') for (const c of kids(val.body)) { const [cid, cv] = kids(c.body), n = cid.body[cid.body.length - 1]; if (n >= 1 && n <= 16) sgx.comp[n - 1] = num(cv); else if (n === 17) sgx.pcesvn = num(cv); }
    }
    cert.sgx = sgx;
  }
  return cert;
}
export const pemCerts = (pem) => [...String(pem).matchAll(/-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/g)].map((m) => parseCert(b64(m[1])));

/** Leaf first. Every certificate must be signed by the next, and the last must be Intel's pinned root. */
export async function verifyChain(certs, at = Date.now()) {
  if (certs.length < 2 || certs.length > 5) throw new Error('certificate chain has an unexpected length');
  if (!Number.isFinite(at)) throw new Error('no time to check the certificates against');
  const root = certs[certs.length - 1];
  if (hex(root.publicKey) !== INTEL_SGX_ROOT_PUBKEY) throw new Error('chain does not end at the Intel SGX Root CA');
  for (let i = 0; i < certs.length; i++) {
    const c = certs[i], by = certs[Math.min(i + 1, certs.length - 1)];
    if (c.issuer !== by.subject) throw new Error(`certificate ${i}: issuer is not the next certificate`);
    if (!(await p256Verify(by.publicKey, c.signature, c.tbs))) throw new Error(`certificate ${i}: bad signature`);
    if (at < c.notBefore || at > c.notAfter) throw new Error(`certificate ${i}: not valid at ${new Date(at).toISOString()}`);
  }
  return certs[0];
}

// ---------- the quote ----------
const HEADER = 48, BODY = 584;
export function parseQuote(q) {
  if (typeof q === 'string') q = /^[0-9a-fA-F]+$/.test(q) ? unhex(q) : b64(q);
  if (q.length < HEADER + BODY + 4) throw new Error('quote too short');
  const version = u16(q, 0), keyType = u16(q, 2), teeType = u32(q, 4);
  if (version !== 4) throw new Error(`quote version ${version} is not supported (expected 4)`);
  if (keyType !== 2) throw new Error('attestation key is not ECDSA P-256');
  if (teeType !== 0x81) throw new Error('not a TDX quote');
  const b = q.subarray(HEADER, HEADER + BODY), f = (a, z) => hex(b.subarray(a, z));
  const td = {
    tee_tcb_svn: Array.from(b.subarray(0, 16)), mrseam: f(16, 64), mrsignerseam: f(64, 112), seamattributes: f(112, 120),
    tdattributes: f(120, 128), xfam: f(128, 136), mrtd: f(136, 184), mrconfigid: f(184, 232), mrowner: f(232, 280), mrownerconfig: f(280, 328),
    rtmr: [f(328, 376), f(376, 424), f(424, 472), f(472, 520)], report_data: f(520, 584), debug: (b[120] & 1) === 1,
  };
  const sigLen = u32(q, HEADER + BODY), s = q.subarray(HEADER + BODY + 4, HEADER + BODY + 4 + sigLen);
  if (s.length !== sigLen || sigLen < 134) throw new Error('quote signature data truncated');
  const outerType = u16(s, 128), outer = s.subarray(134, 134 + u32(s, 130));
  if (outerType !== 6) throw new Error(`certification data type ${outerType} is not supported (expected 6)`);
  const qeReport = outer.subarray(0, 384), qeReportSig = outer.subarray(384, 448), authLen = u16(outer, 448), qeAuth = outer.subarray(450, 450 + authLen);
  const inner = outer.subarray(450 + authLen), innerType = u16(inner, 0), pem = inner.subarray(6, 6 + u32(inner, 2));
  if (innerType !== 5) throw new Error(`PCK certification type ${innerType} is not supported (expected 5)`);
  return {
    signed: q.subarray(0, HEADER + BODY), td, signature: s.subarray(0, 64), attestKey: s.subarray(64, 128), qeReport, qeReportSig, qeAuth, pck: text(pem),
    qe: { miscselect: hex(qeReport.subarray(16, 20)), attributes: hex(qeReport.subarray(48, 64)), mrsigner: hex(qeReport.subarray(128, 160)), isvprodid: u16(qeReport, 256), isvsvn: u16(qeReport, 258), report_data: hex(qeReport.subarray(320, 384)) },
  };
}

/**
 * Check a quote's signatures down to Intel's root. Throws on any failure.
 * Returns the TD report and what the collateral check needs.
 */
export async function verifyQuote(quote, { at = Date.now() } = {}) {
  const q = parseQuote(quote);
  const certs = pemCerts(q.pck);
  const pck = await verifyChain(certs, at);
  if (!(await p256Verify(pck.publicKey, q.qeReportSig, q.qeReport))) throw new Error('Quoting Enclave report is not signed by the PCK key');
  const bind = hex(await digest('SHA-256', cat(q.attestKey, q.qeAuth)));
  if (q.qe.report_data.slice(0, 64) !== bind) throw new Error('Quoting Enclave report does not commit to the attestation key');
  if (!(await p256Verify(cat(Uint8Array.of(4), q.attestKey), q.signature, q.signed))) throw new Error('quote is not signed by the attestation key');
  if (q.td.debug) throw new Error('the TD runs in debug mode');
  return { td: q.td, qe: q.qe, pck: { ...pck.sgx, serial: pck.serial, notAfter: pck.notAfter } };
}

// ---------- Intel collateral: TCB level and Quoting Enclave identity ----------
/** The exact bytes of one top-level JSON member, as Intel signed them. */
function memberBytes(body, name) {
  const start = body.indexOf(`"${name}":`) + name.length + 3, end = body.lastIndexOf(',"signature"');
  if (start < name.length + 3 || end < start) throw new Error(`collateral: no ${name}`);
  return body.slice(start, end);
}
async function signedJson(body, chainPem, name, at) {
  const signer = await verifyChain(pemCerts(chainPem), at);
  // Intel signs TCB info and enclave identities with its TCB Signing certificate, not with any certificate under its root.
  if (!text(unhex(signer.subject)).includes('Intel SGX TCB Signing')) throw new Error(`collateral: ${name} is not signed by Intel's TCB Signing certificate`);
  const raw = memberBytes(body, name), sig = JSON.parse(body).signature;
  if (!(await p256Verify(signer.publicKey, unhex(sig), utf8(raw)))) throw new Error(`collateral: ${name} is not signed by Intel`);
  const doc = JSON.parse(raw);
  const issued = Date.parse(doc.issueDate), next = Date.parse(doc.nextUpdate);
  if (!Number.isFinite(issued) || !Number.isFinite(next)) throw new Error(`collateral: ${name} has no readable issue or update date`);
  if (next < at) throw new Error(`collateral: ${name} expired on ${doc.nextUpdate}`);
  if (issued > at + 86400000) throw new Error(`collateral: ${name} was issued after the time it is checked for`);
  return doc;
}
export async function fetchCollateral(fmspc, { pcs = INTEL_PCS, fetch: f = globalThis.fetch } = {}) {
  const get = async (path, header) => {
    const r = await f(`${pcs}${path}`, { signal: AbortSignal.timeout(30000) });
    if (!r.ok) throw new Error(`Intel PCS ${path}: HTTP ${r.status}`);
    return { body: await r.text(), chain: decodeURIComponent(r.headers.get(header) ?? '') };
  };
  const [tcb, qe] = await Promise.all([get(`/tdx/certification/v4/tcb?fmspc=${fmspc}`, 'TCB-Info-Issuer-Chain'), get('/tdx/certification/v4/qe/identity', 'SGX-Enclave-Identity-Issuer-Chain')]);
  return { tcb, qe, fetched_at: new Date().toISOString() };
}
/**
 * Judge a verified quote against Intel's signed TCB info and QE identity.
 * Returns { tcb_status, advisories, qe_status, tcb_date }. Throws if the collateral
 * is not Intel's, is for another platform, or the Quoting Enclave is not Intel's.
 */
export async function verifyCollateral(v, col, { at = Date.now() } = {}) {
  const info = await signedJson(col.tcb.body, col.tcb.chain, 'tcbInfo', at);
  if (info.id !== 'TDX') throw new Error('collateral: TCB info is not for TDX');
  if (info.fmspc.toLowerCase() !== v.pck.fmspc || info.pceId.toLowerCase() !== v.pck.pceid) throw new Error('collateral: TCB info is for another platform');
  if (info.tdxModule && info.tdxModule.mrsigner.toLowerCase() !== v.td.mrsignerseam) throw new Error('TDX module signer is not Intel\'s');
  const level = info.tcbLevels.find((l) =>
    l.tcb.sgxtcbcomponents.every((c, i) => v.pck.comp[i] >= c.svn) && v.pck.pcesvn >= l.tcb.pcesvn && l.tcb.tdxtcbcomponents.every((c, i) => v.td.tee_tcb_svn[i] >= c.svn));
  if (!level) throw new Error('platform TCB matches no level in Intel\'s TCB info');
  const id = await signedJson(col.qe.body, col.qe.chain, 'enclaveIdentity', at);
  if (id.id !== 'TD_QE') throw new Error('collateral: identity is not the TDX Quoting Enclave\'s');
  const masked = (a, m) => hex(unhex(a).map((x, i) => x & unhex(m)[i]));
  if (id.mrsigner.toLowerCase() !== v.qe.mrsigner) throw new Error('Quoting Enclave is not signed by Intel');
  if (id.isvprodid !== v.qe.isvprodid) throw new Error('Quoting Enclave product id mismatch');
  if (masked(v.qe.miscselect, id.miscselectMask) !== masked(id.miscselect, id.miscselectMask) || masked(v.qe.attributes, id.attributesMask) !== masked(id.attributes, id.attributesMask)) throw new Error('Quoting Enclave attributes mismatch');
  const qeLevel = id.tcbLevels.find((l) => v.qe.isvsvn >= l.tcb.isvsvn);
  if (!qeLevel) throw new Error('Quoting Enclave version matches no level in Intel\'s identity');
  return { tcb_status: level.tcbStatus, tcb_date: level.tcbDate, advisories: level.advisoryIDs ?? [], qe_status: qeLevel.tcbStatus, collateral_issued: info.issueDate };
}

// ---------- what the TD report says about a NEAR AI Cloud enclave ----------
/** Replay an event log into the four RTMRs (sha384 extend) and compare with the quote. */
export async function replayRtmrs(td, events) {
  const rt = [0, 1, 2, 3].map(() => new Uint8Array(48));
  for (const e of events) rt[e.imr] = await digest('SHA-384', cat(rt[e.imr], unhex(e.digest)));
  return rt.map((r, i) => hex(r) === td.rtmr[i]);
}
const asObj = (x) => (typeof x === 'string' ? JSON.parse(x) : x);

/**
 * Verify one attestation entry from NEAR AI Cloud's /v1/attestation/report
 * (the gateway's, or a model enclave's): the quote itself, then that the enclave
 * holds `signing_address` and (if given) answered our nonce, and which compose
 * file it runs. Returns a flat record of what was proven; throws if the quote
 * or the key binding fails.
 */
export async function verifyEnclave(att, { nonce = null, at = Date.now(), collateral = null } = {}) {
  const v = await verifyQuote(att.intel_quote ?? att.quote_b64 ?? att.quote, { at });
  const rd = v.td.report_data, addr = String(att.signing_address ?? '').toLowerCase().replace(/^0x/, '');
  // report_data = signing address (20 bytes, zero-padded to 32) ‖ the caller's nonce.
  if (!/^[0-9a-f]{40}$/.test(addr) || rd.slice(0, 64) !== addr.padEnd(64, '0')) throw new Error('quote does not bind the signing address');
  const out = {
    signing_address: '0x' + addr, nonce: rd.slice(64), nonce_fresh: nonce ? rd.slice(64) === nonce.toLowerCase() : null,
    mrtd: v.td.mrtd, rtmr: v.td.rtmr, mrconfigid: v.td.mrconfigid, fmspc: v.pck.fmspc, tee_tcb_svn: hex(v.td.tee_tcb_svn),
    compose_hash: null, compose_bound: false, app_id: att.info?.app_id ?? null, os_image_hash: null, images: [], rtmr_replayed: null, tcb: null,
  };
  if (nonce && !out.nonce_fresh) throw new Error('quote does not carry our nonce (stale or replayed)');
  const tcb = asObj(att.info?.tcb_info ?? null);
  if (tcb?.app_compose) {
    // dstack puts 0x01 ‖ sha256(app_compose) in MRCONFIGID, so the quote names the compose file.
    out.compose_hash = await sha256hex(tcb.app_compose);
    out.compose_bound = v.td.mrconfigid === ('01' + out.compose_hash).padEnd(96, '0');
    out.os_image_hash = tcb.os_image_hash ?? null;
    try { out.images = [...new Set([...String(JSON.parse(tcb.app_compose).docker_compose_file ?? '').matchAll(/image:\s*(\S+@sha256:[0-9a-f]{64})/g)].map((m) => m[1]))]; } catch { /* compose is not JSON */ }
  }
  const events = asObj(att.event_log ?? tcb?.event_log ?? null);
  if (Array.isArray(events)) out.rtmr_replayed = await replayRtmrs(v.td, events);
  if (collateral) out.tcb = await verifyCollateral(v, collateral, { at });
  out.fmspc = v.pck.fmspc;
  return out;
}

/** The parts of an attestation entry needed to re-verify it later (drops GPU evidence and logs). */
export function slimAttestation(att) {
  const tcb = asObj(att.info?.tcb_info ?? null);
  return {
    signing_address: att.signing_address, signing_algo: att.signing_algo ?? 'ecdsa', model_name: att.model_name ?? null, intel_quote: att.intel_quote,
    event_log: asObj(att.event_log ?? tcb?.event_log ?? null),
    info: { app_id: att.info?.app_id ?? null, tcb_info: tcb ? { app_compose: tcb.app_compose, os_image_hash: tcb.os_image_hash } : null },
  };
}

// ---------- NVIDIA GPU evidence, judged by NVIDIA's attestation service ----------
export const NVIDIA_NRAS = 'https://nras.attestation.nvidia.com';
const b64u = (s) => b64(s + '='.repeat((4 - (s.length % 4)) % 4));
/**
 * Send the enclave's GPU evidence to NVIDIA (NRAS) and check the answer: the
 * token must be signed by a key from NVIDIA's published key set, say the GPUs
 * passed, and carry the same nonce as the TDX quote. An error with `refused: true`
 * means the evidence or the token was judged and failed; any other error means
 * NVIDIA's service could not be asked.
 */
const refusal = (m) => Object.assign(new Error(m), { refused: true });
export async function verifyGpu(nvidiaPayload, { nonce, nras = NVIDIA_NRAS, fetch: f = globalThis.fetch } = {}) {
  const payload = asObj(nvidiaPayload);
  if (nonce && String(payload.nonce).toLowerCase() !== nonce.toLowerCase()) throw refusal('GPU evidence does not carry our nonce');
  const r = await f(`${nras}/v3/attest/gpu`, { method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json' }, body: JSON.stringify(payload), signal: AbortSignal.timeout(60000) });
  if (!r.ok) throw new Error(`NVIDIA NRAS: HTTP ${r.status}`);
  const body = await r.json(), jwt = body?.[0]?.[1];
  if (typeof jwt !== 'string') throw new Error('NVIDIA NRAS: no token in the answer');
  const [h, p, s] = jwt.split('.'), head = JSON.parse(text(b64u(h))), claims = JSON.parse(text(b64u(p)));
  const jwks = await (await f(`${nras}/.well-known/jwks.json`, { signal: AbortSignal.timeout(30000) })).json();
  const jwk = jwks.keys.find((k) => k.kid === head.kid);
  if (!jwk || head.alg !== 'ES384') throw refusal('NVIDIA NRAS: token key is not in NVIDIA\'s key set');
  const key = await subtle.importKey('jwk', { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y }, { name: 'ECDSA', namedCurve: 'P-384' }, false, ['verify']);
  if (!(await subtle.verify({ name: 'ECDSA', hash: 'SHA-384' }, key, b64u(s), utf8(`${h}.${p}`)))) throw refusal('NVIDIA NRAS: bad token signature');
  if (claims.exp && claims.exp * 1000 < Date.now()) throw new Error('NVIDIA NRAS: token expired');
  if (nonce && String(claims.eat_nonce).toLowerCase() !== nonce.toLowerCase()) throw refusal('NVIDIA NRAS: token is for another nonce');
  if (claims['x-nvidia-overall-att-result'] !== true) throw refusal('NVIDIA NRAS: GPUs did not pass');
  return { gpus: payload.evidence_list?.length ?? 0, arch: payload.arch ?? payload.evidence_list?.[0]?.arch ?? null, verdict: true, issuer: claims.iss ?? null };
}

// ---------- saved proofs ----------
/**
 * A key proof is a saved attestation entry plus the Intel collateral fetched
 * with it: { role: 'gateway' | 'model', model, nonce, fetched_at, attestation,
 * collateral, gpu }. Re-verify it from scratch, as of the time it was fetched.
 */
export async function verifyKeyProof(p) {
  const at = Date.parse(p.fetched_at);
  if (!Number.isFinite(at)) throw new Error('key proof has no fetch time');
  const rec = await verifyEnclave(p.attestation, { nonce: p.nonce ?? null, at, collateral: p.collateral ?? null });
  return { ...rec, role: p.role, model: p.model ?? null, fetched_at: p.fetched_at, gpu: p.gpu ?? null };
}

/**
 * Intel's verdict on a platform or Quoting Enclave TCB level, as this code treats it:
 * 'ok' (up to date, or Intel only asks for configuration or software hardening),
 * 'warn' (out of date: genuine hardware that is behind on updates) or 'bad' (revoked or unknown).
 */
export const tcbVerdict = (status) =>
  ['UpToDate', 'SWHardeningNeeded', 'ConfigurationNeeded', 'ConfigurationAndSWHardeningNeeded'].includes(status) ? 'ok'
    : ['OutOfDate', 'OutOfDateConfigurationNeeded'].includes(status) ? 'warn' : 'bad';

/**
 * Which keys may sign for a bundle, and are they hardware-backed?
 * `proofFor(address)` returns a saved key proof or null. A model-enclave key
 * must be proven for exactly this model; a gateway key by a gateway proof.
 * Returns one row per key: { address, role, ok, why, warn, proof }.
 *
 * What a passing row establishes: a genuine Intel TDX quote, valid when the
 * proof was fetched, binds this address and names the enclave's compose file,
 * and Intel's signed collateral does not revoke the platform. What it takes
 * from the published proof file, unsigned: the role, the model name, the fetch
 * time and the recorded NVIDIA verdict. The compose file is hashed into the
 * quote, but no list of approved compose files or measurements is enforced.
 */
export async function proveKeys(attestation, model, proofFor) {
  const lower = (xs) => (xs ?? []).map((a) => String(a).toLowerCase());
  const own = lower(attestation?.signing_addresses), gw = lower(attestation?.gateway_addresses);
  const enclave = attestation?.level === 'model-enclave';
  const rows = [];
  for (const [address, role] of [...own.map((a) => [a, enclave ? 'model' : 'gateway']), ...gw.map((a) => [a, 'gateway'])]) {
    const row = { address, role, ok: false, why: null, warn: null, proof: null };
    try {
      const p = await proofFor(address);
      if (!p) throw new Error('no hardware quote is published for this key');
      const rec = await verifyKeyProof(p);
      if (rec.signing_address !== address) throw new Error('the quote is for another key');
      if (rec.role !== role) throw new Error(`the quote is for a ${rec.role} enclave, the evidence uses the key as a ${role} key`);
      if (role === 'model' && rec.model !== model) throw new Error(`the quote is for ${rec.model}'s enclave`);
      if (!rec.compose_bound) throw new Error('the quote does not name the enclave\'s compose file');
      // Intel's signed TCB info must be saved with the proof, and must not revoke the platform or the Quoting Enclave.
      if (!rec.tcb) throw new Error('the proof carries no Intel TCB collateral, so the platform\'s patch level is unchecked');
      const verdicts = [tcbVerdict(rec.tcb.tcb_status), tcbVerdict(rec.tcb.qe_status)];
      if (verdicts.includes('bad')) throw new Error(`Intel's collateral rates this platform ${rec.tcb.tcb_status} (Quoting Enclave ${rec.tcb.qe_status})`);
      if (verdicts.includes('warn')) row.warn = `Intel rated this platform ${rec.tcb.tcb_status} (Quoting Enclave ${rec.tcb.qe_status}) when the quote was fetched: genuine hardware that was behind on updates`;
      row.ok = true; row.proof = rec;
    } catch (e) { row.why = e.message ?? String(e); }
    rows.push(row);
  }
  return rows;
}
