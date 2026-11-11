// The hosted page's defences, checked from the files: the response headers, the page's own
// markup, the pinned wallet list and the vendored libraries. A change that loosens one of
// these fails here before it is published.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';

const web = (f) => fileURLToPath(new URL('../../web/' + f, import.meta.url));
const read = (f) => readFileSync(web(f), 'utf8');
const sha256 = (f) => createHash('sha256').update(readFileSync(web(f))).digest('hex');

// The header block that applies to every path.
const headers = (() => {
  const out = {}; let on = false;
  for (const l of read('_headers').split('\n')) {
    if (!/^\s/.test(l)) { on = l.trim() === '/*'; continue; }
    const m = on && /^\s+([A-Za-z-]+):\s*(.+?)\s*$/.exec(l); if (m) out[m[1].toLowerCase()] = m[2];
  }
  return out;
})();
const policy = (text) => Object.fromEntries(text.split(';').map((d) => d.trim().split(/\s+/)).filter((d) => d[0]).map(([k, ...v]) => [k, v]));

test('response headers: every path gets the security headers', () => {
  assert.equal(headers['x-content-type-options'], 'nosniff');
  assert.equal(headers['x-frame-options'], 'DENY');
  assert.match(headers['strict-transport-security'], /^max-age=\d{8,}/);
  assert.ok(headers['referrer-policy'] && headers['permissions-policy'] && headers['cross-origin-opener-policy']);
});

test('content security policy: script only from this site, nothing embedded or framed', () => {
  const p = policy(headers['content-security-policy']);
  assert.deepEqual(p['default-src'], ["'none'"]);
  // No other host may serve script to the page, and strings are never run as code.
  // The one exception is the host's own visit counter, which the host adds to the page it serves.
  assert.deepEqual([...p['script-src']].sort(), ["'self'", "'unsafe-inline'", "'wasm-unsafe-eval'", 'https://static.cloudflareinsights.com']);
  for (const d of ['object-src', 'base-uri', 'form-action', 'frame-ancestors']) assert.deepEqual(p[d], ["'none'"], d);
  for (const [d, v] of Object.entries(p)) assert.ok(!v.includes('*') && !v.includes('http:') && !v.includes("'unsafe-eval'"), d);
});

test('page: the per-load nonce policy is set before anything is rendered, and reaches the wallet connector', () => {
  const html = read('index.html');
  const mod = html.slice(html.indexOf('<script type="module">'));
  const at = mod.indexOf("m.httpEquiv = 'Content-Security-Policy'");
  assert.ok(at > 0 && at < 2500, 'the policy is added at the top of the page script');
  assert.match(mod, /crypto\.getRandomValues\(new Uint8Array\(18\)\)/);
  assert.match(mod, /m\.content = `script-src 'self' 'nonce-\$\{NONCE\}' 'wasm-unsafe-eval' https:\/\/static\.cloudflareinsights\.com; object-src 'none'; base-uri 'none'`/);
  assert.match(mod, /new NearConnector\(\{[^\n]*cspNonce: NONCE/);
});

test('page: no on-event attributes, no javascript: links, no script from another host', () => {
  const html = read('index.html');
  // Attributes in the markup and in the HTML the script writes (template strings included).
  assert.deepEqual(html.match(/<[a-z][^<>]*\son[a-z]+\s*=/gi) ?? [], []);
  assert.ok(!/(href|src|action)\s*=\s*["'`]?\s*javascript:/i.test(html));
  assert.deepEqual(html.match(/<script[^>]*\ssrc\s*=/gi) ?? [], []);
  assert.equal((html.match(/<script/g) ?? []).length, 4, 'three small classic scripts and the page module');
  // Everything the page imports is one of its own files.
  const imports = [...html.matchAll(/import\(\s*['"]([^'"]+)['"]\s*\)|^import [^\n]* from\s+['"]([^'"]+)['"]/gm)].map((m) => m[1] ?? m[2]);
  assert.ok(imports.length >= 3);
  for (const from of imports) assert.match(from, /^\.\//);
});

test('page: the hosted site reads the official contract on testnet, whatever the link says', () => {
  const html = read('index.html');
  assert.match(html, /const NETWORK = LOCAL && q\.get\('network'\) === 'mainnet' \? 'mainnet' : 'testnet';/);
  assert.match(html, /const CONTRACT = LOCAL && isAccount\(q\.get\('contract'\)\) \? q\.get\('contract'\) : OFFICIAL;/);
  assert.match(html, /listed\.filter\(\(ds\) => ds\.owner === OFFICIAL\)/);
});

test('wallet list: this site\'s own file, GitHub-hosted connector code pinned to a commit', () => {
  const m = JSON.parse(read('vendor/wallets.json'));
  assert.ok(m.wallets.length >= 1);
  for (const w of m.wallets) {
    assert.equal(w.type, 'sandbox', w.id);
    assert.equal(w.features?.testnet, true, w.id);
    const u = new URL(w.executor);
    assert.equal(u.protocol, 'https:', w.id);
    if (u.host === 'raw.githubusercontent.com') assert.match(u.pathname, /^\/[^/]+\/[^/]+\/[0-9a-f]{40}\//, `${w.id}: a branch name can be moved, a commit cannot`);
  }
  assert.match(read('index.html'), /manifest: new URL\('vendor\/wallets\.json', location\.href\)\.href/);
});

test('vendored libraries are the recorded builds', () => {
  const notes = read('vendor/README.md');
  for (const f of ['ethers.min.js', 'near-connect.min.js']) assert.ok(notes.includes(sha256('vendor/' + f)), `${f} does not match the SHA-256 in vendor/README.md`);
});

test('unknown paths get a 404 page with no script', () => {
  assert.ok(existsSync(web('404.html')));
  assert.ok(!/<script/i.test(read('404.html')));
});

test('wallet frame: scripts and its own confirm dialogs only, never this site\'s origin or top navigation', () => {
  const lib = read('vendor/near-connect.min.js');
  const boxes = lib.match(/setAttribute\("sandbox","[^"]*"\)/g) ?? [];
  assert.deepEqual(boxes, ['setAttribute("sandbox","allow-scripts allow-modals")']);
});

test('page: the only transaction it builds is request_run on the pinned contract, under a price cap', () => {
  const html = read('index.html');
  const sends = html.match(/signAndSendTransactions?\(\{[^\n]*\n[^\n]*/g) ?? [];
  assert.equal(sends.length, 1);
  assert.match(sends[0], /signAndSendTransaction\(\{ receiverId: CONTRACT, actions: \[\{ type: 'FunctionCall', params: \{\s*methodName: 'request_run', args: \{ dataset_id: ds\.id, model \}, gas: '30000000000000', deposit: String\(ds\.price\) \} \}\] \}\)/);
  assert.match(html, /if \(paying \|\| !IS_OFFICIAL\) return;/);
  assert.match(html, /if \(BigInt\(ds\.price\) > PRICE_CAP\)/);
  assert.ok(!/addFunctionCallKey|signMessage|signDelegate/.test(html), 'the page asks a wallet for nothing else');
});
