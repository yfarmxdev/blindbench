// "tests" grading: the model writes a Python module, and hidden unit tests run
// against it. Score = share of tests passed. Objective, so no judge model.
//
// The tests belong to the private set (committed in its Merkle leaf like any
// answer key) and never leave the runner's machine. Model code is untrusted,
// so every test runs in its own short-lived python3 process with CPU (5 s),
// memory (1 GB) and file-size limits, a wall-clock timeout (30 s) and at most
// one sandbox per core at a time. On Linux the process is also jailed in fresh
// namespaces with a new root that holds only Python (see sandbox() below).
//
// What this does and does not defend. The jail protects the runner's machine
// and the private set, and the token below stops an answer that prints its own
// "pass" line or exits early. But a test runs in the same Python process as the
// code it tests, so code written to attack the harness (reading the token out
// of the interpreter) could still write a pass. The canary catches that: one
// passed test per item is run again inverted (it passes only if the real test
// fails). An honest module can never pass both, so a module that does is forging
// verdicts and the item scores 0. Code that also reads the hidden test and tells
// the two runs apart is not caught; closing that fully means running tests in a
// separate process from the code under test (see the roadmap).
import { spawn, spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir, cpus } from 'node:os';
import { join } from 'node:path';
import { randomHex } from './util.mjs';

// Runs inside the sandboxed process. Reads {code, test, token} from stdin
// (before any model code runs), executes the model's module, then one test.
// The verdict line carries a random token that is not in the model's namespace,
// so printing a verdict or exiting early cannot fake a pass. With "invert" the
// verdict flips: ok only if the test raised (the canary run, see above).
const HARNESS = String.raw`
import sys, json, os, resource
d = json.loads(sys.stdin.read()); sys.stdin.close()
tok, code, test, inv = d.pop('token'), d.pop('code'), d.pop('test'), d.pop('invert', False)
mem = 1 << 30
for r, v in ((resource.RLIMIT_AS, mem), (resource.RLIMIT_CPU, d['cpu']), (resource.RLIMIT_FSIZE, 1 << 20)):
    try: resource.setrlimit(r, (v, v))
    except Exception: pass
out = os.dup(1)
def _same(a, b):
    if type(a) is not type(b): return False
    if isinstance(a, (list, tuple)): return len(a) == len(b) and all(_same(x, y) for x, y in zip(a, b))
    if isinstance(a, dict): return a.keys() == b.keys() and all(_same(a[k], b[k]) for k in a)
    if isinstance(a, (set, frozenset)): return a == b
    return a == b
def _eq(got, exp):
    if not _same(got, exp): raise AssertionError('got %r, expected %r' % (got, exp))
def _raises(exc, fn, *a, **k):
    try: fn(*a, **k)
    except exc: return
    except BaseException as e: raise AssertionError('expected %s, got %s' % (exc.__name__, type(e).__name__))
    raise AssertionError('expected %s, nothing raised' % exc.__name__)
ok, err = False, None
try:
    ns = {'__name__': 'solution', '__builtins__': __builtins__}
    exec(compile(code, 'solution.py', 'exec'), ns)
    ns.update(_eq=_eq, _raises=_raises)
    try:
        exec(compile(test, 'test.py', 'exec'), ns)
        ok = not inv
    except BaseException as e:
        ok, err = bool(inv), (type(e).__name__ + ': ' + str(e))[:300]
except BaseException as e:
    ok, err = False, (type(e).__name__ + ': ' + str(e))[:300]
os.write(out, (json.dumps({'token': tok, 'ok': ok, 'err': err}) + '\n').encode())
os._exit(0)
`;

// How well the model's code is boxed in, best first. Decided once per process.
//   isolated: its own user, mount, pid, network, ipc and uts namespaces, and a
//             new root that holds only a read-only Python runtime and an empty
//             scratch directory. No host files, no other processes, no network.
//   network:  only the network is cut off; host files are readable.
//   none:     an ordinary child process with resource limits (macOS, Windows,
//             or a Linux that forbids unprivileged namespaces).
// A real run refuses anything below "isolated" unless BLINDBENCH_WEAK_SANDBOX=1,
// because the runner's machine holds the private set and its keys.
const JAIL = String.raw`
set -e
R="$PWD/root"; mkdir -p "$R"
mount -t tmpfs -o size=32m,mode=755 tmpfs "$R"
py="$1"; shift
for d in "$@"; do
  [ -d "$d" ] || continue
  mkdir -p "$R$d"
  mount --rbind "$d" "$R$d"
  mount -o remount,bind,ro "$R$d" 2>/dev/null || mount -o remount,bind,ro,nosuid,nodev "$R$d"
done
for l in /bin /sbin /lib /lib64 /lib32; do if [ -L "$l" ] && [ ! -e "$R$l" ]; then cp -P "$l" "$R$l"; fi; done
mkdir -p "$R/work" "$R/old"
mount -t tmpfs -o size=8m,mode=700 tmpfs "$R/work"
cd "$R"
pivot_root . old
exec chroot . "$py" -I -c '
import ctypes, os, sys
os.chdir("/work")
# Detach the old root: after this the host file system cannot be reached at all.
if ctypes.CDLL(None, use_errno=True).umount2(b"/old", 2) != 0 or os.listdir("/old"): sys.exit(97)
os.rmdir("/old")
src = os.environ.pop("BB_HARNESS")
exec(compile(src, "harness", "exec"))
'
`;
const NS = ['--user', '--map-root-user', '--net', '--pid', '--fork', '--kill-child', '--mount', '--ipc', '--uts'];
let BOX = null;
export function sandbox() {
  if (BOX) return BOX;
  BOX = { level: 'none', python: 'python3', roots: [], lib: '' };
  const probe = spawnSync('python3', ['-I', '-c', 'import sys,os;print(os.path.realpath(sys.executable));print(sys.base_prefix)'], { encoding: 'utf8', timeout: 10000 });
  if (probe.status !== 0) return BOX;
  const [exe, prefix] = probe.stdout.trim().split('\n');
  const roots = [...new Set(['/usr', '/bin', '/sbin', '/lib', '/lib64', '/lib32', prefix.startsWith('/usr') ? null : prefix].filter(Boolean))];
  const dir = mkdtempSync(join(tmpdir(), 'bb-probe-'));
  try {
    const env = { PATH: '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', BB_HARNESS: 'import os,sys;sys.exit(0 if sorted(set(os.listdir("/")) - {"usr", "bin", "sbin", "lib", "lib64", "lib32"}) == ["work"] else 3)', LD_LIBRARY_PATH: join(prefix, 'lib') };
    const full = spawnSync('unshare', [...NS, 'sh', '-c', JAIL, 'jail', exe, ...roots], { cwd: dir, env, stdio: 'ignore', timeout: 10000 });
    if (full.status === 0) BOX = { level: 'isolated', python: exe, roots, lib: join(prefix, 'lib') };
    else if (spawnSync('unshare', ['-rn', 'python3', '-c', 'pass'], { stdio: 'ignore', timeout: 5000 }).status === 0) BOX.level = 'network';
  } finally { rmSync(dir, { recursive: true, force: true }); }
  return BOX;
}

function runOne(code, test, { timeoutMs = 30000, cpuSeconds = 5, invert = false } = {}) {
  return new Promise((resolve) => {
    const dir = mkdtempSync(join(tmpdir(), 'bb-test-'));
    const token = randomHex(16);
    const box = sandbox();
    const [cmd, args] = box.level === 'isolated' ? ['unshare', [...NS, 'sh', '-c', JAIL, 'jail', box.python, ...box.roots]]
      : box.level === 'network' ? ['unshare', ['-rn', 'python3', '-I', '-c', HARNESS]] : ['python3', ['-I', '-c', HARNESS]];
    const env = box.level === 'isolated' ? { PATH: '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', PYTHONHASHSEED: '0', HOME: '/work', BB_HARNESS: HARNESS, LD_LIBRARY_PATH: box.lib }
      : { PATH: process.env.PATH, PYTHONHASHSEED: '0', HOME: dir };
    const p = spawn(cmd, args, { cwd: dir, env, stdio: ['pipe', 'pipe', 'pipe'] });
    let out = '', done = false;
    const finish = (r) => { if (done) return; done = true; clearTimeout(t); try { p.kill('SIGKILL'); } catch {} rmSync(dir, { recursive: true, force: true }); resolve(r); };
    const t = setTimeout(() => finish({ ok: false, err: 'timeout' }), timeoutMs);
    p.stdout.on('data', (b) => { out += b; if (out.length > 1 << 20) out = out.slice(-65536); });
    p.stderr.on('data', () => {});
    p.on('error', (e) => finish({ ok: false, err: 'could not start python3: ' + e.message }));
    p.on('close', () => {
      const line = out.split('\n').reverse().find((l) => l.includes(token));
      let v = null;
      try { v = line && JSON.parse(line); } catch {}
      finish(v && v.token === token ? { ok: v.ok, err: v.err } : { ok: false, err: 'no verdict (crashed or exited early)' });
    });
    p.stdin.on('error', () => {});
    p.stdin.end(JSON.stringify({ code, test, token, cpu: cpuSeconds, invert }));
  });
}

/** The model's module: the last fenced Python block that defines every entry point. */
export function extractCode(text, entry = []) {
  const blocks = [...String(text).matchAll(/```[ \t]*(python3?|py)?[^\n]*\n([\s\S]*?)```/gi)].map((m) => ({ lang: (m[1] ?? '').toLowerCase(), code: m[2] }));
  const defines = (c) => entry.every((e) => new RegExp(`^\\s*(def|class|async\\s+def)\\s+${e}\\b|^${e}\\s*=`, 'm').test(c));
  const py = blocks.filter((b) => b.lang);
  for (const pool of [py.filter((b) => defines(b.code)), blocks.filter((b) => defines(b.code)), py, blocks]) {
    if (pool.length) return pool[pool.length - 1].code;
  }
  // No fence: accept a bare module.
  return /^\s*(def|class|import|from)\s/m.test(text) ? String(text) : '';
}

// One pool of sandbox slots per process, so items graded in parallel never run more
// sandboxes than there are cores (a starved sandbox would hit the wall clock and fail).
const SLOTS = { free: Math.max(2, cpus().length), wait: [] };
const acquire = () => (SLOTS.free > 0 ? (SLOTS.free--, Promise.resolve()) : new Promise((r) => SLOTS.wait.push(r)));
const release = () => { const next = SLOTS.wait.shift(); if (next) next(); else SLOTS.free++; };

/** Grade one "tests" item: { entry: [...], tests: [{ id, code }], timeout_s?, cpu_s? }. */
export async function gradeTests(item, text, { concurrency = Math.max(2, Math.min(8, cpus().length)), requireIsolation = false } = {}) {
  if (requireIsolation && sandbox().level !== 'isolated' && process.env.BLINDBENCH_WEAK_SANDBOX !== '1') {
    throw new Error(`tests grading needs an isolated sandbox, and this machine only offers "${sandbox().level}" (unprivileged Linux namespaces are missing). Model code would be able to read this machine's files. Run on Linux with user namespaces enabled, or set BLINDBENCH_WEAK_SANDBOX=1 to accept that.`);
  }
  const code = extractCode(text, item.entry ?? []);
  if (!code.trim()) return { score: 0, detail: { extracted: false, passed: 0, total: item.tests.length, failed: item.tests.map((t) => t.id) } };
  const results = new Array(item.tests.length);
  const queue = item.tests.map((t, i) => [t, i]);
  await Promise.all(Array.from({ length: Math.min(concurrency, queue.length) }, async () => {
    while (queue.length) {
      const [t, i] = queue.shift();
      await acquire();
      try {
        // CPU time is the real limit; the wall clock only catches code that sleeps or blocks.
        results[i] = { id: t.id, ...(await runOne(code, t.code, { timeoutMs: (item.timeout_s ?? 30) * 1000, cpuSeconds: item.cpu_s ?? 5 })) };
      } finally { release(); }
    }
  }));
  // Canary: an honest module cannot pass a test and its inverse. Checked twice,
  // so one flaky run is not mistaken for a forgery.
  const probe = results.findIndex((r) => r.ok);
  if (probe >= 0) {
    const limits = { timeoutMs: (item.timeout_s ?? 30) * 1000, cpuSeconds: item.cpu_s ?? 5, invert: true };
    let forged = true;
    for (let n = 0; n < 2 && forged; n++) {
      await acquire();
      try { forged = (await runOne(code, item.tests[probe].code, limits)).ok; } finally { release(); }
    }
    if (forged) return { score: 0, detail: { extracted: true, passed: 0, total: item.tests.length, forged_verdict: true, failed: item.tests.map((t) => ({ id: t.id, err: 'verdicts not trusted: the module passed a test and its inverse' })) } };
  }
  const passed = results.filter((r) => r.ok).length;
  return { score: passed / item.tests.length, detail: { extracted: true, passed, total: item.tests.length, failed: results.filter((r) => !r.ok).map((r) => ({ id: r.id, err: r.err })) } };
}
