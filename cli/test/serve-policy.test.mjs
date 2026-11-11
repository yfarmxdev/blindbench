import test from 'node:test';
import assert from 'node:assert/strict';
import { servePolicy } from '../lib/serve-policy.mjs';

const run = (id, model = 'a/cheap', requester = 'alice.near') => ({ id, model, requester });

test('serve limits: model and requester allowlists, run caps, and a failing run is not retried forever', () => {
  // Serving does not start without a model list and a total cap: both decide what the operator spends.
  assert.throws(() => servePolicy({}), /needs --models/);
  assert.throws(() => servePolicy({ models: 'a/cheap' }), /needs --max-runs/);
  const base = { models: 'a/cheap', 'max-runs': '10' };
  // A run that fails is not tried again unless --max-tries says so.
  const once = servePolicy(base);
  assert.equal(once.refuse(run(1, 'a/cheap', 'anyone.near')), null);
  once.start(run(1));
  assert.match(once.refuse(run(1)), /already tried 1 time/);
  assert.equal(once.refuse(run(2)), null);
  const twice = servePolicy({ ...base, 'max-tries': '2' });
  twice.start(run(1)); assert.equal(twice.refuse(run(1)), null);
  twice.start(run(1)); assert.match(twice.refuse(run(1)), /already tried 2 times/);
  // Counts outlive the process: what one serve saved, the next one starts from.
  let saved = null;
  const first = servePolicy({ ...base, 'max-runs': '2' }, { save: (s) => { saved = JSON.parse(JSON.stringify(s)); } });
  first.start(run(1)); first.start(run(2));
  const second = servePolicy({ ...base, 'max-runs': '2' }, { state: saved });
  assert.match(second.refuse(run(1)), /already tried 1 time/);
  assert.match(second.refuse(run(3)), /--max-runs 2 reached/);
  assert.match(second.describe(), /at most 2 runs \(2 already started\)/);
  assert.equal(servePolicy(base, { state: { started: 'x', per: 5, tries: { 1: -3 } } }).refuse(run(1)), null);

  const p = servePolicy({ models: 'a/cheap, b/cheap', requesters: 'alice.near,bob.near', 'max-runs': '3', 'max-per-requester': '2' });
  assert.match(p.refuse(run(1, 'c/expensive')), /not on --models/);
  assert.match(p.refuse(run(1, 'a/cheap', 'mallory.near')), /not on --requesters/);
  assert.equal(p.refuse(run(1)), null); p.start(run(1));
  assert.equal(p.refuse(run(2)), null); p.start(run(2));
  assert.match(p.refuse(run(3)), /--max-per-requester 2 reached for alice\.near/);
  assert.equal(p.refuse(run(4, 'b/cheap', 'bob.near')), null); p.start(run(4, 'b/cheap', 'bob.near'));
  assert.match(p.refuse(run(5, 'b/cheap', 'bob.near')), /--max-runs 3 reached/);
  assert.match(p.describe(), /models: a\/cheap, b\/cheap; requesters: alice\.near, bob\.near; at most 3 runs \(3 already started\); at most 2 per requester/);

  assert.equal(p.firstTime(run(9), 'x'), true);
  assert.equal(p.firstTime(run(9), 'x'), false);
  assert.match(servePolicy({ ...base, 'max-runs': '0' }).refuse(run(1)), /--max-runs 0 reached/);
  assert.throws(() => servePolicy({ ...base, 'max-runs': 'lots' }), /whole number/);
  assert.throws(() => servePolicy({ ...base, models: true }), /comma-separated/);
  assert.throws(() => servePolicy({ ...base, requesters: ' , ' }), /comma-separated/);
  assert.throws(() => servePolicy({ ...base, 'max-runs': true }), /whole number/);
});
