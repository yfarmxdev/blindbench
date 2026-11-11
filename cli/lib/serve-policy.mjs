// Limits for `serve`, the loop that fulfils paid runs with the operator's own inference key.
// Without limits anyone who pays the set's price decides what the operator spends: the model,
// how often, and (through a run that keeps failing) how many times the same run is tried.
// So serving does not start without two limits: the models it will pay for (--models) and
// how many runs in total (--max-runs). A flag given without a value must not read as "no limit".
// Counts are kept in a state the caller can save and load, so a restart does not reset them.
const list = (v) => (v == null ? null : v === true ? [] : String(v).split(',').map((s) => s.trim()).filter(Boolean));
const count = (v, flag) => {
  if (v == null) return Infinity;
  const n = v === true ? NaN : Number(v);
  if (!Number.isInteger(n) || n < 0) throw new Error(`${flag} takes a whole number, 0 or more`);
  return n;
};

/**
 * @param opt    the command's flags
 * @param state  counts from an earlier `serve` on the same contract and set ({ started, per, tries }), or nothing
 * @param save   called with the counts after every attempt, so the caller can write them to disk
 */
export function servePolicy(opt = {}, { state = null, save = () => {} } = {}) {
  const models = list(opt.models), requesters = list(opt.requesters);
  if (!models) throw new Error('serve needs --models <id,id,…>: the models you are willing to pay inference for');
  if (!models.length) throw new Error('--models takes a comma-separated list of model ids');
  if (requesters && !requesters.length) throw new Error('--requesters takes a comma-separated list of accounts');
  if (opt['max-runs'] == null) throw new Error('serve needs --max-runs <n>: the most runs it may start in total (each one spends your inference credit)');
  const maxRuns = count(opt['max-runs'], '--max-runs');
  const maxPer = count(opt['max-per-requester'], '--max-per-requester');
  const maxTries = opt['max-tries'] == null ? 1 : count(opt['max-tries'], '--max-tries');
  const whole = (n) => (Number.isSafeInteger(n) && n >= 0 ? n : 0);
  const counts = (o) => new Map(Object.entries(o && typeof o === 'object' ? o : {}).map(([k, n]) => [k, whole(n)]));
  let started = whole(state?.started);
  const per = counts(state?.per), tries = counts(state?.tries), told = new Set();
  return {
    describe() {
      const p = [];
      p.push(`models: ${models.join(', ')}`);
      p.push(requesters ? `requesters: ${requesters.join(', ')}` : 'any requester');
      p.push(`at most ${maxRuns} runs${started ? ` (${started} already started)` : ''}`);
      p.push(maxPer !== Infinity ? `at most ${maxPer} per requester` : 'no limit per requester');
      p.push(`a run is tried at most ${maxTries} time${maxTries === 1 ? '' : 's'}`);
      return p.join('; ');
    },
    // Why this run is left pending, or null to go ahead. A run left pending can be cancelled
    // by its requester after 24 hours, so nobody's deposit is stuck.
    refuse(run) {
      if (!models.includes(run.model)) return `model ${run.model} is not on --models`;
      if (requesters && !requesters.includes(run.requester)) return `requester ${run.requester} is not on --requesters`;
      if ((tries.get(String(run.id)) ?? 0) >= maxTries) return `already tried ${maxTries} time${maxTries === 1 ? '' : 's'}`;
      if (started >= maxRuns) return `--max-runs ${maxRuns} reached`;
      if ((per.get(run.requester) ?? 0) >= maxPer) return `--max-per-requester ${maxPer} reached for ${run.requester}`;
      return null;
    },
    // Every attempt counts, whether it ends in a certificate or not: inference was paid either way.
    start(run) {
      started++;
      per.set(run.requester, (per.get(run.requester) ?? 0) + 1);
      tries.set(String(run.id), (tries.get(String(run.id)) ?? 0) + 1);
      save({ started, per: Object.fromEntries(per), tries: Object.fromEntries(tries) });
    },
    // True the first time a (run, reason) pair is seen, so the poll loop logs it once.
    firstTime(run, why) { const k = `${run.id}|${why}`; if (told.has(k)) return false; told.add(k); return true; },
  };
}
