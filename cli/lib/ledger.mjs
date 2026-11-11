// LOCAL SIMULATION of the BlindBench contract, for the no-keys demo only.
// It mirrors contract/src/lib.rs (commit_dataset, request_run, fulfill_run,
// post_bounty, leaderboard) closely enough to show the flow; the real rules
// are the Rust contract's, which `cargo test` checks and testnet runs.
export class Ledger {
  constructor() { this.datasets = []; this.runs = []; this.certificates = []; this.bounties = []; this.balances = {}; }
  pay(to, amt) { this.balances[to] = (this.balances[to] ?? 0) + amt; }
  commit_dataset(owner, { root, items, description, price, grading, require_tee = true }) {
    const id = this.datasets.length;
    this.datasets.push({ id, owner, runner: owner, root, items, description, price, grading, require_tee, runs_completed: 0, earned: 0 });
    return id;
  }
  request_run(requester, { dataset_id, model }, deposit) {
    const ds = this.datasets[dataset_id];
    if (deposit < ds.price) throw new Error('attach at least the price');
    // the price is escrowed; anything above it goes straight back
    if (deposit > ds.price) this.pay(requester, deposit - ds.price);
    const id = this.runs.length;
    this.runs.push({ id, dataset_id, requester, model, paid: ds.price, status: 'Pending' });
    return id;
  }
  fulfill_run(caller, { run_id, score_bps, evidence_hash, tee, judge_model, breakdown = [] }) {
    const run = this.runs[run_id];
    const ds = this.datasets[run.dataset_id];
    if (run.status !== 'Pending') throw new Error('run is not pending');
    if (caller !== ds.runner) throw new Error('only the dataset runner can fulfil');
    if (ds.require_tee && (!tee || tee.signed_responses !== ds.items)) throw new Error('every item needs a TEE-signed response');
    if (ds.grading === 'rubric' && !judge_model) throw new Error('rubric grading must name its judge model');
    const id = this.certificates.length;
    this.certificates.push({ id, run_id, dataset_id: ds.id, dataset_root: ds.root, model: run.model, score_bps, items: ds.items, judge_model: judge_model ?? null, evidence_hash, tee, breakdown });
    run.status = 'Done';
    ds.runs_completed += 1; ds.earned += run.paid;
    this.pay(ds.owner, run.paid);
    const won = [];
    for (const b of this.bounties) {
      if (b.dataset_id === ds.id && !b.winner && score_bps >= b.threshold_bps) {
        b.winner = run.requester; b.winning_certificate = id; this.pay(run.requester, b.reward); won.push(b);
      }
    }
    return { id, won };
  }
  post_bounty(sponsor, { dataset_id, threshold_bps }, reward) {
    const id = this.bounties.length;
    this.bounties.push({ id, dataset_id, sponsor, threshold_bps, reward, winner: null });
    return id;
  }
  leaderboard(dataset_id) {
    return this.certificates.filter((c) => c.dataset_id === dataset_id).sort((a, b) => b.score_bps - a.score_bps || a.id - b.id);
  }
}
