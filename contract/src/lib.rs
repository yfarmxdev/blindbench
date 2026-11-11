//! # BlindBench: private eval registry and marketplace
//!
//! A private eval set is only valuable while nobody has seen it. This contract
//! lets its owner earn from it anyway:
//!
//! 1. **commit_dataset**: the owner publishes a *commitment* (a Merkle root
//!    over the items), the item count, a public description and a price per
//!    run. The questions themselves never come onchain.
//! 2. **request_run** (payable): anyone pays the price to have a model scored.
//!    The price sits in escrow; anything attached above it is sent straight back.
//! 3. **fulfill_run**: the dataset's runner (the account that holds the data
//!    and talks to the NEAR AI Cloud TEE) submits the score, the hash of the
//!    evidence bundle and the TEE evidence. A certificate is issued, the owner
//!    is paid, and any open bounty the score clears is paid to the requester.
//! 4. **cancel_run**: if the runner never answers, the requester takes the
//!    deposit back after `RUN_TIMEOUT_NS`.
//!
//! Bounties: anyone can lock a reward on a dataset ("first model to reach
//! 90%"); the first fulfilled run at or above the threshold claims it.
use near_sdk::store::{IterableSet, Vector};
use near_sdk::{env, near, require, AccountId, NearToken, PanicOnDefault, Promise};

/// A requester can reclaim an unanswered run after 24 hours.
pub const RUN_TIMEOUT_NS: u64 = 24 * 60 * 60 * 1_000_000_000;
const MAX_DESCRIPTION: usize = 280;
const MAX_URI: usize = 512;
const MAX_NAME: usize = 128;
/// Every fulfilment looks at the open bounties, so their number is capped and
/// each one must be worth posting.
const MAX_OPEN_BOUNTIES: u32 = 100;
const MIN_BOUNTY: NearToken = NearToken::from_millinear(100);

/// Ids are u64 in the interface and u32 in storage. An id that does not fit is
/// rejected instead of wrapping around onto another record.
fn slot(id: u64) -> Option<u32> {
    u32::try_from(id).ok()
}

/// Printable ASCII without spaces at the ends: what a name or key may hold.
fn is_plain(s: &str, max: usize) -> bool {
    !s.is_empty() && s.len() <= max && s.chars().all(|c| c.is_ascii_graphic() || c == ' ') && s.trim() == s
}

#[near(serializers = [json, borsh])]
#[derive(Clone, Debug, PartialEq)]
pub enum RunStatus {
    Pending,
    Done,
    Cancelled,
}

#[near(serializers = [json, borsh])]
#[derive(Clone, Debug)]
pub struct TeeEvidence {
    /// Model enclave signing address from NEAR AI Cloud /v1/attestation/report.
    pub signing_address: String,
    /// "ecdsa" or "ed25519".
    pub signing_algo: String,
    /// sha256 (hex) of the raw attestation report the runner verified.
    pub attestation_hash: String,
    /// Responses that carried a valid per-response enclave signature.
    pub signed_responses: u32,
}

#[near(serializers = [json, borsh])]
#[derive(Clone, Debug)]
pub struct Dataset {
    pub id: u64,
    pub owner: AccountId,
    /// Account allowed to fulfil runs (holds the data). Defaults to the owner.
    pub runner: AccountId,
    /// Merkle root (hex sha256) over the canonical items.
    pub root: String,
    pub items: u32,
    /// Public description, e.g. "40 contract-law questions, exact-answer".
    pub description: String,
    pub price: NearToken,
    /// "exact", "checklist", "rubric" or "tests" (hidden unit tests run on the model's code): how answers are graded.
    pub grading: String,
    /// When true, a run is only accepted with TEE evidence for every item.
    pub require_tee: bool,
    pub created_ns: u64,
    pub runs_completed: u32,
    pub earned: NearToken,
    /// Set if the owner later reveals the items so anyone can re-grade.
    pub reveal_uri: Option<String>,
}

#[near(serializers = [json, borsh])]
#[derive(Clone, Debug)]
pub struct Run {
    pub id: u64,
    pub dataset_id: u64,
    pub requester: AccountId,
    pub model: String,
    pub paid: NearToken,
    pub status: RunStatus,
    pub created_ns: u64,
    pub certificate_id: Option<u64>,
}

#[near(serializers = [json, borsh])]
#[derive(Clone, Debug)]
pub struct Certificate {
    pub id: u64,
    pub run_id: u64,
    pub dataset_id: u64,
    /// Dataset root at issue time, so the certificate is self-contained.
    pub dataset_root: String,
    pub model: String,
    pub runner: AccountId,
    pub score_bps: u32,
    pub items: u32,
    /// Model that graded open-ended answers (rubric mode), if any.
    pub judge_model: Option<String>,
    /// sha256 (hex) of the evidence bundle: per-item request/response hashes,
    /// enclave signatures and grades. Nothing in it reveals the questions.
    pub evidence_hash: String,
    pub tee: Option<TeeEvidence>,
    /// Optional per-tier means (e.g. easy / medium / hard) when the set's
    /// items carry a tier. Empty for single-tier sets.
    pub breakdown: Vec<ScorePart>,
    pub issued_ns: u64,
}

/// One slice of a score: the mean over the items with this label.
#[near(serializers = [json, borsh])]
#[derive(Clone, Debug, PartialEq)]
pub struct ScorePart {
    pub label: String,
    pub items: u32,
    pub score_bps: u32,
}

#[near(serializers = [json, borsh])]
#[derive(Clone, Debug)]
pub struct Bounty {
    pub id: u64,
    pub dataset_id: u64,
    pub sponsor: AccountId,
    pub threshold_bps: u32,
    pub reward: NearToken,
    pub expires_ns: u64,
    pub winner: Option<AccountId>,
    pub winning_certificate: Option<u64>,
    pub reclaimed: bool,
}

#[near(serializers = [json])]
pub struct FulfillInput {
    pub run_id: u64,
    /// Score in basis points (8125 = 81.25%), partial credit allowed.
    pub score_bps: u32,
    pub judge_model: Option<String>,
    pub evidence_hash: String,
    pub tee: Option<TeeEvidence>,
    /// Optional per-tier means; their item counts must add up to the set's,
    /// and their weighted mean must match score_bps to within one basis point
    /// per tier (each tier mean is rounded on its own).
    pub breakdown: Option<Vec<ScorePart>>,
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct BlindBench {
    datasets: Vector<Dataset>,
    runs: Vector<Run>,
    certificates: Vector<Certificate>,
    bounties: Vector<Bounty>,
    /// dataset id -> certificate ids, for leaderboards.
    by_dataset: near_sdk::store::LookupMap<u64, Vec<u64>>,
    open_bounties: IterableSet<u64>,
}

fn is_hex_hash(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
}

#[near]
impl BlindBench {
    #[init]
    pub fn new() -> Self {
        Self {
            datasets: Vector::new(b"d"),
            runs: Vector::new(b"r"),
            certificates: Vector::new(b"c"),
            bounties: Vector::new(b"b"),
            by_dataset: near_sdk::store::LookupMap::new(b"x"),
            open_bounties: IterableSet::new(b"o"),
        }
    }

    // ------------------------------------------------------------ datasets

    pub fn commit_dataset(
        &mut self,
        root: String,
        items: u32,
        description: String,
        price: NearToken,
        grading: String,
        require_tee: Option<bool>,
        runner: Option<AccountId>,
    ) -> u64 {
        require!(is_hex_hash(&root), "root must be a 64-char hex sha256");
        require!(items > 0, "items must be > 0");
        require!(description.len() <= MAX_DESCRIPTION, "description max 280 bytes");
        require!(matches!(grading.as_str(), "exact" | "checklist" | "rubric" | "tests"), "grading must be exact, checklist, rubric or tests");
        let owner = env::predecessor_account_id();
        let id = self.datasets.len() as u64;
        self.datasets.push(Dataset {
            id,
            runner: runner.unwrap_or_else(|| owner.clone()),
            owner,
            root,
            items,
            description,
            price,
            grading,
            require_tee: require_tee.unwrap_or(true),
            created_ns: env::block_timestamp(),
            runs_completed: 0,
            earned: NearToken::from_yoctonear(0),
            reveal_uri: None,
        });
        log_event("dataset_committed", id);
        id
    }

    pub fn set_price(&mut self, dataset_id: u64, price: NearToken) {
        let ds = self.dataset_mut(dataset_id);
        require!(ds.owner == env::predecessor_account_id(), "owner only");
        ds.price = price;
    }

    /// Publish where the items can be downloaded, so anyone can recompute the
    /// root and re-grade every certificate. Burns the set's secrecy for good.
    pub fn reveal_dataset(&mut self, dataset_id: u64, uri: String) {
        let ds = self.dataset_mut(dataset_id);
        require!(ds.owner == env::predecessor_account_id(), "only the dataset owner can reveal");
        require!(!uri.is_empty() && uri.len() <= MAX_URI, "uri 1-512 bytes");
        ds.reveal_uri = Some(uri);
    }

    // ---------------------------------------------------------------- runs

    #[payable]
    pub fn request_run(&mut self, dataset_id: u64, model: String) -> u64 {
        let ds = self.dataset(dataset_id);
        require!(ds.reveal_uri.is_none(), "dataset was revealed; its scores are no longer private");
        require!(is_plain(&model, MAX_NAME), "model id: 1-128 printable ASCII characters");
        let attached = env::attached_deposit();
        require!(attached >= ds.price, format!("attach at least {} yoctoNEAR", ds.price.as_yoctonear()));
        // Escrow exactly the price as it stands now and refund the rest at once. The run
        // then pays out what it escrowed, whatever the owner does to the price later.
        let requester = env::predecessor_account_id();
        let excess = attached.saturating_sub(ds.price);
        if !excess.is_zero() {
            let _ = Promise::new(requester.clone()).transfer(excess);
        }
        let id = self.runs.len() as u64;
        self.runs.push(Run {
            id,
            dataset_id,
            requester,
            model,
            paid: ds.price,
            status: RunStatus::Pending,
            created_ns: env::block_timestamp(),
            certificate_id: None,
        });
        log_event("run_requested", id);
        id
    }

    pub fn fulfill_run(&mut self, input: FulfillInput) -> u64 {
        let run = self.run(input.run_id);
        require!(run.status == RunStatus::Pending, "run is not pending");
        let ds = self.dataset(run.dataset_id);
        require!(env::predecessor_account_id() == ds.runner, "only the dataset runner can fulfil");
        require!(input.score_bps <= 10_000, "score_bps max 10000");
        if ds.grading == "rubric" {
            require!(input.judge_model.is_some(), "rubric grading must name its judge model");
        }
        if let Some(j) = &input.judge_model {
            require!(is_plain(j, MAX_NAME), "judge model: 1-128 printable ASCII characters");
        }
        require!(is_hex_hash(&input.evidence_hash), "evidence_hash must be a 64-char hex sha256");
        if ds.require_tee {
            let tee = input.tee.as_ref().unwrap_or_else(|| env::panic_str("this dataset requires TEE evidence"));
            require!(tee.signed_responses == ds.items, "every item needs a TEE-signed response");
        }
        // TEE evidence is checked for shape whenever it is supplied, required or not.
        if let Some(tee) = &input.tee {
            require!(tee.signed_responses <= ds.items, "signed_responses cannot exceed the set's items");
            require!(is_hex_hash(&tee.attestation_hash), "attestation_hash must be hex sha256");
            require!(is_plain(&tee.signing_address, MAX_NAME), "signing_address: 1-128 printable ASCII characters");
            require!(is_plain(&tee.signing_algo, 16), "signing_algo: 1-16 printable ASCII characters");
        }

        let breakdown = input.breakdown.unwrap_or_default();
        if !breakdown.is_empty() {
            require!(breakdown.len() <= 8, "at most 8 breakdown parts");
            let mut items = 0u64;
            let mut weighted = 0u64;
            for p in &breakdown {
                require!(is_plain(&p.label, 32), "breakdown label: 1-32 printable ASCII characters");
                require!(breakdown.iter().filter(|q| q.label == p.label).count() == 1, "breakdown labels must differ");
                require!(p.score_bps <= 10_000 && p.items > 0, "breakdown part needs items and score_bps <= 10000");
                items += p.items as u64;
                weighted += p.items as u64 * p.score_bps as u64;
            }
            require!(items == ds.items as u64, "breakdown items must add up to the set's items");
            let mean = (weighted + items / 2) / items;
            require!(mean.abs_diff(input.score_bps as u64) <= breakdown.len() as u64, "breakdown does not average to score_bps");
        }

        let score_bps = input.score_bps;
        let cert_id = self.certificates.len() as u64;
        self.certificates.push(Certificate {
            id: cert_id,
            run_id: run.id,
            dataset_id: ds.id,
            dataset_root: ds.root.clone(),
            model: run.model.clone(),
            runner: ds.runner.clone(),
            score_bps,
            items: ds.items,
            judge_model: input.judge_model,
            evidence_hash: input.evidence_hash,
            tee: input.tee,
            breakdown,
            issued_ns: env::block_timestamp(),
        });
        let mut list = self.by_dataset.get(&ds.id).cloned().unwrap_or_default();
        list.push(cert_id);
        self.by_dataset.insert(ds.id, list);

        // Escrow: what this run escrowed goes to the owner. Never the current price,
        // which the owner may have changed since the request.
        let price = run.paid;
        {
            let r = self.runs.get_mut(run.id as u32).unwrap();
            r.status = RunStatus::Done;
            r.certificate_id = Some(cert_id);
        }
        {
            let d = self.dataset_mut(ds.id);
            d.runs_completed += 1;
            d.earned = d.earned.saturating_add(price);
        }
        if !price.is_zero() {
            let _ = Promise::new(ds.owner.clone()).transfer(price);
        }

        // Bounties: the first certificate to clear an open bounty wins it.
        // A bounty rewards a score on a secret set. Once the set is revealed, runs
        // that were still pending are certified but can no longer win one.
        let now = env::block_timestamp();
        let candidates: Vec<u64> = if ds.reveal_uri.is_some() { vec![] } else { self.open_bounties.iter().cloned().collect() };
        for bid in candidates {
            let b = self.bounties.get_mut(bid as u32).unwrap();
            if b.dataset_id == ds.id && b.winner.is_none() && now <= b.expires_ns && score_bps >= b.threshold_bps {
                b.winner = Some(run.requester.clone());
                b.winning_certificate = Some(cert_id);
                let reward = b.reward;
                self.open_bounties.remove(&bid);
                let _ = Promise::new(run.requester.clone()).transfer(reward);
                log_event("bounty_won", bid);
            }
        }
        log_event("certificate_issued", cert_id);
        cert_id
    }

    pub fn cancel_run(&mut self, run_id: u64) {
        let run = self.run(run_id);
        require!(run.requester == env::predecessor_account_id(), "requester only");
        require!(run.status == RunStatus::Pending, "run is not pending");
        require!(env::block_timestamp() >= run.created_ns + RUN_TIMEOUT_NS, "runner still has time to answer");
        self.runs.get_mut(run.id as u32).unwrap().status = RunStatus::Cancelled;
        let _ = Promise::new(run.requester).transfer(run.paid);
    }

    // ------------------------------------------------------------ bounties

    #[payable]
    pub fn post_bounty(&mut self, dataset_id: u64, threshold_bps: u32, duration_days: u32) -> u64 {
        let ds = self.dataset(dataset_id);
        require!(ds.reveal_uri.is_none(), "dataset was revealed; it takes no new bounties");
        require!(self.open_bounties.len() < MAX_OPEN_BOUNTIES, "too many open bounties; try again when one settles");
        require!(threshold_bps > 0 && threshold_bps <= 10_000, "threshold_bps 1-10000");
        require!(duration_days > 0 && duration_days <= 365, "duration_days 1-365");
        let reward = env::attached_deposit();
        require!(reward >= MIN_BOUNTY, "attach the reward: at least 0.1 NEAR");
        let id = self.bounties.len() as u64;
        self.bounties.push(Bounty {
            id,
            dataset_id: ds.id,
            sponsor: env::predecessor_account_id(),
            threshold_bps,
            reward,
            expires_ns: env::block_timestamp() + duration_days as u64 * 86_400 * 1_000_000_000,
            winner: None,
            winning_certificate: None,
            reclaimed: false,
        });
        self.open_bounties.insert(id);
        log_event("bounty_posted", id);
        id
    }

    pub fn reclaim_bounty(&mut self, bounty_id: u64) {
        let slot = slot(bounty_id).unwrap_or_else(|| env::panic_str("no such bounty"));
        let (id, dataset_id) = self.bounties.get(slot).map(|b| (b.id, b.dataset_id)).unwrap_or_else(|| env::panic_str("no such bounty"));
        // A revealed set can no longer pay a bounty, so its sponsor need not wait for the expiry.
        let revealed = self.dataset(dataset_id).reveal_uri.is_some();
        let b = self.bounties.get_mut(slot).unwrap();
        require!(b.sponsor == env::predecessor_account_id(), "sponsor only");
        require!(b.winner.is_none() && !b.reclaimed, "bounty already settled");
        require!(revealed || env::block_timestamp() > b.expires_ns, "bounty has not expired");
        b.reclaimed = true;
        let (to, amt) = (b.sponsor.clone(), b.reward);
        self.open_bounties.remove(&id);
        let _ = Promise::new(to).transfer(amt);
    }

    // --------------------------------------------------------------- views

    pub fn get_dataset(&self, dataset_id: u64) -> Option<Dataset> {
        slot(dataset_id).and_then(|i| self.datasets.get(i)).cloned()
    }

    pub fn list_datasets(&self, from_index: Option<u64>, limit: Option<u64>) -> Vec<Dataset> {
        page(self.datasets.iter(), from_index, limit)
    }

    pub fn get_run(&self, run_id: u64) -> Option<Run> {
        slot(run_id).and_then(|i| self.runs.get(i)).cloned()
    }

    pub fn list_pending_runs(&self, runner: AccountId) -> Vec<Run> {
        self.runs
            .iter()
            .filter(|r| r.status == RunStatus::Pending)
            .filter(|r| self.datasets.get(r.dataset_id as u32).map(|d| d.runner == runner).unwrap_or(false))
            .take(50)
            .cloned()
            .collect()
    }

    pub fn get_certificate(&self, certificate_id: u64) -> Option<Certificate> {
        slot(certificate_id).and_then(|i| self.certificates.get(i)).cloned()
    }

    pub fn list_certificates(&self, from_index: Option<u64>, limit: Option<u64>) -> Vec<Certificate> {
        page(self.certificates.iter(), from_index, limit)
    }

    /// Certificates for one dataset, best score first.
    pub fn leaderboard(&self, dataset_id: u64) -> Vec<Certificate> {
        let mut v: Vec<Certificate> = self
            .by_dataset
            .get(&dataset_id)
            .map(|ids| ids.iter().filter_map(|i| self.certificates.get(*i as u32).cloned()).collect())
            .unwrap_or_default();
        v.sort_by(|a, b| b.score_bps.cmp(&a.score_bps).then(a.id.cmp(&b.id)));
        v
    }

    pub fn get_bounty(&self, bounty_id: u64) -> Option<Bounty> {
        slot(bounty_id).and_then(|i| self.bounties.get(i)).cloned()
    }

    pub fn list_bounties(&self, dataset_id: u64) -> Vec<Bounty> {
        self.bounties.iter().filter(|b| b.dataset_id == dataset_id).cloned().collect()
    }

    pub fn stats(&self) -> (u64, u64, u64, u64) {
        (
            self.datasets.len() as u64,
            self.runs.len() as u64,
            self.certificates.len() as u64,
            self.bounties.len() as u64,
        )
    }

    // ------------------------------------------------------------- helpers

    fn dataset(&self, id: u64) -> Dataset {
        slot(id).and_then(|i| self.datasets.get(i)).cloned().unwrap_or_else(|| env::panic_str("no such dataset"))
    }

    fn dataset_mut(&mut self, id: u64) -> &mut Dataset {
        slot(id).and_then(|i| self.datasets.get_mut(i)).unwrap_or_else(|| env::panic_str("no such dataset"))
    }

    fn run(&self, id: u64) -> Run {
        slot(id).and_then(|i| self.runs.get(i)).cloned().unwrap_or_else(|| env::panic_str("no such run"))
    }
}

fn page<'a, T: Clone + 'a>(it: impl Iterator<Item = &'a T>, from: Option<u64>, limit: Option<u64>) -> Vec<T> {
    it.skip(from.unwrap_or(0) as usize).take(limit.unwrap_or(20).min(100) as usize).cloned().collect()
}

fn log_event(event: &str, id: u64) {
    env::log_str(&format!("EVENT_JSON:{{\"standard\":\"blindbench\",\"version\":\"1.0.0\",\"event\":\"{event}\",\"data\":{{\"id\":{id}}}}}"));
}

#[cfg(test)]
mod tests {
    use super::*;
    use near_sdk::test_utils::{accounts, VMContextBuilder};
    use near_sdk::testing_env;

    const ROOT: &str = "a3f9000000000000000000000000000000000000000000000000000000000001";
    const EVID: &str = "e000000000000000000000000000000000000000000000000000000000000002";

    fn ctx(who: usize, deposit_near: u128, ts: u64) {
        testing_env!(VMContextBuilder::new()
            .predecessor_account_id(accounts(who))
            .attached_deposit(NearToken::from_millinear(deposit_near * 1000))
            .block_timestamp(ts)
            .build());
    }

    fn tee(n: u32) -> Option<TeeEvidence> {
        Some(TeeEvidence {
            signing_address: "0xabc".into(),
            signing_algo: "ecdsa".into(),
            attestation_hash: EVID.into(),
            signed_responses: n,
        })
    }

    /// owner = accounts(1), requester = accounts(2), sponsor = accounts(3)
    fn setup() -> (BlindBench, u64) {
        ctx(1, 0, 1);
        let mut c = BlindBench::new();
        let ds = c.commit_dataset(ROOT.into(), 40, "40 contract-law questions".into(), NearToken::from_near(1), "checklist".into(), None, None);
        (c, ds)
    }

    #[test]
    fn test_graded_sets_need_no_judge() {
        ctx(1, 0, 1);
        let mut c = BlindBench::new();
        let ds = c.commit_dataset(ROOT.into(), 10, "10 coding tasks, hidden unit tests".into(), NearToken::from_near(1), "tests".into(), None, None);
        ctx(2, 1, 10);
        let run = c.request_run(ds, "Qwen/Qwen3.8-27B".into());
        ctx(1, 0, 20);
        let cert = c.fulfill_run(FulfillInput { run_id: run, score_bps: 7000, judge_model: None, evidence_hash: EVID.into(), tee: tee(10), breakdown: None });
        assert_eq!(c.get_certificate(cert).unwrap().score_bps, 7000);
    }

    #[test]
    #[should_panic(expected = "grading must be exact, checklist, rubric or tests")]
    fn unknown_grading_is_rejected() {
        ctx(1, 0, 1);
        let mut c = BlindBench::new();
        c.commit_dataset(ROOT.into(), 10, "x".into(), NearToken::from_near(1), "vibes".into(), None, None);
    }

    #[test]
    fn a_price_change_after_the_request_does_not_change_the_payout() {
        let (mut c, ds) = setup();
        ctx(2, 2, 10); // attaches 2 NEAR for a 1 NEAR run: 1 is escrowed, 1 goes straight back
        let run = c.request_run(ds, "zai-org/GLM-5.1-FP8".into());
        assert_eq!(c.get_run(run).unwrap().paid, NearToken::from_near(1));
        // the owner raises the price before fulfilling: the run still pays what it escrowed,
        // so a payout can never draw on other runs' escrow or on bounty rewards
        ctx(1, 0, 15);
        c.set_price(ds, NearToken::from_near(100));
        ctx(1, 0, 20);
        c.fulfill_run(FulfillInput { run_id: run, score_bps: 5000, judge_model: None, evidence_hash: EVID.into(), tee: tee(40), breakdown: None });
        assert_eq!(c.get_dataset(ds).unwrap().earned, NearToken::from_near(1));
    }

    #[test]
    fn paid_run_issues_certificate_and_pays_owner() {
        let (mut c, ds) = setup();
        ctx(2, 2, 10);
        let run = c.request_run(ds, "zai-org/GLM-5.1-FP8".into());
        ctx(1, 0, 20);
        let cert = c.fulfill_run(FulfillInput { run_id: run, score_bps: 8250, judge_model: None, evidence_hash: EVID.into(), tee: tee(40), breakdown: None });
        let cert = c.get_certificate(cert).unwrap();
        assert_eq!(cert.score_bps, 8250);
        assert_eq!(cert.dataset_root, ROOT);
        let d = c.get_dataset(ds).unwrap();
        assert_eq!(d.runs_completed, 1);
        assert_eq!(d.earned, NearToken::from_near(1));
        assert_eq!(c.get_run(run).unwrap().status, RunStatus::Done);
    }

    #[test]
    fn leaderboard_sorts_best_first() {
        let (mut c, ds) = setup();
        for (model, correct) in [("a", 20u32), ("b", 36), ("c", 30)] {
            ctx(2, 1, 10);
            let r = c.request_run(ds, model.into());
            ctx(1, 0, 20);
            c.fulfill_run(FulfillInput { run_id: r, score_bps: correct * 250, judge_model: None, evidence_hash: EVID.into(), tee: tee(40), breakdown: None });
        }
        let lb: Vec<String> = c.leaderboard(ds).into_iter().map(|x| x.model).collect();
        assert_eq!(lb, vec!["b", "c", "a"]);
    }

    #[test]
    fn bounty_paid_to_first_run_over_threshold() {
        let (mut c, ds) = setup();
        ctx(3, 5, 10);
        let b = c.post_bounty(ds, 9000, 7);
        ctx(2, 1, 11);
        let low = c.request_run(ds, "weak".into());
        ctx(1, 0, 12);
        c.fulfill_run(FulfillInput { run_id: low, score_bps: 7500, judge_model: None, evidence_hash: EVID.into(), tee: tee(40), breakdown: None });
        assert!(c.get_bounty(b).unwrap().winner.is_none());
        ctx(2, 1, 13);
        let high = c.request_run(ds, "strong".into());
        ctx(1, 0, 14);
        let cert = c.fulfill_run(FulfillInput { run_id: high, score_bps: 9500, judge_model: None, evidence_hash: EVID.into(), tee: tee(40), breakdown: None });
        let won = c.get_bounty(b).unwrap();
        assert_eq!(won.winner, Some(accounts(2)));
        assert_eq!(won.winning_certificate, Some(cert));
    }

    #[test]
    #[should_panic(expected = "this dataset requires TEE evidence")]
    fn tee_required_by_default() {
        let (mut c, ds) = setup();
        ctx(2, 1, 10);
        let r = c.request_run(ds, "m".into());
        ctx(1, 0, 20);
        c.fulfill_run(FulfillInput { run_id: r, score_bps: 250, judge_model: None, evidence_hash: EVID.into(), tee: None, breakdown: None });
    }

    #[test]
    fn tier_breakdown_is_stored_and_checked() {
        let (mut c, ds) = setup();
        ctx(2, 2, 10);
        let r = c.request_run(ds, "m".into());
        ctx(1, 0, 20);
        let parts = vec![
            ScorePart { label: "easy".into(), items: 10, score_bps: 10_000 },
            ScorePart { label: "medium".into(), items: 20, score_bps: 8_000 },
            ScorePart { label: "hard".into(), items: 10, score_bps: 4_000 },
        ];
        let cert = c.fulfill_run(FulfillInput { run_id: r, score_bps: 7_500, judge_model: None, evidence_hash: EVID.into(), tee: tee(40), breakdown: Some(parts.clone()) });
        assert_eq!(c.get_certificate(cert).unwrap().breakdown, parts);
    }

    #[test]
    #[should_panic(expected = "breakdown items must add up")]
    fn tier_breakdown_must_cover_every_item() {
        let (mut c, ds) = setup();
        ctx(2, 2, 10);
        let r = c.request_run(ds, "m".into());
        ctx(1, 0, 20);
        let parts = vec![ScorePart { label: "easy".into(), items: 10, score_bps: 7_500 }];
        c.fulfill_run(FulfillInput { run_id: r, score_bps: 7_500, judge_model: None, evidence_hash: EVID.into(), tee: tee(40), breakdown: Some(parts) });
    }

    #[test]
    #[should_panic(expected = "only the dataset runner can fulfil")]
    fn strangers_cannot_fulfil() {
        let (mut c, ds) = setup();
        ctx(2, 1, 10);
        let r = c.request_run(ds, "m".into());
        c.fulfill_run(FulfillInput { run_id: r, score_bps: 10000, judge_model: None, evidence_hash: EVID.into(), tee: tee(40), breakdown: None });
    }

    #[test]
    #[should_panic(expected = "attach at least")]
    fn underpaid_run_rejected() {
        let (mut c, ds) = setup();
        ctx(2, 0, 10);
        c.request_run(ds, "m".into());
    }

    #[test]
    fn requester_can_cancel_after_timeout() {
        let (mut c, ds) = setup();
        ctx(2, 1, 10);
        let r = c.request_run(ds, "m".into());
        ctx(2, 0, 10 + RUN_TIMEOUT_NS);
        c.cancel_run(r);
        assert_eq!(c.get_run(r).unwrap().status, RunStatus::Cancelled);
    }

    #[test]
    #[should_panic(expected = "runner still has time")]
    fn cannot_cancel_early() {
        let (mut c, ds) = setup();
        ctx(2, 1, 10);
        let r = c.request_run(ds, "m".into());
        ctx(2, 0, 11);
        c.cancel_run(r);
    }

    #[test]
    #[should_panic(expected = "dataset was revealed")]
    fn revealed_dataset_takes_no_new_runs() {
        let (mut c, ds) = setup();
        c.reveal_dataset(ds, "https://example.com/set.jsonl".into());
        ctx(2, 1, 10);
        c.request_run(ds, "m".into());
    }
    #[test]
    fn ids_that_do_not_fit_are_rejected_not_wrapped() {
        let (mut c, ds) = setup();
        let alias = ds + (1u64 << 32);
        assert!(c.get_dataset(alias).is_none());
        assert!(c.get_run(1u64 << 32).is_none());
        ctx(3, 5, 10);
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| c.post_bounty(alias, 9000, 7)));
        assert!(r.is_err(), "a wrapped dataset id must not reach a real dataset");
    }

    #[test]
    fn a_reclaimed_bounty_leaves_the_open_set() {
        let (mut c, ds) = setup();
        ctx(3, 5, 10);
        let b = c.post_bounty(ds, 9000, 1);
        assert_eq!(c.open_bounties.len(), 1);
        ctx(3, 0, 10 + 2 * 86_400 * 1_000_000_000);
        c.reclaim_bounty(b);
        assert_eq!(c.open_bounties.len(), 0);
        assert!(c.get_bounty(b).unwrap().reclaimed);
    }

    #[test]
    #[should_panic(expected = "at least 0.1 NEAR")]
    fn dust_bounties_are_refused() {
        let (mut c, ds) = setup();
        testing_env!(VMContextBuilder::new().predecessor_account_id(accounts(3)).attached_deposit(NearToken::from_yoctonear(1)).block_timestamp(10).build());
        c.post_bounty(ds, 9000, 7);
    }

    #[test]
    fn a_revealed_set_pays_no_bounty_and_frees_the_sponsor() {
        let (mut c, ds) = setup();
        ctx(3, 5, 10);
        let b = c.post_bounty(ds, 9000, 7);
        ctx(2, 1, 11);
        let run = c.request_run(ds, "strong".into());
        ctx(1, 0, 12);
        c.reveal_dataset(ds, "https://example.org/set.jsonl".into());
        // The pending run is still certified and the owner paid, but the bounty stays put.
        c.fulfill_run(FulfillInput { run_id: run, score_bps: 9900, judge_model: None, evidence_hash: EVID.into(), tee: tee(40), breakdown: None });
        assert!(c.get_bounty(b).unwrap().winner.is_none());
        // The sponsor takes the reward back at once, well before the expiry.
        ctx(3, 0, 13);
        c.reclaim_bounty(b);
        assert!(c.get_bounty(b).unwrap().reclaimed);
        // And no new bounty can be posted on it.
        ctx(3, 5, 14);
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| c.post_bounty(ds, 9000, 7)));
        assert!(r.is_err());
    }

    #[test]
    fn free_text_fields_are_bounded_and_plain() {
        let (mut c, ds) = setup();
        ctx(2, 1, 11);
        let bad = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| c.request_run(ds, "<img src=x>\u{7}".into())));
        assert!(bad.is_err(), "control characters in a model id");
        ctx(2, 1, 11);
        let run = c.request_run(ds, "org/model-1.0".into());
        ctx(1, 0, 12);
        let empty_judge = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            c.fulfill_run(FulfillInput { run_id: run, score_bps: 5000, judge_model: Some(String::new()), evidence_hash: EVID.into(), tee: tee(40), breakdown: None })
        }));
        assert!(empty_judge.is_err(), "an empty judge name");
        ctx(1, 0, 12);
        let long_key = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut t = tee(40).unwrap();
            t.signing_address = "0x".to_string() + &"a".repeat(400);
            c.fulfill_run(FulfillInput { run_id: run, score_bps: 5000, judge_model: None, evidence_hash: EVID.into(), tee: Some(t), breakdown: None })
        }));
        assert!(long_key.is_err(), "an oversized signing address");
        ctx(1, 0, 12);
        let twins = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let parts = vec![ScorePart { label: "easy".into(), items: 20, score_bps: 5000 }, ScorePart { label: "easy".into(), items: 20, score_bps: 5000 }];
            c.fulfill_run(FulfillInput { run_id: run, score_bps: 5000, judge_model: None, evidence_hash: EVID.into(), tee: tee(40), breakdown: Some(parts) })
        }));
        assert!(twins.is_err(), "two breakdown parts with one label");
    }
}
