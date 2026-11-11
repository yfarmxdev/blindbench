# BlindBench

**Private AI evals that pay the people who write them.**

- An expert commits a secret test set to NEAR as a hash.
- Anyone pays to have a model scored on it. The owner is paid per run, and a bounty pays the first model to clear a bar.
- The questions go only to models running in NEAR AI Cloud TEEs and are never published. The set's owner and runner hold them; what the model's operator can see rests on the enclave hardware (see the [trust model](#trust-model-what-is-proven-and-what-is-trusted)).
- A certificate lands onchain: model, score, dataset hash, and the enclave key that signed every answer. Anyone can recheck it.

Built for NEAR HACKATHON 2026. Tracks: **Privacy & Private AI** (primary), Agent Economy.

## For judges: 90 seconds

1. **In a browser, nothing to install.** Open [blindben.ch](https://blindben.ch), click any leaderboard row, then **Fetch and verify the evidence**. Your browser reads the certificate from the testnet contract, recomputes the evidence hash, recovers every enclave signature, and checks the Intel TDX quote behind each signing key down to Intel's root certificate. See `Evidence checks passed · signatures, TDX quotes, set root and score`.
2. **In a terminal, with no API key and no NEAR account** (Node 22.22.2 or newer; Rust and Python 3 are used if present; the first run takes a few minutes because the Rust tests compile):
   ```
   git clone https://github.com/yfarmxdev/blindbench && cd blindbench/cli && npm ci && npm run judge
   ```
   It runs every step of the table below, offline ones first, then the live ones (testnet contract, NEAR AI Cloud, Intel, NVIDIA, NEAR Intents), and prints `✓` with what it saw for each. See `every step passed` at the end (`every step that ran passed` if Rust is missing and step 1 is skipped). The browser steps (4b, 6c, 6d) are not part of the script.
3. **What is proven and what is still trusted** is one table: [Trust model](#trust-model-what-is-proven-and-what-is-trusted).

## The problem

- **Public benchmarks leak.** Once a test set is public it ends up in training data, and scores stop meaning much. The evals people trust keep a hidden set, but then you have to trust whoever holds it.
- **Generic scores don't answer your question.** A law firm, an auditor or a blockchain-forensics team needs to know how models do on *their* tasks, and cannot hand that data around.
- **Nobody earns from good evals.** A private set has one use, and sharing it destroys it.

BlindBench is private AI benchmarking with results certified against the model and a hash of the test set, plus a market: owners set a price, the contract holds the payment and pays the owner when the certificate lands, and a payer on another chain can get a NEAR Intents quote for the price.

## Try it: do X, see Y

Needs Node 22.22.2 or newer, Rust (stable) for step 1 and Python 3 for one test in step 2. Commands are for a POSIX shell (Linux, macOS, WSL); on native Windows the Python sandbox test does not apply, and `export X=…` is `$env:X = "…"` in PowerShell. The steps run in order in one shell from the repository root: step 1 leaves you in `contract/`, step 2 moves to `cli/`, and the rest stay there. No API key and no NEAR account are needed for steps 1 to 6e; only step 7 needs a NEAR AI Cloud key. `npm run judge` (in `cli/`) runs the terminal steps from 1 to 6e and checks each result; the browser steps (4b, 6c, 6d) are for you to click through.

| # | Do | See |
|---|---|---|
| 1 | `cd contract && cargo test` | `test result: ok. 19 passed`: paid runs, owner payout, escrow that a later price change cannot touch, leaderboard order, bounties (minimum size, none on a revealed set, reclaim), TEE requirement, timeouts, reveal lockout, per-tier score breakdown, grading-mode checks, ids that do not fit rejected, bounded text fields |
| 2 | `cd ../cli && npm ci && npm test` | `pass 54`, `fail 0`: Merkle proofs, enclave-signature checks, real Intel TDX quotes verified to Intel's root (and rejected when one byte changes), evidence that names its own unproven signing key refused, graders, an end-to-end run where a forged score and a swapped answer are both caught, evidence that skips an item, relabels the model or forges a judge signature is rejected, sandboxed code grading (code that fakes a pass or loops forever scores 0, and on Linux the code cannot see the host's files, processes or network), a model never judging itself, a cut-short run resuming without re-asking answers it already holds (and re-asking any signed by a key the fresh attestation does not cover), and the grader v2 checks (several answers per item, judge votes, quote and anchor overturns). The sandbox test is skipped if Python 3 is missing |
| 3 | `npm run demo` (in `cli/`) | four private sets committed (exact, checklist and rubric grading), 12 paid runs, every answer `enclave-signed ✓`, four leaderboards, `🏆 bounty #0 won`, `expert.near: 6 NEAR from 12 paid runs`, then a certificate re-verified and one item revealed with a Merkle proof |
| 4 | `node blindbench.mjs verify ../.blindbench/evidence/ds1-demo_strong.json` | `3/3 enclave signatures valid` and the evidence hash, then `3 item leaves hash up to dataset root …` and `3/3 judge calls signed …`. Edit any `response_sha256` in that file and rerun: `signature does not verify`. Edit a `leaf`: `item leaves do not hash up to dataset_root`. Set `"simulated": false` in it: `signing key … is NOT hardware-backed`, because evidence cannot vouch for its own key |
| 4b | `node blindbench.mjs web`, then open `http://localhost:8080/?snapshot=/local/demo-snapshot.json` | the step 3 ledger as a web page: four leaderboards with `model enclave` badges showing every answer signed (`6/6`, `3/3`, `2/2` and `3/3`, one per sample set). Click a row, then **Fetch and verify the evidence**: your browser recomputes the evidence hash and recovers every signature (for the six-item set, `6/6 answers carry a valid signature from a key declared in the evidence`, then `CHECKS PASSED, WITH WARNINGS`: the warning is the line saying this evidence came from the simulated enclave) |
| 5 | `node blindbench.mjs pay-quote --from nep141:base-0x833589fcd6edb6e08f4c7c32d4f71b54bda02913.omft.near --amount 2000000 --recipient intents.near --refund-to 0x4838B106FCe9647Bdf1E7877BF73cE8B0BAD5f97` | a live NEAR Intents dry quote such as `2.0 in -> 0.548… wNEAR`: what 2 USDC on Base would buy towards a run. It is a quote only; nothing is swapped |
| 6 | `export BLINDBENCH_CONTRACT=blindbench-hnxot5.testnet`, then `node blindbench.mjs datasets` and `node blindbench.mjs leaderboard 4` | the live testnet contract, read with no account: the six committed datasets, then the certificates for dataset #4 (the coding set), best score first, each `TEE-signed 12/12` with its certificate number |
| 6b | `node blindbench.mjs verify --cert <n>` with a certificate number from step 6 | the evidence published in this repo for that certificate, rechecked against the chain: `12/12 enclave signatures valid`, one line per signing key (`Intel TDX quote validated for this address, checked to Intel's root (TCB UpToDate, …)`), `12 item leaves hash up to dataset root …`, then `matches onchain certificate #<n>`. `verify --all` does this for every certificate: `21 of 21 certificates verified against their evidence, the chain and Intel TDX quotes` (the count grows with every new certificate) |
| 6c | open `http://localhost:8080/` (with `node blindbench.mjs web` running) | the same live contract in the browser. **Run a model** lets you pick a TEE model, then either connects a NEAR wallet and sends a test `request_run` (public runs are paused in this version, so that request gets no certificate and can be cancelled after 24 hours; see Known limits), or (tab **Other chains · quote preview**, **Get quote**) asks NEAR Intents for a live quote to pay from Base, Arbitrum, Ethereum or Solana |
| 6d | open `https://blindben.ch` | step 6c with nothing to install: the hosted copy of `web/`, reading the same live contract |
| 6e | `node blindbench.mjs attest --model deepseek-ai/DeepSeek-V4.1-Flash-1017` | the hardware proof, live and with no key: for the gateway enclave and the model enclave, `Intel TDX quote: … PCK chain ends at Intel's SGX Root CA`, `the quote binds this signing key and our fresh nonce`, `platform TCB UpToDate` from Intel's signed collateral, and `NVIDIA attestation service: 8 GPUs (HOPPER) pass` (the GPU count and the TCB status are what the services report on the day). The key it prints is the key that signed the certificates in step 6b |
| 7 | `NEARAI_API_KEY=… node blindbench.mjs run ../examples/ledger-arithmetic.jsonl --model <TEE model id>` | a real run against NEAR AI Cloud: attested enclave key, `signed ✓` on every item, score, and an evidence file. For the harder sample, run `../examples/privacy-chain-tracing.jsonl` with `--judge <another TEE model id>`: three tracing cases, each graded finding by finding |

Steps 3, 4 and 4b use a **simulated** NEAR AI enclave (`cli/mock/tee-server.mjs`) that speaks the same API and signs in the same format, so the verification code is the real code. Its attestation says `"simulated": true`, and the CLI and the web page say so. Steps 6 to 7 are the live path: real NEAR AI Cloud enclaves and the testnet contract.

If a step prints something else: the CLI reads NEAR through two public RPC endpoints and falls back from one to the other; set `NEAR_RPC_URL` to use your own. Step 5 calls the public 1Click API, which can rate-limit; wait a minute and rerun.

## How it works

```
 dataset owner                      payer                              anyone
      │ commit_dataset(root,…)           │ (1Click quote: USDC/SOL/ETH→NEAR) │ leaderboard(), get_certificate()
      ▼                                  ▼ request_run(dataset, model) $     ▼
 ┌─────────────────────────── BlindBench contract (NEAR) ───────────────────────────┐
 │ datasets: root, items, grading, price      runs: escrowed payment                │
 │ certificates: model, score, dataset_root, evidence_hash, enclave key             │
 │ bounties: threshold, reward → first certificate over the bar                     │
 └───────────────────────────────▲──────────────────────────────────────────────────┘
                                 │ fulfill_run(score, evidence_hash, tee)  → owner paid, bounty paid
 ┌───────────── runner (holds the set) ──────────────┐
 │ for each item: send to model ──► NEAR AI Cloud TEE (model + judge run in enclaves)
 │   fetch /v1/signature/<chat id>, check it recovers to the key from /v1/attestation/report
 │   grade: exact │ checklist (severity-weighted) │ rubric (TEE judge model) │ tests (sandboxed)
 │ evidence bundle = hashes + signatures only, never questions
 └───────────────────────────────────────────────────┘
```

**Commitment.** Each item gets a random 32-byte salt (kept privately in `<set>.salts.json`). `leaf = sha256(salt ‖ canonical(item))`, and the Merkle root of the leaves is what goes onchain. The salt stops anyone guessing short answers from a leaf. The owner can later reveal a single item with its proof (`prove` / `check-proof`) to settle a dispute without revealing the rest.

**TEE evidence.** NEAR AI Cloud signs the SHA-256 of the exact request and response bytes with a key that its attestation report binds to Intel TDX / NVIDIA hardware. The runner checks that the report echoes a fresh nonce, that every response signature recovers to an attested key, and that the signed hashes are exactly the bytes sent and received. The certificate stores the signing key, the report's hash and how many responses were signed. For a dataset with `require_tee` (the default) the contract refuses a certificate unless the runner reports a signed response for every item; the signatures themselves are checked off-chain by `verify`, not by the contract.

**Hardware proof.** A signature only means something if the key lives in a real enclave, so the report's Intel TDX quote is verified in this repo's own code (`web/tdx.mjs`, one file, no dependencies, the same file in the CLI and the browser): the PCK certificate chain up to Intel's SGX Root CA (its key is pinned), the Quoting Enclave's report, the attestation key, and the signature over the TD report; that the TD is not a debug TD; that `report_data` is the signing key followed by our nonce; and that MRCONFIGID names the compose file the enclave runs (the proof lists the image digests that file names). Intel's signed TCB info and Quoting Enclave identity are fetched from Intel and judged (`UpToDate` today), and the GPU evidence is sent to NVIDIA's attestation service, whose signed token must pass and carry the same nonce. `attest --save` stores each key's quote and Intel's collateral under `web/attestations/<key>.json`, so `verify` and the web page can redo the Intel part of the check offline: the quote, its certificate chain, the key binding, and Intel's signed TCB verdict as it stood when the proof was saved (a revoked or unrecognised status fails; an out-of-date one is shown as a warning). NVIDIA's verdict is checked live by `attest` and recorded in the saved proof; `verify` and the page show it as recorded and do not recheck it. `verify` accepts a signing key only if such a proof exists for it, for the right model: an evidence file cannot vouch for its own key. The proof file is also what says which role and model a key belongs to, so that classification rests on the proofs published here, not on Intel's signature. The runner refuses to start a run whose quotes fail.

There are two proof levels, and the evidence and the web page say which one applies:

- **Model enclave**: NEAR runs the model in its own TDX + GPU enclave, which signs `"<model>:<sha256(request)>:<sha256(response)>"`. The runner asks for these answers unstreamed, because that is when the model enclave signs with its own key.
- **Gateway + TEE**: the model runs in a third-party TEE (Chutes). NEAR AI's attested gateway checks that provider's enclave and GPU evidence, and signs `"<sha256(request)>:<sha256(response)>"`. A model-enclave answer that had to be streamed (long runs) also falls back to this signature.

**Run protocol.** Answers are capped at 32k tokens at temperature 0.6 (reasoning models loop at temperature 0). Reasoning can be switched off for a run (`--no-think`) or for one item (`"thinking": false`); the very long items here (100k+ characters) are marked that way, because with reasoning on, models think past their budget and never answer. If a model spends its whole budget reasoning and returns nothing, it is asked once more with reasoning off; the item records that (`empty_retry`), and the run reports how many answers stayed empty. The settings used are recorded in every evidence bundle.

**Grading modes**, chosen by the dataset owner:
- `exact`: objective answers with ground truth (for example, the fee a transaction pays or the payout of a swap).
- `checklist`: known findings with weights and severities (for example, planted smart-contract bugs, or the points a tracing report has to cover). Partial credit is given: a finding rated within one severity level of the key earns full credit, and one rated two or more levels off earns 75% (a set can choose `"severity": "exact"`, where any other level earns 50%). A set can also plant decoys (`"trap": true`): code or clauses that look wrong but are fine. Claiming a decoy as a real issue costs its weight, so listing every possible issue does not pay. A set can switch to judge protocol v2 (`"judge_protocol": "v2"`), where the judge must quote the candidate's own words for every finding it credits and must match the root cause, not the topic; credits whose quote cannot be found in the answer are overturned. The match ignores case, punctuation and spacing, and a long quote passes when most of it is found, so it shows the judge pointed at real text, not that the text proves the finding.
- `rubric`: open-ended work such as legal drafting, scored per criterion by a judge model in the TEE. The judge is named on the certificate.
- `tests`: coding tasks. The model writes a Python module, and hidden unit tests run against it. Each test runs in its own short-lived process with CPU, memory, file-size and time limits. On Linux that process is jailed in fresh user, mount, pid and network namespaces with a new root that holds only a read-only Python runtime, so model code cannot read the private set, the runner's keys or anything else on the machine, and has no network. A real run refuses to grade without the jail unless the operator sets `BLINDBENCH_WEAK_SANDBOX=1`. Its verdict carries a random token, so code that prints its own "pass" or exits early scores 0. One passed test per task is also run inverted (it passes only if the real test fails); a module that passes both is forging verdicts and the task scores 0. The score is the share of tests passed, so no judge model is needed. Known limit: a test runs in the same process as the code it tests, so code written to read the hidden test out of the harness could still cheat; see the trust model.

A model never judges its own answers. When the model under test is also the judge, an alternate judge (`--alt-judge`) grades that run, and the certificate names the judge actually used.

**Choosing a judge.** A judge is checked against the set's own key before it is trusted, because a judge that is too generous inflates every score on the set. For the checklist sets here, the same stored answers were graded by two TEE judges and by hand. The two judges agreed on 86 of 90 finding-level verdicts under protocol v1 and 82 of 90 under v2, and every disagreement was the cheaper judge being stricter, including the two credits a hand check had already marked as too generous. Protocol v2 is therefore the default for these sets, and the certificates record which judge and protocol produced them. A judge that costs about fourteen times more per output token did not grade better.

**What a score means.** A certificate scores one run on a small, fixed set, so it comes with two error bars. The *rerun* bar (printed when a run draws more than one answer per item, `--samples k`) says how much the same certificate would move if the run were repeated. The *item* bar says how much the score depends on which items the set happens to contain. On sets of 4 to 26 items a small difference between two models is noise, so the page groups a model with the leader above it unless it is at least a fixed band behind: 10 points on judged sets, 25 on exact and test-graded sets. Those are rough figures from a paired analysis of the first runs; the runner does not work out a gap for each run. These bands are a display guide, not a significance test for each pair. A perfect score is never "100% ± 0": the model passed these items, and a small fixed set says little about questions outside it (even if the items were a random sample, 16 out of 16 would only bound the pass rate at 83% with 95% confidence). Empty answers (a reasoning model that spends its whole budget thinking) are counted and shown on the certificate. Set owners can require several judge passes per answer (`--judge-passes n`); the passes vote per finding and the certificate records how often they agreed.

**Reference models and calibration.** `node blindbench.mjs grade <set> --answers <dir> --judge <model>` scores answers made outside BlindBench with the same TEE judge. Before a set is committed, a closed frontier model (Fable 5.2) answers it blind, one question per fresh run with no tools, and is graded by the same TEE judge. That reference score shows where the set's top sits: on the checklist sets it is 79-96%, and two sets (coding, finance) it answers perfectly, which marks them as floor tests rather than rankings (see "What a score means"). Reference scores are drawn dashed on the web page (`web/reference.json`) and are never certificates, because those answers were not produced and signed inside an enclave. Findings that a reference model first surfaced are tagged `"source"` in the key, so scores can be reported with and without them.

## Trust model: what is proven and what is trusted

| Claim | How |
|---|---|
| The questions were fixed before any run | Merkle root committed onchain first. Certificates copy the root |
| The answers came from the model named | Per-response enclave signatures. The evidence names its signing keys, so `verify` accepts a key only when a hardware quote published with the site binds that key to an enclave, and the published proof lists that key for the right role and model (see the hardware rows below; the role and model labels come from the proof file, not from Intel's signature). A model enclave signs the model's name with the hashes, and `verify` requires it to be the certificate's model. At the gateway level the model's name is inside the hashed request, which NEAR AI's attested gateway routed |
| The evidence accounts for the whole committed set | The evidence lists one salted leaf per item, and `verify` rebuilds the Merkle root from them. Evidence that leaves out or swaps a leaf does not match the root. That each leaf's question is the one that was sent is part of trusting the runner (below): a signature covers the request's hash, and the request is private |
| The questions were not exposed to the model operator | Inference runs in NEAR AI Confidential TEEs. Only TEE models are scored |
| The certificate's score is the mean of the item scores in the evidence | Evidence bundle is public, and `verify` recomputes the mean and rechecks every model and judge signature, in the CLI and in the browser. The item scores themselves come from the runner (below) |
| The evidence is the certificate's | `verify --cert` compares the evidence hash, root, model, score, item count, signed-answer count and attestation hash with the onchain certificate |
| **Trusted:** the runner graded honestly | Today the dataset owner runs the runner: it sends the committed questions, and it turns answers into item scores. The evidence binds each score to a signed answer hash, but only the owner can open the answer. **Next step:** run it in its own enclave so the grading code is attested too |
| **Trusted:** hidden tests are not attacked by the code they test | `tests` grading jails the code away from the machine (Linux) and catches forged verdicts with a token and an inverted canary run, but test and code share a Python process. **Next step:** run the assertions in a separate process |
| Each signing key is bound by a genuine Intel TDX quote | The raw TDX quote behind every signing key is verified in this repo's code down to Intel's pinned root, with Intel's signed TCB verdict (`attest`, `verify`, the web page). NVIDIA's GPU verdict is checked live by `attest` and only recorded in the saved proof. A key without a published quote is refused |
| **Limits of the hardware proof** | The certificates so far were made before quotes were saved, so their keys are proven by quotes fetched afterwards from the same enclaves (the keys did not change); runs from now on check the quote against their own nonce before the first question. Certificate revocation lists are not fetched. The boot event log replays to RTMR0-2 but not RTMR3, which the enclave extends at run time. We check which compose file and image digests the enclave runs, not what the images contain: that part is NEAR AI's published build. A quote shows that an enclave put this address in its report; there is no allow-list of approved measurements yet, so that the key was made inside, and never leaves, the model-serving software also rests on that build |

## NEAR technology used

- **NEAR AI Cloud** (`cloud-api.near.ai/v1`): private inference in TEEs, `/v1/attestation/report`, `/v1/signature/<id>`.
- **NEAR smart contract** (Rust, `near-sdk` 5.30): registry, escrow, payouts, bounties and leaderboards. See `contract/src/lib.rs`.
- **NEAR Intents 1Click** (`1click.chaindefuser.com`): live quotes for paying a run's price from another chain (`pay-quote` in the CLI, and an exact-output quote in the web page). The prototype stops at the quote; settling the swap into `request_run` is roadmap item 3.
- **NEAR Connect** (`@hot-labs/near-connect`): wallet sign-in and the `request_run` payment in the web page.
- Named accounts as dataset owners, runners and payers.

## Repository layout

```
contract/            NEAR contract (Rust) + unit tests
cli/blindbench.mjs   runner CLI: commit, request, run, serve, submit, grade, datasets, leaderboard, cert, attest, verify, prove, check-proof, pay-quote, web, demo
cli/lib/             dataset commitments, NEAR AI chat + TEE checks, hardware proof, graders, sandbox, NEAR RPC, Intents
cli/mock/            simulated NEAR AI enclave for the no-keys demo
cli/test/            node:test suite (54 tests)
cli/scripts/         judge.mjs runs the steps above and checks them; deploy the contract; re-grade stored answers
web/                 static page, no build step: live leaderboards, wallet payment, Intents quote, in-browser evidence check
web/tdx.mjs          Intel TDX quote verification, shared by the CLI and the page
web/evidence/        evidence bundles for the live certificates (hashes and signatures only)
web/attestations/    one hardware proof per enclave signing key: its TDX quote and Intel's signed collateral
examples/            PUBLIC sample sets (ledger arithmetic, privacy-chain tracing, smart-contract bugs, contract drafting)
```

The sample sets are public by definition, so they only show the format. Real sets are kept outside the repo (`private/` is git-ignored), and only their roots go onchain.

## Live deployment

- Contract (testnet): [`blindbench-hnxot5.testnet`](https://testnet.nearblocks.io/address/blindbench-hnxot5.testnet)
- Datasets onchain: #0 is an earlier public tracing sample (6 items, exact; it only shows the format and has no runs, so the page leaves it out, and the repo now ships harder samples in its place). #1 to #5 are the five private sets (on-chain tracing, legal contract review, smart-contract audit, coding, financial analysis): only their Merkle roots, item counts, grading modes and prices are onchain. Bounty #0 (2 NEAR to the first TEE model scoring 90% or more on the coding set) was paid out by the contract with certificate #10 (94.1%). Bounty #1 is open: 2 NEAR to the first TEE model scoring 50% or more on the on-chain tracing set. The page shows both on their set cards. Every score so far, with the cells that were not run and why, is in [RESULTS.md](RESULTS.md).
- Evidence bundles for the certificates on the live contract are published under `web/evidence/<evidence_hash>.json` (hashes and signatures only), so the web page's **Fetch and verify the evidence** works for live certificates too.
- Hosted page: [blindben.ch](https://blindben.ch) serves `web/` as static files with no build step. The page reads the contract over NEAR RPC and verifies evidence in the browser, so it is the same as step 6c with nothing to install. The host (Cloudflare) adds its visit counter to the hosted page (Web Analytics: page views without cookies); it is the only script the page's policy allows from another address, and the copy in `web/` does not contain it.
- Deploy your own: `cargo near build non-reproducible-wasm` in `contract/` (needs [`cargo-near`](https://github.com/near/cargo-near)), then, back in the repository root, `NEAR_ACCOUNT_ID=<you>.testnet node cli/scripts/deploy.mjs`. It prints the network, the target account and the code hash and sends nothing; add `--send` to deploy and initialise. It refuses an account that already holds a contract, and afterwards checks that the account holds exactly the code it sent

## Known limits of the prototype

These are deliberate gaps in a two-week testnet prototype. They are listed so nobody has to find them.

- **The hosted page does not serve runs on demand.** `request_run` on the testnet contract works and holds the payment in escrow, but the `serve` loop that fulfils public requests is not running for this submission, so a request made from the page gets no certificate and can be taken back with `cancel_run` after 24 hours. The certificates on the board were made by the team's own runs. The page says this in its Status section and in the pay dialog.
- **A bounty sponsor trusts the set's runner.** The runner reports the score, and the contract pays the bounty on it. A dishonest owner who is also the runner could request a run from a second account and report any score. Sponsor a bounty only on a set whose runner you trust, until grading is attested (roadmap 1).
- **Anyone can commit a set and certify scores on it.** A certificate means "this set's runner reports this score, with this evidence". It carries the weight of the set and its owner, not of BlindBench.
- **Payouts and refunds are plain transfers with no callback.** The owner's payout, a bounty payout, a refund of an overpayment, a cancelled run's refund and a reclaimed bounty are each a transfer the contract schedules. If the receiving account has been deleted, the transfer fails, the NEAR stays in the contract, and the record still says done, cancelled, won or reclaimed: there is no retry path yet.
- **An owner can reveal a set while a paid run is pending.** The run is still fulfilled and the owner still paid, but a bounty on that set can no longer be won.
- **Storage is paid by the contract's own balance.** Committing a set and requesting a free run cost the caller only gas. Bounties need at least 0.1 NEAR and at most 100 can be open, which keeps `fulfill_run` bounded, but there is no per-record storage deposit yet.
- **No upgrade path, migration or runner rotation** is built into the contract.
- **Request hashes are not salted.** The evidence publishes the SHA-256 of each request. Leaves are salted, requests are not, so someone who can guess a whole prompt and the run settings exactly could confirm the guess. The private sets here use long prompts; a set of short, guessable questions should not publish its evidence until requests carry a private nonce.
- **Published evidence and key proofs carry provider metadata**: chat ids, token counts, and the enclave's compose configuration with its service addresses. They are inside the hashed evidence and the quote-bound configuration, so they are published as they are.
- **`exact` grading compares numbers, not units.** `5%` and `5 bps` both match a key of `5`. Set authors should ask for the unit in the prompt.
- **The hosted page lists the project's own sets.** Anyone can commit a set to the testnet contract; the page at blindben.ch shows the ones the contract's own account published and says how many others it left out. Every set is onchain and readable with the CLI (`node blindbench.mjs datasets`). The hosted page also reads only the official contract on testnet: the `?contract=` and `?network=` parameters work when the page is served from your machine.
- **A wallet's connector code comes from that wallet.** The wallet list is a file in this repo (`web/vendor/wallets.json`), and where a wallet publishes its connector code on GitHub the list names an exact commit. Two wallets serve theirs from their own sites, so that code is not pinned. The code runs in a sandboxed frame, only after you pick that wallet. The page loads the connector only when you click Connect wallet (or had connected before), and the connector remembers the chosen wallet in the browser's local storage.
- **The page's script policy has two parts.** The response header allows script only from the site's own files but has to allow inline script, because the page is one static file. The page then adds a stricter policy with a nonce made for that page load, before it renders anything read from the ledger. A browser that ignored the second policy would be left with the first.
- **The inference API key** is sent to `cloud-api.near.ai` or localhost only, unless `--send-key-to-endpoint` is given.

## Roadmap

1. Run the runner inside its own TEE, so grading is attested and the owner need not be trusted. Run hidden tests in a separate process from the code under test.
2. Store sets encrypted to the enclave's key, so a hosted service can run sets for many owners.
3. Serve runs on demand on mainnet. Price in USDC through NEP-141 `ft_on_transfer`, with the price split between inference cost, the set's author and a platform fee, and settle 1Click deliveries directly into `request_run`.
4. List BlindBench as a service on NEAR's Agent Market, so agents can pick a model by paying for a private score.

## Disclosures

- All code was written during the hackathon window, starting on 7 Nov 2026. There is no pre-existing codebase.
- Branches: `main` is the only branch and holds the submission. There are no tags or release branches.
- This is the team's only entry in NEAR HACKATHON. No other project was submitted by the same people.
- Much of the code is AI-generated: it was written with an AI coding assistant, and is covered by the tests listed above.
- Libraries: `near-sdk` (Rust), `near-api-js`, `ethers` and `undici` (Node); in the web page, vendored `ethers` and `@hot-labs/near-connect` (bundled with esbuild, see `web/vendor/README.md`). Fonts: Doto, Inter Tight and IBM Plex Mono from Google Fonts.

## License

MIT, see [LICENSE](LICENSE).
