# Results

Every number in the model columns is a certificate on NEAR testnet (contract `blindbench-hnxot5.testnet`), from one run whose answers were produced and signed inside NEAR AI Cloud enclaves. The last column is the uncertified reference. Each certificate links to its evidence bundle in `web/evidence/`, which anyone can recheck with `node blindbench.mjs verify <file>` or on the web page. 22 certificates so far.

| Set | Items | Grading | DeepSeek V4.1 Flash | DeepSeek V3.2 | Kimi K3 | Kimi K2.6 | Qwen3.5 397B | Qwen3.8 27B | Reference (uncertified) |
|---|---|---|---|---|---|---|---|---|---|
| On-chain tracing | 5 | checklist | **36.1%** (#13) | not run | not run | **31.9%** (#9) | not run | **17.2%** (#8) | 79.2% |
| Legal contract review | 4 | checklist | **83.0%** (#20) | **67.0%** (#6) | **92.0%** (#21) | **85.6%** (#7) | not run | **69.4%** (#5) | 95.6% |
| Smart contract audit | 16 | checklist | **51.3%** (#19) | **34.9%** (#11) | not run | **58.2%** (#14) | not run | **34.5%** (#18) | 90.6% |
| Coding | 12 | tests | **94.1%** (#10) | **66.9%** (#0) | **88.0%** (#16)\* | **89.2%** (#12) | not run | **70.5%** (#15) | 100.0% |
| Financial analysis | 26 | exact | **96.2%** (#2) | **76.9%** (#3) | not run | **100.0%** (#4) | not run | **84.6%** (#17) | 100.0% |

Earlier runs kept on the contract and dimmed on the page: #1 (Kimi K3, Coding, 83.3%, replaced by #16). Certificate #1 predates the rule that an empty answer at the token limit is asked once more with thinking off.

\* Coding, Kimi K3 and Kimi K2.6: the two are 1.2 points apart, less than one task (8.3 points). Both ran out of the 32k-token limit while thinking on the two hardest tasks and answered them on a second ask with thinking off. One fresh run of each on 11 November 2026, same settings, kept the order (Kimi K2.6 89.07%, Kimi K3 81.21%); those two runs are not certified and the certificates above stand.

`#n` is the certificate id. The reference column is a closed frontier model (Fable 5.2) graded by the same enclave judge and protocol; its answers were not produced in an enclave, so it has no certificate and is drawn as a dashed line on the page.

## What the numbers say

- **The hard sets separate models from the frontier.** On on-chain tracing the best enclave model so far (DeepSeek V4.1 Flash) scores 36.1% against a reference of 79.2%. On the smart contract audit it is 58.2% (Kimi K2.6) against 90.6%, and on legal review 92.0% (Kimi K3) against 95.6%. An open bounty on the tracing set pays the first enclave model to reach 50%.
- **Coding and finance are floor tests.** The reference answers both perfectly and the best enclave models are close to it, so these two sets show which models fail basic work and do not rank the top. A perfect score on 26 items means the model passed those 26, not that it would pass others.
- **Small sets, one run each.** Each cell is one run on 4 to 26 items. Two models on the same set should be read as tied unless one is at least the board's tie band behind the other (10 points on the judged sets, 25 on the exact-match and hidden-test sets; a display guide, not a significance test; see "What a score means" in the README).
- **One main judge, one protocol.** Every checklist certificate was graded in the enclave by the same judge (DeepSeek V4.1 Flash) under protocol v2, where the judge must quote the answer's own words for every finding it credits. The one exception is DeepSeek V4.1 Flash's own runs: a model never grades itself, so Kimi K2.6 graded those under the same protocol (each certificate names its judge). The reference line was graded by the main judge.

## Cells not run

9 of 30 cells have no certificate:

- On-chain tracing: DeepSeek V3.2
- On-chain tracing: Kimi K3
- On-chain tracing: Qwen3.5 397B
- Legal contract review: Qwen3.5 397B
- Smart contract audit: Kimi K3
- Smart contract audit: Qwen3.5 397B
- Coding: Qwen3.5 397B
- Financial analysis: Kimi K3
- Financial analysis: Qwen3.5 397B

Why: Kimi K3 costs roughly 4 to 15 times more per output token than the other models, so it was run on the coding and legal sets only. Qwen3.5 397B is served by an upstream provider that rate-limited every call on these sets, on 9 and again on 10 November 2026, so none of its runs could finish. On the tracing set, DeepSeek V3.2 and Qwen3.5 397B cannot be scored at all: the two hard items are raw ledgers of about 210,000 tokens each, and both models have a 128,000-token context window. No score is estimated or carried over from an earlier judge: a cell is either a certificate or "not run".
