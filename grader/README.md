# Sealed grader

The program that grades an answer inside a TEE, so the set's owner does not have to be trusted to grade honestly. One run handles one item and one enclave-signed model call. `src/main.rs` starts with what it checks.

- `blindbench-grader.wasm` is the build that runs in the enclave; `grader.json` pins its sha256.
- Jobs are compressed (raw DEFLATE) and then sealed with ChaCha20-Poly1305, so a whole finance item with its signed answer is about 16 to 50 KB of enclave input. The key is stored as an enclave secret that only this program's hash can read.
- Build: `./build.sh` (Rust 1.97, `rustup target add wasm32-wasip1`). It remaps source paths, so the file is the same from any folder and carries no path from the build machine. The hash is only guaranteed to match with the same toolchain; what the enclave attests is the hash of the committed file.
- `cargo test` replays `vectors.json`, about 1,300 answer lines graded by the JavaScript grader (`cli/lib/grade.mjs`), so the two graders are checked to agree on every one of those lines. `node ../cli/scripts/grader-vectors.mjs` rewrites the vectors.
- `cd ../cli && node --test test/sealed.test.mjs` runs the committed `.wasm` locally and checks that a swapped question, a slipped-in answer, a changed key, a swapped response or a request that steers the model is refused or shows up in the receipt.

## What a receipt proves

A receipt is the program's output for one answer: the item's leaf, the sha256 of the request and of the response, the model named in the request, and a score of 0 or 1. Checked against the evidence and the chain it shows that:

- the request the model enclave signed was the fixed system line plus exactly the committed question, with no field that could force or hint an answer (only `model`, `messages`, `max_tokens`, `temperature`, `stream`, `stream_options` and the reasoning switches are allowed);
- the response the model enclave signed, graded by this program's rules, gives this score.

## What it does not prove

- The set's owner still holds the questions, the answer keys and the sealing key: the owner builds the jobs. The seal keeps them off the public chain; it does not hide them from the owner or from the enclave operator's key store.
- The sealed jobs are public ciphertext. If the sealing key ever leaked, the questions and answers of the graded items could be read from the chain.
- The answer key itself is the owner's: a receipt shows the committed key was applied, not that the key is right.
- Only exact-graded sets are covered. Judged sets and hidden-test sets are graded by the runner as before.
- The enclave's own hardware attestation has to be checked as well (see `verify`), and it rests on the enclave operator's platform.
