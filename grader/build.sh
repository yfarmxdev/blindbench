#!/bin/sh
# Build the grader exactly as the committed blindbench-grader.wasm was built.
# Source paths are remapped so the file carries no path from the build machine.
set -eu
cd "$(dirname "$0")"
CARGO_HOME_DIR="${CARGO_HOME:-$HOME/.cargo}"
RUSTFLAGS="--remap-path-prefix=$CARGO_HOME_DIR/registry/src=crates --remap-path-prefix=$(pwd)=grader" \
  cargo build --release --locked --target wasm32-wasip1
cp target/wasm32-wasip1/release/blindbench-grader.wasm blindbench-grader.wasm
sha256sum blindbench-grader.wasm
