#!/bin/bash
set -euxo pipefail

ROOT_DIR="${ROOT_DIR:-$( cd "$(dirname "$(realpath "$( dirname "${BASH_SOURCE[0]}" )")")" >/dev/null 2>&1 && pwd )}"

RUST_BLS48581_PACKAGE="$ROOT_DIR/crates/bls48581"
BINDINGS_DIR="$ROOT_DIR/bls48581"

# Build the Rust BLS48581 package in release mode
cargo build -p bls48581 --release

# Generate Go bindings
pushd "$RUST_BLS48581_PACKAGE" > /dev/null
uniffi-bindgen-go src/lib.udl -o "$BINDINGS_DIR"/generated
