#!/bin/bash
set -euxo pipefail

ROOT_DIR="${ROOT_DIR:-$( cd "$(dirname "$(realpath "$( dirname "${BASH_SOURCE[0]}" )")")" >/dev/null 2>&1 && pwd )}"

RUST_VDF_PACKAGE="$ROOT_DIR/crates/vdf"
BINDINGS_DIR="$ROOT_DIR/vdf"

# Build the Rust VDF package in release mode
RUSTFLAGS='-L /opt/homebrew/Cellar/gmp/6.3.0/lib' cargo build -p vdf --release

# Generate Go bindings
pushd "$RUST_VDF_PACKAGE" > /dev/null
uniffi-bindgen-go src/lib.udl -o "$BINDINGS_DIR"/generated
