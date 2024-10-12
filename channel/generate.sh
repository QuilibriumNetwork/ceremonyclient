#!/bin/bash
set -euxo pipefail

ROOT_DIR="${ROOT_DIR:-$( cd "$(dirname "$(realpath "$( dirname "${BASH_SOURCE[0]}" )")")" >/dev/null 2>&1 && pwd )}"

RUST_CHANNEL_PACKAGE="$ROOT_DIR/crates/channel"
BINDINGS_DIR="$ROOT_DIR/channel"

# Build the Rust Channel package in release mode
cargo build -p channel --release

# Generate Go bindings
pushd "$RUST_CHANNEL_PACKAGE" > /dev/null
uniffi-bindgen-go src/lib.udl -o "$BINDINGS_DIR"/generated
