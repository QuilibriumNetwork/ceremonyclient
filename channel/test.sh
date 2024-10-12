#!/bin/bash
set -euxo pipefail

# Run tests for the channel package. Takes care of linking the native Channel library. 
# Assumes that the Channel library has been built by running the generate.sh script in the same directory.

ROOT_DIR="${ROOT_DIR:-$( cd "$(dirname "$(realpath "$( dirname "${BASH_SOURCE[0]}" )")")" >/dev/null 2>&1 && pwd )}"

NODE_DIR="$ROOT_DIR/channel"
BINARIES_DIR="$ROOT_DIR/target/release"

# Link the native Channel library and execute tests
pushd "$NODE_DIR" > /dev/null
	CGO_LDFLAGS="-L$BINARIES_DIR -lchannel -ldl" \
	CGO_ENABLED=1 \
	GOEXPERIMENT=arenas \
  go test "$@"
