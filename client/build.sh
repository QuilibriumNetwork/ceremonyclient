#!/bin/bash
set -euxo pipefail

# This script builds the node binary for the current platform and statically links it with VDF static lib.
# Assumes that the VDF library has been built by running the generate.sh script in the `../vdf` directory.

ROOT_DIR="${ROOT_DIR:-$( cd "$(dirname "$(realpath "$( dirname "${BASH_SOURCE[0]}" )")")" >/dev/null 2>&1 && pwd )}"

CLIENT_DIR="$ROOT_DIR/client"
BINARIES_DIR="$ROOT_DIR/target/release"

pushd "$CLIENT_DIR" > /dev/null

export CGO_ENABLED=1

os_type="$(uname)"
case "$os_type" in
    "Darwin")
        # Check if the architecture is ARM
        if [[ "$(uname -m)" == "arm64" ]]; then
            # MacOS ld doesn't support -Bstatic and -Bdynamic, so it's important that there is only a static version of the library
            go build -ldflags "-linkmode 'external' -extldflags '-L$BINARIES_DIR -lvdf -lbls48581 -ldl -lm'" "$@"
        else
            echo "Unsupported platform"
            exit 1
        fi
        ;;
    "Linux")
        go build -ldflags "-linkmode 'external' -extldflags '-L$BINARIES_DIR -Wl,-Bstatic -lvdf -lbls48581 -Wl,-Bdynamic -ldl -lm'" "$@"
        ;;
    *)
        echo "Unsupported platform"
        exit 1
        ;;
esac
