# Quilibrium - Solstice

Quilibrium is a decentralized alternative to platform as a service providers.
This release is part of the phases of the Dusk release, which finalizes with
the full permissionless mainnet in version 2.0. Documentation for the
underlying technology can be found at https://www.quilibrium.com/

## Quick Start

Running production nodes from source is no longer recommended given build complexity. Please refer to our release information to obtain the latest version.

## Running From Source

Builds are now a hybrid of Rust and Go, so you will need both go 1.22 and latest Rust + Cargo.

### VDF

The VDF implementation is now in Rust, and requires GMP to build. On Mac, you can install GMP with brew (`brew install gmp`). On Linux, you will need to find the appropriate package for your distro.

Install the go plugin for uniffi-rs:

    cargo install uniffi-bindgen-go --git https://github.com/NordSecurity/uniffi-bindgen-go --tag v0.2.1+v0.25.0

Be sure to follow the PATH export given by the installer.

Build the Rust VDF implementation by navigating to the vdf folder, and run `./generate.sh`.

### Node

Because of the Rust interop, be sure you follow the above steps for the VDF before proceeding to this. Navigate to the node folder, and run (making sure to update the path for the repo):

    CGO_LDFLAGS="-L/path/to/ceremonyclient/target/release -lvdf -ldl -lm" \
        CGO_ENABLED=1 \
        GOEXPERIMENT=arenas \
        go run ./... --signature-check=false

## gRPC/REST Support

If you want to enable gRPC/REST, add the following entries to your config.yml:

    listenGrpcMultiaddr: <multiaddr> 
    listenRESTMultiaddr: <multiaddr>

Please note: this interface, while read-only, is unauthenticated and not rate-
limited. It is recommended that you only enable if you are properly controlling
access via firewall or only query via localhost.

## Token Balance

In order to query the token balance of a running node, execute the following command from the `node/` folder:

    ./node-$version-$platform -balance

The accumulated token balance will be printed to stdout in QUILs.

Note that this feature requires that [gRPC support](#grpcrest-support) is enabled.

## Community Section

This section contains community-built clients, applications, guides, etc <br /><br />
<b>Disclaimer</b>: Because some of these may contain external links, do note that these are unofficial – every dependency added imparts risk, so if another project's github account were compromised, for example, it could lead people down a dangerous or costly path. Proceed with caution as always and refer to reliable members of the community for verification of links before clicking or connecting your wallets

### 1. The Q Guide - Beginners’ Guide

- A detailed beginners' guide for how to setup a Quilibrium Node, created by [@demipoet](https://www.github.com/demipoet) - [link](https://quilibrium.guide/)<br/>

## Development

Please see the [CONTRIBUTING.md](CONTRIBUTING.md) file for more information on
how to contribute to this repository.

## License + Interpretation

Significant portions of Quilibrium's codebase depends on GPL-licensed code,
mandating a minimum license of GPL, however Quilibrium is licensed as AGPL to
accomodate the scenario in which a cloud provider may wish to coopt the network
software. The AGPL allows such providers to do so, provided they are willing
to contribute back the management code that interacts with the protocol and node
software. To provide clarity, our interpretation is with respect to node
provisioning and management tooling for deploying alternative networks, and not
applications which are deployed to the network, mainnet status monitors, or
container deployments of mainnet nodes from the public codebase.
