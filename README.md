# Quilibrium - Solstice

Quilibrium is a decentralized alternative to platform as a service providers.
This release is part of the phases of the Dusk release, which finalizes with
the full permissionless mainnet in version 2.0. Documentation for the
underlying technology can be found at https://www.quilibrium.com/

## Quick Start

Running production nodes from source is no longer recommended given build complexity. Please refer to our release information to obtain the latest version.

## Running From Source

Builds are now a hybrid of Rust and Go, so you will need both go 1.22 and latest Rust + Cargo.

### Prerequisites

Before running from source, ensure you have the necessary prerequisites installed. We provide an `install_dependencies.sh` script that will automatically install the required dependencies for Linux and macOS systems. To use it:

1. Make the script executable:
   ```
   chmod +x install_dependencies.sh
   ```

2. Run the script:
   ```
   ./install_dependencies.sh
   ```

This script will install:
- Rust (latest version)
- Go (version 1.22.4)
- GMP (GNU Multiple Precision Arithmetic Library)
- Other necessary dependencies specific to your operating system

For manual installation or for other operating systems, please refer to the [CONTRIBUTING.md](CONTRIBUTING.md#manually-installing-dependencies) file for detailed instructions.

### Compiling VDF and BLS48581 Libraries

The VDF implementation is now in Rust, and requires GMP to build. On Mac, you can install GMP with brew (`brew install gmp`). On Linux, you will need to find the appropriate package for your distro.

Install the go plugin for uniffi-rs:

    cargo install uniffi-bindgen-go --git https://github.com/NordSecurity/uniffi-bindgen-go --tag v0.2.1+v0.25.0

Be sure to follow the PATH export given by the installer.

#### VDF
Build the Rust VDF implementation by navigating to the vdf folder, and run `./generate.sh`.

#### BLS48581
Similarly, for the BLS48581 implementation, navigate to the bls48581 folder and run `./generate.sh`.

### Compiling the Node binary

Because of the Rust interop, be sure you follow the above steps for the VDF and BLS48581 libraries before proceeding to this. 

Navigate to the `node` folder, and run:
    GOEXPERIMENT=arenas CGO_ENABLED=1 go build \
      -ldflags "-linkmode 'external' -extldflags '-L$(dirname $(dirname $(realpath $0)))/target/release -lvdf -lbls48581 -ldl -lm'" \
      -o node main.go

#### Running Your Compiled Node Version

For local development, specific use-cases, or running custom versions, you can run the node binary without signature checks. This is primarily useful for testing, debugging, and experimenting with modifications to the node software.

To run the node binary without signature checks (it will fail otherwise):

1. Navigate to the `node` directory:

   ```
   cd node
   ```

2. Run the node with the `--signature-check=false` flag:

   ```
   ./node --signature-check=false
   ```

   This flag disables signature checks and sets up the node for local development.

3. Optionally, you can specify a custom config file:

   ```
   ./node --signature-check=false --config path/to/your/config.yml
   ```
   ```

Note: Running without signature checks should generally never be used in production, i.e. on the mainnet. It bypasses important security measures and should only be employed for specific, well-defined use-cases where the risks are fully understood and mitigated. Do not use this option simply because it's available; always consider the security implications carefully.

### Running a Local Testnet

For development and testing purposes, you can set up a local testnet using the `run_testnet.sh` script. This script automates the process of setting up and running multiple test nodes on your local machine.

To use the script:

1. Run the script from the repository root:

   ```
   ./run_testnet.sh
   ```

2. The script will guide you through the setup process, including recommending the number of nodes and CPU limits based on your system resources.

Once you have run this once, it will give you a command that you can use to run the nodes once you have completed the setup in order to avoid having to interact with the prompts again.

You can customize the testnet setup using command-line options. For more detailed information on setting up a local testnet, including available options and manual dependency installation, please refer to the [Contributing Guide](CONTRIBUTING.md#setting-up-a-local-testnet).

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

### 1. The Q Guide - Beginners' Guide

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