# Contributing

## Testing

Testing the [`vdf`](./vdf) and [`node`](./node) packages requires linking the
[native VDF](./crates/vdf). The `test.sh` scripts in the respective directories
help with this.

## Setting Up a Local Testnet

To set up and run a local testnet for development and testing purposes, you can use the `run_testnet.sh` script provided in the repository. This script automates the process of setting up multiple nodes on your local machine, including installing necessary prerequisites.

To use the script:

1. Run the script from the repository root:

   ```
   ./run_testnet.sh
   ```

2. The script will check for and install prerequisites (Rust, Go, GMP, cpulimit) if they're not already present.

3. It will then display recommended settings based on your system resources and ask if you want to use them. If not, you can manually define the parameters.

You can also customize the testnet setup using command-line options:

- `--recompile-libs`: Force recompilation of libraries
- `--reinstall-deps`: Reinstall dependencies
- `--redo-config`: Recreate node configurations
- `--node-count <number>`: Set the number of nodes to run
- `--cores-per-node <number>`: Set the number of cores per node (minimum 4)
- `--cpu-limit <percentage>`: Set CPU usage limit per node
- `--timeout <seconds>`: Set a timeout for the testnet run
- `--dry-run`: Perform a dry run without actually starting the nodes

For example:

```
./run_testnet.sh --node-count 6 --cores-per-node 4 --cpu-limit 50 --timeout 3600
```

This local testnet setup is useful for testing network interactions, consensus mechanisms, and other features that require multiple nodes.

Note: The script will attempt to install prerequisites automatically, but some systems may require manual intervention or additional setup steps depending on the specific environment.

#### Validating a working testnet

You can run: 
```bash
grpcurl -plaintext localhost:8337 quilibrium.node.node.pb.NodeService.GetNodeInfo

# Output should be:
# {
#   "peerId": "Qm...", // the peer id printed out in the console when running the testnet startup script
#   "maxFrame": "0", // varies depending on how long it has been running until you ran the command
#   "version": "AQQVAQ==" // will vary depending on version of the binarys
# }
```
### Manually Installing Dependencies

Based on the `run_testnet.sh` script, here's a list of prerequisites that may need to be installed manually, depending on your system:

#### Linux Dependencies

| Dependency | Version | Install Command |
|------------|---------|-----------------|
| Rust | Latest | `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh` |
| Go | 1.22.4 | `wget https://golang.org/dl/go1.22.4.linux-amd64.tar.gz && sudo tar -C /usr/local -xzf go1.22.4.linux-amd64.tar.gz` |
| GMP | Latest | `sudo apt-get install libgmp-dev` |
| curl | Latest | `sudo apt-get install curl` |
| build-essential | Latest | `sudo apt-get install build-essential` |
| wget | Latest | `sudo apt-get install wget` |
| uniffi-bindgen-go | v0.2.1+v0.25.0 | `cargo install uniffi-bindgen-go --git https://github.com/NordSecurity/uniffi-bindgen-go --tag v0.2.1+v0.25.0` |
| grpcurl | Latest | `go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest` |
| cpulimit | Latest | `sudo apt-get install cpulimit` |

#### macOS Dependencies

| Dependency | Version | Install Command |
|------------|---------|-----------------|
| Rust | Latest | `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh` |
| Homebrew | Latest | `/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"` |
| Go | 1.22.4 | `brew install go@1.22.4` |
| GMP | Latest | `brew install gmp` |
| curl | Latest | `brew install curl` |
| wget | Latest | `brew install wget` |
| uniffi-bindgen-go | v0.2.1+v0.25.0 | `cargo install uniffi-bindgen-go --git https://github.com/NordSecurity/uniffi-bindgen-go --tag v0.2.1+v0.25.0` |
| grpcurl | Latest | `go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest` |
| cpulimit | Latest | `brew install cpulimit` |

Note: The script attempts to install these prerequisites automatically. However, depending on your system configuration, you might need to install some of these manually if the automatic installation fails. In such cases, you would need to use your system's package manager (apt, brew, etc.) to install the missing components before running the script again.

## Pull Requests

Contributions are welcome – a new network is rife with opportunities. We are
in the process of updating our JIRA board so that it can be made public. The
repository has basic coding guidelines:

- 80 character line limit, with the exception where gofmt or the syntax is
  impossible to achieve otherwise
- Error wrapping matching function names
- Interface composition and dependency injection with Wire

## Building release binaries

The following software is required to build release binaries (assuming MacOS
ARM):

- [Running from source](README.md#running-from-source) dependencies
- Docker
- [Taskfile](https://taskfile.dev/)

Then from the repo root use the following commands to build the release binaries
that statically link the [native VDF](./crates/vdf) for the supported platforms:

```shell
task build_node_arm64_macos
task build_node_arm64_linux
task build_node_amd64_linux
```

The output binaries will be in `node/build`.