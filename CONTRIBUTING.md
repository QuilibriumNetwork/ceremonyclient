# Local development

The following software is required for local development (assuming MacOS ARM):

- Go 1.20 
- Rust toolchain 
- GMP 6.3: `brew install gmp`
- Install the Go plugin for uniffi-rs: `cargo install uniffi-bindgen-go --git https://github.com/NordSecurity/uniffi-bindgen-go --tag v0.2.1+v0.25.0`

# Building release binaries

The following is software is required to build release binaries (assuming MacOS
ARM) :

- [Local development](#local-development) dependencies
- Docker
- [Taskfile](https://taskfile.dev/)

Then from the repo root use the following commands to build the release binaries
that statically link the [native VDF](./crates/vdf) for the supported platforms:

```shell
task build_node_arm64_macos
task build_node_arm64_linux
task build_node_arm64_macos
```

The output binaries will be in `node/build`.

# Testing

Testing the [`vdf`](./vdf) and [`node`](./node) packages requires linking the
[native VDF](./crates/vdf). The `test.sh` scripts in the respective directories
help with this.
