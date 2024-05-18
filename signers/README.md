# Release Signatories

Scripts in this folder are tools for release signers to build and sign Quilibrium binaries.

Requirements:
- bash environment (Ubuntu, macOS, etc.)
- openssl - digests and signatures
- git - to checkout this branch
- Docker - to run a container with golang and compile binaries
- [Taskfile](https://taskfile.dev/installation/)

Checkout the whole repo from a release branch and then in the `signers` folder you can run `task` commands. Before you
can run commands you have to copy `.env.example` to `.env` and fill it out. You need a local folder with all the pem
files, required by signature verification.

Important tasks:
- `task build` to build the binaries in a dedicated docker image
- `task verify:build` to verify that you can build the exact same binaries
- `task verify:digest` to verify the digests
- `task verify:signatures` to verify all signatures
