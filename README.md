# Quilibrium - Dawn

Quilibrium is a decentralized alternative to platform as a service providers.
This release, mirrored to GitHub, is the Dawn release, which contains the
initial application, the MPC Powers-of-Tau Ceremony. Documentation for the
underlying technology can be found at https://www.quilibrium.com/

## Quick Start

All commands are to be run in the `node/` folder.

If you have a voucher from the offline ceremony, first run:

    GOEXPERIMENT=arenas go run ./... -import-priv-key `cat /path/to/voucher.hex`

If you do not, or have already run the above, run:

    GOEXPERIMENT=arenas go run ./...

## EXPERIMENTAL – gRPC/REST Support

If you want to enable gRPC/REST, add the following entries to your config.yml:

    listenGrpcMultiaddr: <multiaddr> 
    listenRESTMultiaddr: <multiaddr>

Please note: this interface, while read-only, is unauthenticated and not rate-
limited. It is recommended that you only enable if you are properly controlling
access via firewall or only query via localhost.

## Purpose

The ceremony application provides a secure reference string (SRS) from which
KZG proofs can be constructed for the network. This yields applicability for a
number of proof systems, in particular for the release after Dawn, the ability
to provide proofs of execution, and proofs of data availability for the network.

### Rewards

For participating in a round of the ceremony, nodes will be allocated:

    reward = 161 * log_2(participant_count) QUIL

### Basic Flow

Rounds of the ceremony follow the following order:

- OPEN: Nodes can join in for the round, deferring preference to nodes that
could not join in on the prior round
- IN PROGRESS: The MPC ceremony round is in progress, nodes are engaging in a
logarithmic collection of Multiplication-to-Add Oblivious Transfer circuits,
each sub round producing a new collection of values, until the sub rounds have
completed, producing a collection of public G1 and G2 BLS48-581 points for each
peer.
- FINALIZING: The collection of points are broadcasted, and added together,
producing a singular ceremony transcript contribution.
- VALIDATING: The updated ceremony transcript is validated against the
predecessor, and is confirmed to be the new state, issuing rewards to the
participant set. The next round can begin.

## Pull Requests

Contributions are welcome – a new network is rife with opportunities. We are
in the process of updating our JIRA board so that it can be made public. The
repository has basic coding guidelines:

- 80 character line limit, with the exception where gofmt or the syntax is
impossible to achieve otherwise
- Error wrapping matching function names
- Interface composition and dependency injection with Wire

## Minimum System Requirements

For the Dawn phase, a server must have a minimum of 16GB of RAM, preferably
32 GB, 250GB of storage, preferably via SSD, and 50MBps symmetric bandwidth.
For Intel/AMD, the baseline processor is a Skylake processor @ 3.4GHz with 12
dedicated cores. For ARM, the M1 line of Apple is a good reference.

With Dusk, these minimum requirements will reduce significantly.

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

