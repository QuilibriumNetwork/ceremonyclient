# Quilibrium - Aurora

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

## Peer ID

In order to find the peer id of a running node, execute the following command from the `node/` folder:

    GOEXPERIMENT=arenas go run ./... -peer-id

The peer id will be printed to stdout.

## EXPERIMENTAL – gRPC/REST Support

If you want to enable gRPC/REST, add the following entries to your config.yml:

    listenGrpcMultiaddr: <multiaddr> 
    listenRESTMultiaddr: <multiaddr>

Please note: this interface, while read-only, is unauthenticated and not rate-
limited. It is recommended that you only enable if you are properly controlling
access via firewall or only query via localhost.

## Token Balance

In order to query the token balance of a running node, execute the following command from the `node/` folder:

    GOEXPERIMENT=arenas go run ./... -balance

The confirmed token balance will be printed to stdout in QUILs.

Note that this feature requires that [gRPC support](#experimental--grpcrest-support) is enabled.

## Stats Collection

In order to opt-in to stats collection about the health of the network, edit your `config.yml` in the `node/.config` directory to have a new section under `engine`:

```yml
<earlier parts of config>
engine:
  statsMultiaddr: "/dns/stats.quilibrium.com/tcp/443"
  <rest of config continues below>
```

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

## Community Section

This section contains community-built clients, applications, guides, etc <br /><br />
<b>Disclaimer</b>: Because some of these may contain external links, do note that these are unofficial – every dependency added imparts risk, so if another project's github account were compromised, for example, it could lead people down a dangerous or costly path. Proceed with caution as always and refer to reliable members of the community for verification of links before clicking or connecting your wallets

### 1. The Q Guide - Beginners’ Guide

- A detailed beginners' guide for how to setup a Quilibrium Node, created by [@demipoet](https://www.github.com/demipoet) - [link](https://quilibrium.guide/)<br/>

  
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
