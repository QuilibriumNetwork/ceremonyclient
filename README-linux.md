# Quilibrium - Dawn

Quilibrium is a decentralized alternative to platform as a service providers.
This release, mirrored to GitHub, is the Dawn release, which contains the
initial application, the MPC Powers-of-Tau Ceremony. Documentation for the
underlying technology can be found at https://www.quilibrium.com/

## Install Requirements

    wget https://:go.dev/dl/go1.20.14.linux-amd64.tar.gz
    sudo tar -xvf go1.20.14.linux-amd64.tar.gz
    sudo mv go /usr/local
    sudo rm go1.20.14.linux-amd64.tar.gz
    sudo nano ~/.bashrc

At the end of the file, add these lines and save the file.

    GOROOT=/usr/local/go
    GOPATH=$HOME/go
    PATH=$GOPATH/bin:$GOROOT/bin:$PATH

On command line, run 
    ~/.bashrc

Check GO Version
    go version

It must show "go version go.1.20.14 linux/amd64"

## Configure Linux Network Device Settings

To optimize throughput and latency for large parallel job typcal of network like Q

    nano /etc/sysctl.conf

Copy and paste the 3 lines below into the file. The values below are six hundred million.

    #Increase buffer sizes for better network performance
    net.core.rmem_max=600000000
    net.core.wmem_max=600000000

Save and exit then
    sudo sysctl -p


## Clone the Repo

    git clone https://github.com/QuilibriumNetwork/ceremonyclient.git
    cd ceremonyclient/node
    
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

    sudo nano .config/config.yml

edit these lines below

    listenGrpcMultiaddr: /ip4/127.0.0.1/tcp/8337
    listenRESTMultiaddr: /ip4/127.0.0.1/tcp/8338

Save and exit

Ensure that port 8337 among other neeeded ports are enabled via firewall.

    sudo ufw enable
    sudo ufw allow 8336
    sudo ufw allow 8337
    sudo ufw allow 8338
    sudo ufw status


Please note: this interface, while read-only, is unauthenticated and not rate-
limited. It is recommended that you only enable if you are properly controlling
access via firewall or only query via localhost.

## Token Balance

In order to query the token balance of a running node, execute the following command from the `node/` folder:

    GOEXPERIMENT=arenas go run ./... -balance

Or

    GOEXPERIMENT=arenas /root/go/bin/node -balance

The confirmed token balance will be printed to stdout in QUILs.

Note that this feature requires that [gRPC support](#experimental--grpcrest-support) is enabled.

## Build the node binary file 

    GOEXPERIMENT=arenas go install ./...

Thiw will build binary file in /root/go/bin folder

## Start the Quilibrium Node as a Service

    nano /lib/systemd/system/ceremonyclient.service

Write the code below

    [Unit]
    Description=Ceremony Client Go App Service

    [Service]
    Type=simple
    Restart=always
    RestartSec=5s
    WorkingDirectory=/root/ceremonyclient/node
    Environment=GOEXPERIMENT=arenas
    ExecStart=/root/go/bin/node ./...

    [Install]
    WantedBy=multi-user.target

Save and exit

To start service run

    service ceremonyclient start

To stop service run

    service ceremonyclient stop

To view service logs run

    sudo journalctl -u ceremonyclient.service -f --no-hostname -o cat

## Upgrading Node

    service ceremonyclient stop
    git fetch origin
    git merge origin

Go to ceremonyclient/node folder and run

    GOEXPERIMENT=arenas go clean -v -n -a ./...
    rm /root/go/bin/node
    GOEXPERIMENT=arenas go install ./...
    service ceremonyclient start

If everything is okay you would see logs when you run

    sudo journalctl -u ceremonyclient.service -f --no-hostname -o cat

Ensure that your service running correctly.

## Auto Upgrading Script

Create a file named update.sh in your server and put the code below.



    #!/bin/bash

    # Stop the ceremonyclient service
    service ceremonyclient stop

    # Switch to the ~/ceremonyclient directory
    cd ~/ceremonyclient

    # Fetch updates from the remote repository
    git fetch origin
    git merge origin

    # Switch to the ~/ceremonyclient/node directory
    cd ~/ceremonyclient/node

    # Clean and reinstall node
    GOEXPERIMENT=arenas go clean -v -n -a ./...
    rm /root/go/bin/node
    GOEXPERIMENT=arenas go install ./...

    # Start the ceremonyclient service
    service ceremonyclient start


    chmod u+x update.sh

When there is new update, run
    ./update.sh

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

