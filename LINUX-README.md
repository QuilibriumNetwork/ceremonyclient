# Quilibrium - Sunset

Quilibrium is a decentralized alternative to platform as a service providers.
This release, mirrored to GitHub, is the Sunset release, which contains the
initial application, the MPC Powers-of-Tau Ceremony. Documentation for the
underlying technology can be found at https://www.quilibrium.com/

## Install Requirements

    wget https://go.dev/dl/go1.20.14.linux-amd64.tar.gz
    sudo tar -xvf go1.20.14.linux-amd64.tar.gz
    sudo mv go /usr/local
    sudo rm go1.20.14.linux-amd64.tar.gz
    sudo nano ~/.bashrc

If you use arm cpu, you must change the commands as amd64.tar.gz instead of amd64.tar.gz

At the end of the file, add these lines and save the file.

    GOROOT=/usr/local/go
    GOPATH=$HOME/go
    PATH=$GOPATH/bin:$GOROOT/bin:$PATH

On command line, run 
   source  ~/.bashrc

Check GO Version
    go version

It must show "go version go.1.20.14 linux/amd64" or arm64 based on your cpu technology.

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


Save the file then,
    
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

## Useful Commands
In order to query the below commands, execute the following command at ceremonyclient/node/ folder

    GOEXPERIMENT=arenas go run ./...  -balance
print the node's confirmed token balance to stdout and exit

 
     GOEXPERIMENT=arenas go run ./...  -config string
the configuration directory (default ".config")


    GOEXPERIMENT=arenas go run ./...  -cpuprofile string
write cpu profile to file


    GOEXPERIMENT=arenas go run ./...  -db-console
starts the node in database console mode


    GOEXPERIMENT=arenas go run ./...  -debug
sets log output to debug (verbose)


    GOEXPERIMENT=arenas go run ./...  -import-priv-key string
creates a new config using a specific key from the phase one ceremony


    GOEXPERIMENT=arenas go run ./...  -memprofile string
write memory profile after 20m to this file


    GOEXPERIMENT=arenas go run ./...  -node-info
print node related information


    GOEXPERIMENT=arenas go run ./...  -peer-id
print the peer id to stdout from the config and exit
