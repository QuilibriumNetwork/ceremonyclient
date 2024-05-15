FROM golang:1.20.14-bookworm

ENV GOEXPERIMENT=arenas

RUN sh -c "$(curl --location https://taskfile.dev/install.sh)" -- -d -b /usr/local/bin
RUN apt-get update && apt-get install git

WORKDIR /root/ceremonyclient

COPY . .

WORKDIR /root/ceremonyclient/signers
