# go-libp2p-blossomsub

<p align="left">
  <a href="https://quilibrium.com"><img src="https://img.shields.io/badge/made%20by-Quilibrium%20Inc-orange.svg?style=flat-square" /></a>
  <a href="https://github.com/quilibriumnetwork"><img src="https://img.shields.io/badge/project-Quilibrium-orange.svg?style=flat-square" /></a>
  <a href="https://discourse.quilibrium.com/"><img src="https://img.shields.io/discourse/posts.svg?server=https%3A%2F%2Fquilibrium.discourse.group&style=flat-square" /></a>
  <a href=""><img src="https://img.shields.io/badge/golang-%3E%3D1.22.0-orange.svg?style=flat-square" /></a>
</p>

This repo contains the canonical blossomsub implementation for Quilibrium. It has historical origins in [Gossipsub](https://github.com/libp2p/go-libp2p-pubsub), but has diverged significantly. Floodsub and Randomsub are not included in this fork.

## Table of Contents

- [Install](#install)
- [Usage](#usage)
- [Overview](#overview)
- [Tracing](#tracing)
- [Contribute](#contribute)
- [License](#license)

## Install

```
go get source.quilibrium.com/quilibrium/monorepo/go-libp2p-pubsub
```

## Usage

To be used for messaging in high scale, high throughput p2p instrastructure such as Quilibrium.

### Overview

```
.
├── LICENSE
├── README.md
# Regular Golang repo set up
├── codecov.yml
├── pb
├── go.mod
├── go.sum
├── doc.go
# PubSub base
├── backoff.go
├── bitmask.go
├── blacklist.go
├── comm.go
├── discovery.go
├── gossip_tracer.go
├── midgen.go
├── peer_gater.go
├── peer_notify.go
├── pubsub.go
├── sign.go
├── subscription.go
├── tag_tracer.go
├── trace.go
├── tracer.go
├── validation.go
# Blossomsub router
├── blossomsub_feat.go
├── blossomsub.go
├── mcache.go
├── score.go
└── score_params.go
```

### Tracing

The pubsub system supports _tracing_, which collects all events pertaining to the internals of the system. This allows you to recreate the complete message flow and state of the system for analysis purposes.

To enable tracing, instantiate the pubsub system using the `WithEventTracer` option; the option accepts a tracer with three available implementations in-package (trace to json, pb, or a remote peer).
If you want to trace using a remote peer in the same way gossipsub tracing worked, you would need to do so by forking the `traced` daemon from [go-libp2p-pubsub-tracer](https://github.com/libp2p/go-libp2p-pubsub-tracer).

For instance, to capture the trace as a json file, you can use the following option:
```go
tracer, err := pubsub.NewJSONTracer("/path/to/trace.json")
if err != nil {
  panic(err)
}

pubsub.NewBlossomSub(..., pubsub.WithEventTracer(tracer))
```

To capture the trace as a protobuf, you can use the following option:
```go
tracer, err := pubsub.NewPBTracer("/path/to/trace.pb")
if err != nil {
  panic(err)
}

pubsub.NewBlossomSub(..., pubsub.WithEventTracer(tracer))
```

Finally, to use the remote tracer, you can use the following incantations:
```go
// assuming that your tracer runs in x.x.x.x and has a peer ID of QmTracer
pi, err := peer.AddrInfoFromP2pAddr(ma.StringCast("/ip4/x.x.x.x/tcp/4001/p2p/QmTracer"))
if err != nil {
  panic(err)
}

tracer, err := pubsub.NewRemoteTracer(ctx, host, pi)
if err != nil {
  panic(err)
}

ps, err := pubsub.NewBlossomSub(..., pubsub.WithEventTracer(tracer))
```

## Contribute

Contributions welcome. Please check out [the issues](https://source.quilibrium.com/quilibrium/monorepo/-/issues).

Quilibrium does not have a code of conduct for contributions – contributions are accepted on merit and benefit to the protocol.


## License

The go-libp2p-blossomsub project being forked from go-libp2p-pubsub inherits the dual-license under Apache 2.0 and MIT terms:

- Apache License, Version 2.0, ([LICENSE-APACHE](./LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](./LICENSE-MIT) or http://opensource.org/licenses/MIT)
