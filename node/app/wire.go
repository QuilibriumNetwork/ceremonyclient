//go:build wireinject
// +build wireinject

package app

import (
	"github.com/google/wire"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/node/config"
	"source.quilibrium.com/quilibrium/monorepo/node/keys"
	"source.quilibrium.com/quilibrium/monorepo/node/p2p"
)

func debugLogger() *zap.Logger {
	log, err := zap.NewDevelopment()
	if err != nil {
		panic(err)
	}

	return log
}

var debugLoggerSet = wire.NewSet(
	debugLogger,
)

var keyManagerSet = wire.NewSet(
	wire.FieldsOf(new(*config.Config), "Key"),
	keys.NewFileKeyManager,
	wire.Bind(new(keys.KeyManager), new(*keys.FileKeyManager)),
)

var pubSubSet = wire.NewSet(
	wire.FieldsOf(new(*config.Config), "P2P"),
	p2p.NewInMemoryPeerInfoManager,
	p2p.NewBlossomSub,
	wire.Bind(new(p2p.PubSub), new(*p2p.BlossomSub)),
	wire.Bind(new(p2p.PeerInfoManager), new(*p2p.InMemoryPeerInfoManager)),
)

func NewNode(*config.Config) (*Node, error) {
	panic(wire.Build(
		debugLoggerSet,
		keyManagerSet,
		pubSubSet,
		newNode,
	))
}
