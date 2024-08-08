package app

import (
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/go-libp2p-blossomsub/pb"
	"source.quilibrium.com/quilibrium/monorepo/node/keys"
	"source.quilibrium.com/quilibrium/monorepo/node/p2p"
)

type Node struct {
	logger     *zap.Logger
	keyManager keys.KeyManager
	pubSub     p2p.PubSub
	quit       chan struct{}
}

func newNode(
	logger *zap.Logger,
	keyManager keys.KeyManager,
	pubSub p2p.PubSub,
) (*Node, error) {
	return &Node{
		logger:     logger,
		keyManager: keyManager,
		pubSub:     pubSub,
		quit:       make(chan struct{}),
	}, nil
}

func (d *Node) Start() {
	d.pubSub.Subscribe(
		[]byte{
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		},
		func(message *pb.Message) error { return nil },
	)
	<-d.quit
}

func (d *Node) Stop() {
	go func() {
		d.quit <- struct{}{}
	}()
}

func (n *Node) GetLogger() *zap.Logger {
	return n.logger
}

func (n *Node) GetKeyManager() keys.KeyManager {
	return n.keyManager
}

func (n *Node) GetPubSub() p2p.PubSub {
	return n.pubSub
}
