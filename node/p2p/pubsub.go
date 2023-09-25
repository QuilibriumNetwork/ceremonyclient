package p2p

import (
	"source.quilibrium.com/quilibrium/monorepo/go-libp2p-blossomsub/pb"
)

type PubSub interface {
	PublishToBitmask(bitmask []byte, data []byte) error
	Publish(data []byte) error
	Subscribe(bitmask []byte, handler func(message *pb.Message) error, raw bool)
	Unsubscribe(bitmask []byte, raw bool)
	GetPeerID() []byte
	GetBitmaskPeers() map[string][]string
	GetPeerstoreCount() int
	GetNetworkPeersCount() int
	GetRandomPeer(bitmask []byte) ([]byte, error)
}
