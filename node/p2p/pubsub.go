package p2p

import (
	"source.quilibrium.com/quilibrium/monorepo/go-libp2p-blossomsub/pb"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
)

type PubSub interface {
	PublishToBitmask(bitmask []byte, data []byte) error
	Publish(address []byte, data []byte) error
	Subscribe(bitmask []byte, handler func(message *pb.Message) error) error
	Unsubscribe(bitmask []byte, raw bool)
	GetPeerID() []byte
	GetBitmaskPeers() map[string][]string
	GetPeerstoreCount() int
	GetNetworkPeersCount() int
	GetNetworkInfo() *protobufs.NetworkInfoResponse
	SignMessage(msg []byte) ([]byte, error)
	GetPublicKey() []byte
	GetPeerScore(peerId []byte) int64
	SetPeerScore(peerId []byte, score int64)
}
