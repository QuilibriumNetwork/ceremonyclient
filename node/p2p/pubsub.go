package p2p

import (
	"google.golang.org/grpc"
	"source.quilibrium.com/quilibrium/monorepo/go-libp2p-blossomsub/pb"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
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
	GetMultiaddrOfPeer(peerId []byte) string
	StartDirectChannelListener(
		key []byte,
		server *grpc.Server,
	) error
	GetDirectChannel(peerId []byte) (*grpc.ClientConn, error)
	GetNetworkInfo() *protobufs.NetworkInfoResponse
}
