package execution

import (
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
)

type ExecutionEngine interface {
	GetName() string
	GetSupportedApplications() []*protobufs.Application
	Start() <-chan error
	Stop(force bool) <-chan error
	ProcessMessage(
		address []byte,
		message *protobufs.Message,
	) ([]*protobufs.Message, error)
	GetPeerInfo() *protobufs.PeerInfoResponse
	GetFrame() *protobufs.ClockFrame
}
