package consensus

import (
	"crypto"

	"source.quilibrium.com/quilibrium/monorepo/node/config"
	"source.quilibrium.com/quilibrium/monorepo/node/execution"
	"source.quilibrium.com/quilibrium/monorepo/node/keys"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
)

type EngineState int

const (
	EngineStateStopped EngineState = iota
	EngineStateStarting
	EngineStateLoading
	EngineStateCollecting
	EngineStateProving
	EngineStatePublishing
	EngineStateVerifying
	EngineStateStopping
)

type ConsensusEngine interface {
	Start() <-chan error
	Stop(force bool) <-chan error
	RegisterExecutor(exec execution.ExecutionEngine, frame uint64) <-chan error
	UnregisterExecutor(name string, frame uint64, force bool) <-chan error
	GetFrame() *protobufs.ClockFrame
	GetDifficulty() uint32
	GetState() EngineState
	GetFrameChannel() <-chan *protobufs.ClockFrame
}

type DataConsensusEngine interface {
	Start() <-chan error
	Stop(force bool) <-chan error
	RegisterExecutor(exec execution.ExecutionEngine, frame uint64) <-chan error
	UnregisterExecutor(name string, frame uint64, force bool) <-chan error
	GetFrame() *protobufs.ClockFrame
	GetDifficulty() uint32
	GetState() EngineState
	GetProvingKey(
		engineConfig *config.EngineConfig,
	) (crypto.Signer, keys.KeyType, []byte, []byte)
	IsInProverTrie(key []byte) bool
	GetPeerInfo() *protobufs.PeerInfoResponse
}
