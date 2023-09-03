package consensus

import (
	"source.quilibrium.com/quilibrium/monorepo/node/execution"
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
	GetFrame() uint64
	GetDifficulty() uint32
	GetState() EngineState
	GetFrameChannel() <-chan uint64
}
