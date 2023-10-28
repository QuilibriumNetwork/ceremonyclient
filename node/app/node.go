package app

import (
	"errors"

	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus"
	"source.quilibrium.com/quilibrium/monorepo/node/execution"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/ceremony"
	"source.quilibrium.com/quilibrium/monorepo/node/keys"
	"source.quilibrium.com/quilibrium/monorepo/node/p2p"
	"source.quilibrium.com/quilibrium/monorepo/node/store"
)

type Node struct {
	logger      *zap.Logger
	clockStore  store.ClockStore
	keyManager  keys.KeyManager
	pubSub      p2p.PubSub
	execEngines map[string]execution.ExecutionEngine
	engine      consensus.ConsensusEngine
}

func newNode(
	logger *zap.Logger,
	clockStore store.ClockStore,
	keyManager keys.KeyManager,
	pubSub p2p.PubSub,
	ceremonyExecutionEngine *ceremony.CeremonyExecutionEngine,
	engine consensus.ConsensusEngine,
) (*Node, error) {
	if engine == nil {
		return nil, errors.New("engine must not be nil")
	}

	execEngines := make(map[string]execution.ExecutionEngine)
	if ceremonyExecutionEngine != nil {
		execEngines[ceremonyExecutionEngine.GetName()] = ceremonyExecutionEngine
	}

	return &Node{
		logger,
		clockStore,
		keyManager,
		pubSub,
		execEngines,
		engine,
	}, nil
}

func (n *Node) Start() {
	err := <-n.engine.Start()
	if err != nil {
		panic(err)
	}

	// TODO: add config mapping to engine name/frame registration
	for _, e := range n.execEngines {
		n.engine.RegisterExecutor(e, 0)
	}
}

func (n *Node) Stop() {
	err := <-n.engine.Stop(false)
	if err != nil {
		panic(err)
	}
}

func (n *Node) GetLogger() *zap.Logger {
	return n.logger
}

func (n *Node) GetClockStore() store.ClockStore {
	return n.clockStore
}

func (n *Node) GetKeyManager() keys.KeyManager {
	return n.keyManager
}

func (n *Node) GetPubSub() p2p.PubSub {
	return n.pubSub
}

func (n *Node) GetExecutionEngines() []execution.ExecutionEngine {
	list := []execution.ExecutionEngine{}
	for _, e := range n.execEngines {
		list = append(list, e)
	}
	return list
}
