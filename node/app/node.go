package app

import (
	"errors"
	"fmt"

	"go.uber.org/zap"
	"golang.org/x/crypto/sha3"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus/master"
	"source.quilibrium.com/quilibrium/monorepo/node/crypto"
	"source.quilibrium.com/quilibrium/monorepo/node/execution"
	"source.quilibrium.com/quilibrium/monorepo/node/keys"
	"source.quilibrium.com/quilibrium/monorepo/node/p2p"
	"source.quilibrium.com/quilibrium/monorepo/node/store"
)

type Node struct {
	logger         *zap.Logger
	dataProofStore store.DataProofStore
	clockStore     store.ClockStore
	keyManager     keys.KeyManager
	pubSub         p2p.PubSub
	execEngines    map[string]execution.ExecutionEngine
	engine         consensus.ConsensusEngine
}

type DHTNode struct {
	pubSub p2p.PubSub
	quit   chan struct{}
}

func newDHTNode(
	pubSub p2p.PubSub,
) (*DHTNode, error) {
	return &DHTNode{
		pubSub: pubSub,
		quit:   make(chan struct{}),
	}, nil
}

func newNode(
	logger *zap.Logger,
	dataProofStore store.DataProofStore,
	clockStore store.ClockStore,
	keyManager keys.KeyManager,
	pubSub p2p.PubSub,
	// execution engines wire in here
	engine consensus.ConsensusEngine,
) (*Node, error) {
	if engine == nil {
		return nil, errors.New("engine must not be nil")
	}

	execEngines := make(map[string]execution.ExecutionEngine)

	return &Node{
		logger,
		dataProofStore,
		clockStore,
		keyManager,
		pubSub,
		execEngines,
		engine,
	}, nil
}

func (n *Node) VerifyProofIntegrity() {
	i, _, _, e := n.dataProofStore.GetLatestDataTimeProof(n.pubSub.GetPeerID())
	if e != nil {
		panic(e)
	}
	dataProver := crypto.NewKZGInclusionProver(n.logger)
	wesoProver := crypto.NewWesolowskiFrameProver(n.logger)

	for j := int(i); j >= 0; j-- {
		fmt.Println(j)
		_, _, input, o, err := n.dataProofStore.GetDataTimeProof(n.pubSub.GetPeerID(), uint32(j))
		if err != nil {
			panic(err)
		}
		idx, idxProof, idxCommit, idxKP := master.GetOutputs(o)

		ip := sha3.Sum512(idxProof)

		v, err := dataProver.VerifyRaw(ip[:], idxCommit, int(idx), idxKP, 128)
		if err != nil {
			panic(err)
		}

		if !v {
			panic("bad kzg proof")
		}
		wp := []byte{}
		wp = append(wp, n.pubSub.GetPeerID()...)
		wp = append(wp, input...)
		fmt.Printf("%x\n", wp)
		v = wesoProver.VerifyChallengeProof(wp, uint32(j), idx, idxProof)
		if !v {
			panic("bad weso proof")
		}
	}
}

func (n *Node) RunRepair() {
	// intrinsicFilter := append(
	// 	p2p.GetBloomFilter(application.CEREMONY_ADDRESS, 256, 3),
	// 	p2p.GetBloomFilterIndices(application.CEREMONY_ADDRESS, 65536, 24)...,
	// )
	// n.logger.Info("check store and repair if needed, this may take a few minutes")
	// proverTrie := &tries.RollingFrecencyCritbitTrie{}
	// head, err := n.clockStore.GetLatestDataClockFrame(intrinsicFilter, proverTrie)
	// if err == nil && head != nil {
	// 	for head != nil && head.FrameNumber != 0 {
	// 		prev := head
	// 		head, err = n.clockStore.GetStagedDataClockFrame(
	// 			intrinsicFilter,
	// 			head.FrameNumber-1,
	// 			head.ParentSelector,
	// 			true,
	// 		)
	// 		if err != nil {
	// 			panic(err)
	// 		}
	// 		compare, _, err := n.clockStore.GetDataClockFrame(
	// 			intrinsicFilter,
	// 			prev.FrameNumber-1,
	// 			true,
	// 		)
	// 		if err != nil {
	// 			panic(err)
	// 		}
	// 		if !bytes.Equal(head.Output, compare.Output) {
	// 			n.logger.Warn(
	// 				"repairing frame",
	// 				zap.Uint64("frame_number", head.FrameNumber),
	// 			)
	// 			head, err = n.clockStore.GetStagedDataClockFrame(
	// 				intrinsicFilter,
	// 				prev.FrameNumber-1,
	// 				prev.ParentSelector,
	// 				true,
	// 			)
	// 			if err != nil {
	// 				panic(err)
	// 			}

	// 			txn, err := n.clockStore.NewTransaction()
	// 			if err != nil {
	// 				panic(err)
	// 			}

	// 			selector, err := head.GetSelector()
	// 			if err != nil {
	// 				panic(err)
	// 			}

	// 			err = n.clockStore.CommitDataClockFrame(
	// 				intrinsicFilter,
	// 				head.FrameNumber,
	// 				selector.FillBytes(make([]byte, 32)),
	// 				proverTrie,
	// 				txn,
	// 				true,
	// 			)
	// 			if err != nil {
	// 				panic(err)
	// 			}

	// 			if err = txn.Commit(); err != nil {
	// 				panic(err)
	// 			}
	// 		}
	// 	}
	// }
	// n.logger.Info("check complete")
}

func (d *DHTNode) Start() {
	<-d.quit
}

func (d *DHTNode) Stop() {
	go func() {
		d.quit <- struct{}{}
	}()
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

func (n *Node) GetDataProofStore() store.DataProofStore {
	return n.dataProofStore
}

func (n *Node) GetKeyManager() keys.KeyManager {
	return n.keyManager
}

func (n *Node) GetPubSub() p2p.PubSub {
	return n.pubSub
}

func (n *Node) GetMasterClock() *master.MasterClockConsensusEngine {
	return n.engine.(*master.MasterClockConsensusEngine)
}

func (n *Node) GetExecutionEngines() []execution.ExecutionEngine {
	list := []execution.ExecutionEngine{}
	for _, e := range n.execEngines {
		list = append(list, e)
	}
	return list
}
