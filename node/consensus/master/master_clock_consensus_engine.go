package master

import (
	"encoding/hex"
	"sync"
	"time"

	"github.com/pkg/errors"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/node/config"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus"
	"source.quilibrium.com/quilibrium/monorepo/node/execution"
	"source.quilibrium.com/quilibrium/monorepo/node/keys"
	"source.quilibrium.com/quilibrium/monorepo/node/p2p"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/node/store"
)

type SyncStatusType int

const (
	SyncStatusNotSyncing = iota
	SyncStatusAwaitingResponse
	SyncStatusSynchronizing
)

type MasterClockConsensusEngine struct {
	frame               uint64
	difficulty          uint32
	logger              *zap.Logger
	state               consensus.EngineState
	pubSub              p2p.PubSub
	keyManager          keys.KeyManager
	lastFrameReceivedAt time.Time
	latestFrame         *protobufs.ClockFrame

	frameChan        chan uint64
	executionEngines map[string]execution.ExecutionEngine
	filter           []byte
	input            []byte
	syncingStatus    SyncStatusType
	syncingTarget    []byte
	engineMx         sync.Mutex
	seenFramesMx     sync.Mutex
	historicFramesMx sync.Mutex
	seenFrames       []*protobufs.ClockFrame
	historicFrames   []*protobufs.ClockFrame
	clockStore       store.ClockStore
}

var _ consensus.ConsensusEngine = (*MasterClockConsensusEngine)(nil)

func NewMasterClockConsensusEngine(
	engineConfig *config.EngineConfig,
	logger *zap.Logger,
	clockStore store.ClockStore,
	keyManager keys.KeyManager,
	pubSub p2p.PubSub,
) *MasterClockConsensusEngine {
	if logger == nil {
		panic(errors.New("logger is nil"))
	}

	if engineConfig == nil {
		panic(errors.New("engine config is nil"))
	}

	if keyManager == nil {
		panic(errors.New("key manager is nil"))
	}

	if pubSub == nil {
		panic(errors.New("pubsub is nil"))
	}

	seed, err := hex.DecodeString(engineConfig.GenesisSeed)
	if err != nil {
		panic(errors.New("genesis seed is nil"))
	}

	e := &MasterClockConsensusEngine{
		frame:               0,
		difficulty:          10000,
		logger:              logger,
		state:               consensus.EngineStateStopped,
		keyManager:          keyManager,
		pubSub:              pubSub,
		frameChan:           make(chan uint64),
		executionEngines:    map[string]execution.ExecutionEngine{},
		input:               seed,
		lastFrameReceivedAt: time.Time{},
		syncingStatus:       SyncStatusNotSyncing,
		clockStore:          clockStore,
	}

	if e.filter, err = hex.DecodeString(engineConfig.Filter); err != nil {
		panic(errors.Wrap(err, "could not parse filter value"))
	}

	logger.Info("constructing consensus engine")

	return e
}

func (e *MasterClockConsensusEngine) Start() <-chan error {
	e.logger.Info("starting consensus engine")
	e.state = consensus.EngineStateStarting
	errChan := make(chan error)

	e.state = consensus.EngineStateLoading
	e.logger.Info("syncing last seen state")

	latestFrame, err := e.clockStore.GetLatestMasterClockFrame(e.filter)
	if err != nil && errors.Is(err, store.ErrNotFound) {
		latestFrame = e.createGenesisFrame()
		txn, err := e.clockStore.NewTransaction()
		if err != nil {
			panic(err)
		}

		if err = e.clockStore.PutMasterClockFrame(latestFrame, txn); err != nil {
			panic(err)
		}

		if err = txn.Commit(); err != nil {
			panic(err)
		}
	} else if err != nil {
		panic(err)
	} else {
		e.setFrame(latestFrame)
	}

	e.historicFrames = []*protobufs.ClockFrame{}

	if latestFrame.FrameNumber != 0 {
		min := uint64(0)
		if latestFrame.FrameNumber-255 > min {
			min = latestFrame.FrameNumber - 255
		}

		iter, err := e.clockStore.RangeMasterClockFrames(
			e.filter,
			min,
			latestFrame.FrameNumber-1,
		)
		if err != nil {
			panic(err)
		}

		for iter.First(); iter.Valid(); iter.Next() {
			frame, err := iter.Value()
			if err != nil {
				panic(err)
			}

			e.historicFrames = append(e.historicFrames, frame)
		}

		if err = iter.Close(); err != nil {
			panic(err)
		}
	}

	e.historicFrames = append(e.historicFrames, latestFrame)

	e.logger.Info("subscribing to pubsub messages")
	e.pubSub.Subscribe(e.filter, e.handleMessage, true)
	e.pubSub.Subscribe(e.pubSub.GetPeerID(), e.handleSync, true)

	e.state = consensus.EngineStateCollecting

	go func() {
		for {
			e.logger.Info(
				"peers in store",
				zap.Int("peer_store_count", e.pubSub.GetPeerstoreCount()),
				zap.Int("network_peer_count", e.pubSub.GetNetworkPeersCount()),
			)
			e.logger.Info(
				"peers by bitmask",
				zap.Any("peers", e.pubSub.GetBitmaskPeers()),
			)
			time.Sleep(10 * time.Second)
		}
	}()

	go func() {
		for e.state < consensus.EngineStateStopping {
			var err error
			switch e.state {
			case consensus.EngineStateCollecting:
				if latestFrame, err = e.collect(latestFrame); err != nil {
					e.logger.Error("could not collect", zap.Error(err))
					errChan <- err
				}
			case consensus.EngineStateProving:
				if latestFrame, err = e.prove(latestFrame); err != nil {
					e.logger.Error("could not prove", zap.Error(err))
					errChan <- err
				}
			case consensus.EngineStatePublishing:
				if err = e.publishProof(latestFrame); err != nil {
					e.logger.Error("could not publish", zap.Error(err))
					errChan <- err
				}
			}
		}
	}()

	go func() {
		errChan <- nil
	}()

	return errChan
}

func (e *MasterClockConsensusEngine) Stop(force bool) <-chan error {
	e.logger.Info("stopping consensus engine")
	e.state = consensus.EngineStateStopping
	errChan := make(chan error)

	wg := sync.WaitGroup{}
	wg.Add(len(e.executionEngines))
	for name := range e.executionEngines {
		name := name
		go func(name string) {
			err := <-e.UnregisterExecutor(name, e.frame, force)
			if err != nil {
				errChan <- err
			}
			wg.Done()
		}(name)
	}

	e.logger.Info("waiting for execution engines to stop")
	wg.Wait()
	e.logger.Info("execution engines stopped")

	e.state = consensus.EngineStateStopped

	e.engineMx.Lock()
	defer e.engineMx.Unlock()
	go func() {
		errChan <- nil
	}()
	return errChan
}

func (e *MasterClockConsensusEngine) GetDifficulty() uint32 {
	return e.difficulty
}

func (e *MasterClockConsensusEngine) GetFrame() uint64 {
	return e.frame
}

func (e *MasterClockConsensusEngine) GetState() consensus.EngineState {
	return e.state
}

func (e *MasterClockConsensusEngine) GetFrameChannel() <-chan uint64 {
	return e.frameChan
}
