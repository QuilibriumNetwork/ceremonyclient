package master

import (
	"context"
	"encoding/hex"
	"math/big"
	"sync"
	"time"

	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"source.quilibrium.com/quilibrium/monorepo/node/config"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus"
	qtime "source.quilibrium.com/quilibrium/monorepo/node/consensus/time"
	"source.quilibrium.com/quilibrium/monorepo/node/crypto"
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
	*protobufs.UnimplementedValidationServiceServer

	difficulty          uint32
	logger              *zap.Logger
	state               consensus.EngineState
	pubSub              p2p.PubSub
	keyManager          keys.KeyManager
	frameProver         crypto.FrameProver
	lastFrameReceivedAt time.Time

	frameChan        chan *protobufs.ClockFrame
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
	masterTimeReel   *qtime.MasterTimeReel
	report           *protobufs.SelfTestReport
	peerMapMx        sync.Mutex
	peerMap          map[string]*protobufs.SelfTestReport
}

var _ consensus.ConsensusEngine = (*MasterClockConsensusEngine)(nil)

func NewMasterClockConsensusEngine(
	engineConfig *config.EngineConfig,
	logger *zap.Logger,
	clockStore store.ClockStore,
	keyManager keys.KeyManager,
	pubSub p2p.PubSub,
	frameProver crypto.FrameProver,
	masterTimeReel *qtime.MasterTimeReel,
	report *protobufs.SelfTestReport,
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

	if frameProver == nil {
		panic(errors.New("frame prover is nil"))
	}

	if masterTimeReel == nil {
		panic(errors.New("master time reel is nil"))
	}

	seed, err := hex.DecodeString(engineConfig.GenesisSeed)
	if err != nil {
		panic(errors.New("genesis seed is nil"))
	}

	e := &MasterClockConsensusEngine{
		difficulty:          10000,
		logger:              logger,
		state:               consensus.EngineStateStopped,
		keyManager:          keyManager,
		pubSub:              pubSub,
		executionEngines:    map[string]execution.ExecutionEngine{},
		frameChan:           make(chan *protobufs.ClockFrame),
		input:               seed,
		lastFrameReceivedAt: time.Time{},
		syncingStatus:       SyncStatusNotSyncing,
		clockStore:          clockStore,
		frameProver:         frameProver,
		masterTimeReel:      masterTimeReel,
		report:              report,
		peerMap:             map[string]*protobufs.SelfTestReport{},
	}

	e.peerMap[string(e.pubSub.GetPeerID())] = report

	if e.filter, err = hex.DecodeString(engineConfig.Filter); err != nil {
		panic(errors.Wrap(err, "could not parse filter value"))
	}

	logger.Info("constructing consensus engine")

	return e
}

func (e *MasterClockConsensusEngine) Start() <-chan error {
	e.logger.Info("starting master consensus engine")
	e.state = consensus.EngineStateStarting
	errChan := make(chan error)

	e.state = consensus.EngineStateLoading
	e.logger.Info("syncing last seen state")

	err := e.masterTimeReel.Start()
	if err != nil {
		panic(err)
	}

	frame, err := e.masterTimeReel.Head()
	if err != nil {
		panic(err)
	}

	e.buildHistoricFrameCache(frame)

	e.logger.Info("subscribing to pubsub messages")
	e.pubSub.Subscribe(e.filter, e.handleMessage, true)

	e.state = consensus.EngineStateCollecting

	go func() {
		server := grpc.NewServer(
			grpc.MaxSendMsgSize(600*1024*1024),
			grpc.MaxRecvMsgSize(600*1024*1024),
		)
		protobufs.RegisterValidationServiceServer(server, e)

		if err := e.pubSub.StartDirectChannelListener(
			e.pubSub.GetPeerID(),
			"validation",
			server,
		); err != nil {
			panic(err)
		}
	}()

	go func() {
		for {
			e.logger.Info(
				"peers in store",
				zap.Int("peer_store_count", e.pubSub.GetPeerstoreCount()),
				zap.Int("network_peer_count", e.pubSub.GetNetworkPeersCount()),
			)
			time.Sleep(10 * time.Second)
		}
	}()

	go func() {
		for {
			time.Sleep(30 * time.Second)

			e.logger.Info("broadcasting self-test info")
			head, err := e.masterTimeReel.Head()
			if err != nil {
				panic(err)
			}

			e.report.MasterHeadFrame = head.FrameNumber

			if err := e.publishMessage(e.filter, e.report); err != nil {
				e.logger.Debug("error publishing message", zap.Error(err))
			}
		}
	}()

	go func() {
		newFrameCh := e.masterTimeReel.NewFrameCh()

		for e.state < consensus.EngineStateStopping {
			var err error
			select {
			case frame := <-newFrameCh:
				currentFrame := frame
				latestFrame := frame
				if latestFrame, err = e.collect(currentFrame); err != nil {
					e.logger.Error("could not collect", zap.Error(err))
					latestFrame = currentFrame
					continue
				}
				if latestFrame, err = e.prove(latestFrame); err != nil {
					e.logger.Error("could not prove", zap.Error(err))
					latestFrame = currentFrame
				}
				if err = e.publishProof(latestFrame); err != nil {
					e.logger.Error("could not publish", zap.Error(err))
				}
			case <-time.After(20 * time.Second):
				frame, err := e.masterTimeReel.Head()
				if err != nil {
					panic(err)
				}

				if frame, err = e.prove(frame); err != nil {
					e.logger.Error("could not prove", zap.Error(err))
					continue
				}
				if err = e.publishProof(frame); err != nil {
					e.logger.Error("could not publish", zap.Error(err))
				}
			}
		}
	}()

	go func() {
		errChan <- nil
	}()

	return errChan
}

func (e *MasterClockConsensusEngine) PerformValidation(
	ctx context.Context,
	msg *protobufs.ValidationMessage,
) (*protobufs.ValidationMessage, error) {
	return msg, nil
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
			frame, err := e.masterTimeReel.Head()
			if err != nil {
				errChan <- err
				return
			}

			err = <-e.UnregisterExecutor(name, frame.FrameNumber, force)
			if err != nil {
				errChan <- err
			}
			wg.Done()
		}(name)
	}

	e.logger.Info("waiting for execution engines to stop")
	wg.Wait()
	e.logger.Info("execution engines stopped")
	e.masterTimeReel.Stop()

	e.state = consensus.EngineStateStopped
	go func() {
		errChan <- nil
	}()
	return errChan
}

func (
	e *MasterClockConsensusEngine,
) GetPeerManifests() *protobufs.PeerManifestsResponse {
	response := &protobufs.PeerManifestsResponse{
		PeerManifests: []*protobufs.PeerManifest{},
	}
	e.peerMapMx.Lock()
	for peerId, peerManifest := range e.peerMap {
		peerId := peerId
		peerManifest := peerManifest
		manifest := &protobufs.PeerManifest{
			PeerId:             []byte(peerId),
			Difficulty:         peerManifest.Difficulty,
			DifficultyMetric:   peerManifest.DifficultyMetric,
			Commit_16Metric:    peerManifest.Commit_16Metric,
			Commit_128Metric:   peerManifest.Commit_128Metric,
			Commit_1024Metric:  peerManifest.Commit_1024Metric,
			Commit_65536Metric: peerManifest.Commit_65536Metric,
			Proof_16Metric:     peerManifest.Proof_16Metric,
			Proof_128Metric:    peerManifest.Proof_128Metric,
			Proof_1024Metric:   peerManifest.Proof_1024Metric,
			Proof_65536Metric:  peerManifest.Proof_65536Metric,
			Cores:              peerManifest.Cores,
			Memory:             new(big.Int).SetBytes(peerManifest.Memory).Bytes(),
			Storage:            new(big.Int).SetBytes(peerManifest.Storage).Bytes(),
			MasterHeadFrame:    peerManifest.MasterHeadFrame,
		}

		for _, capability := range peerManifest.Capabilities {
			metadata := make([]byte, len(capability.AdditionalMetadata))
			copy(metadata[:], capability.AdditionalMetadata[:])
			manifest.Capabilities = append(
				manifest.Capabilities,
				&protobufs.Capability{
					ProtocolIdentifier: capability.ProtocolIdentifier,
					AdditionalMetadata: metadata,
				},
			)
		}

		response.PeerManifests = append(
			response.PeerManifests,
			manifest,
		)
	}
	e.peerMapMx.Unlock()
	return response
}

func (e *MasterClockConsensusEngine) GetDifficulty() uint32 {
	return e.difficulty
}

func (e *MasterClockConsensusEngine) GetFrame() *protobufs.ClockFrame {
	frame, err := e.masterTimeReel.Head()
	if err != nil {
		panic(err)
	}

	return frame
}

func (e *MasterClockConsensusEngine) GetState() consensus.EngineState {
	return e.state
}

func (
	e *MasterClockConsensusEngine,
) GetFrameChannel() <-chan *protobufs.ClockFrame {
	return e.frameChan
}

func (e *MasterClockConsensusEngine) buildHistoricFrameCache(
	latestFrame *protobufs.ClockFrame,
) {
	e.historicFrames = []*protobufs.ClockFrame{}

	if latestFrame.FrameNumber != 0 {
		min := uint64(0)
		if latestFrame.FrameNumber-255 > min && latestFrame.FrameNumber > 255 {
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
}
