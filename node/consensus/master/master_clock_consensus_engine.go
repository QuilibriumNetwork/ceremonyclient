package master

import (
	"bytes"
	"context"
	gcrypto "crypto"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"sync"
	"time"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/mr-tron/base58"
	"github.com/multiformats/go-multiaddr"
	mn "github.com/multiformats/go-multiaddr/net"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
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

	frameChan                   chan *protobufs.ClockFrame
	executionEngines            map[string]execution.ExecutionEngine
	filter                      []byte
	input                       []byte
	syncingStatus               SyncStatusType
	syncingTarget               []byte
	engineMx                    sync.Mutex
	seenFramesMx                sync.Mutex
	historicFramesMx            sync.Mutex
	seenFrames                  []*protobufs.ClockFrame
	historicFrames              []*protobufs.ClockFrame
	clockStore                  store.ClockStore
	masterTimeReel              *qtime.MasterTimeReel
	peerInfoManager             p2p.PeerInfoManager
	report                      *protobufs.SelfTestReport
	frameValidationCh           chan *protobufs.ClockFrame
	bandwidthTestCh             chan []byte
	verifyTestCh                chan verifyChallenge
	currentReceivingSyncPeers   int
	currentReceivingSyncPeersMx sync.Mutex
	engineConfig                *config.EngineConfig
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
	peerInfoManager p2p.PeerInfoManager,
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
		peerInfoManager:     peerInfoManager,
		report:              report,
		frameValidationCh:   make(chan *protobufs.ClockFrame),
		bandwidthTestCh:     make(chan []byte),
		verifyTestCh:        make(chan verifyChallenge),
		engineConfig:        engineConfig,
	}

	e.addPeerManifestReport(e.pubSub.GetPeerID(), report)

	if e.filter, err = hex.DecodeString(engineConfig.Filter); err != nil {
		panic(errors.Wrap(err, "could not parse filter value"))
	}

	e.getProvingKey(engineConfig)

	if err := e.createCommunicationKeys(); err != nil {
		panic(err)
	}

	logger.Info("constructing consensus engine")

	return e
}

func (e *MasterClockConsensusEngine) Start() <-chan error {
	e.logger.Info("starting master consensus engine")
	e.state = consensus.EngineStateStarting
	errChan := make(chan error)

	e.peerInfoManager.Start()

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

	go func() {
		for {
			select {
			case newFrame := <-e.frameValidationCh:
				head, err := e.masterTimeReel.Head()
				if err != nil {
					panic(err)
				}

				if head.FrameNumber > newFrame.FrameNumber ||
					newFrame.FrameNumber-head.FrameNumber > 128 {
					e.logger.Debug(
						"frame out of range, ignoring",
						zap.Uint64("number", newFrame.FrameNumber),
					)
					continue
				}

				if err := e.frameProver.VerifyMasterClockFrame(newFrame); err != nil {
					e.logger.Error("could not verify clock frame", zap.Error(err))
					continue
				}

				e.masterTimeReel.Insert(newFrame, false)
			case peerId := <-e.bandwidthTestCh:
				e.performBandwidthTest(peerId)
			case verifyTest := <-e.verifyTestCh:
				e.performVerifyTest(verifyTest)
			}
		}
	}()

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
		// Let it sit until we at least have a few more peers inbound
		time.Sleep(30 * time.Second)
		difficultyMetric := int64(100000)
		skew := (difficultyMetric * 12) / 10
		parallelism := e.report.Cores - 1

		if parallelism < 3 {
			panic("invalid system configuration, minimum system configuration must be four cores")
		}

		clients, err := e.createParallelDataClients(int(parallelism))
		if err != nil {
			panic(err)
		}

		for {
			head, err := e.masterTimeReel.Head()
			if err != nil {
				panic(err)
			}

			e.report.MasterHeadFrame = head.FrameNumber
			e.report.DifficultyMetric = difficultyMetric

			challenge := binary.BigEndian.AppendUint64(
				[]byte{},
				e.report.MasterHeadFrame,
			)
			challenge = append(challenge, e.pubSub.GetPeerID()...)

			proofs := make([][]byte, parallelism)
			nextMetrics := make([]int64, parallelism)

			wg := sync.WaitGroup{}
			wg.Add(int(parallelism))

			ts := time.Now().UnixMilli()
			for i := uint32(0); i < parallelism; i++ {
				i := i
				go func() {
					resp, err :=
						clients[i].CalculateChallengeProof(
							context.Background(),
							&protobufs.ChallengeProofRequest{
								Challenge: challenge,
								Core:      i,
								Skew:      skew,
								NowMs:     ts,
							},
						)
					if err != nil {
						panic(err)
					}

					proofs[i], nextMetrics[i] = resp.Output, resp.NextSkew
					wg.Done()
				}()
			}
			wg.Wait()
			nextDifficultySum := uint64(0)
			for i := 0; i < int(parallelism); i++ {
				nextDifficultySum += uint64(nextMetrics[i])
			}

			nextDifficultyMetric := int64(nextDifficultySum / uint64(parallelism))

			e.logger.Info(
				"recalibrating difficulty metric",
				zap.Int64("previous_difficulty_metric", difficultyMetric),
				zap.Int64("next_difficulty_metric", nextDifficultyMetric),
			)
			difficultyMetric = nextDifficultyMetric
			skew = (nextDifficultyMetric * 12) / 10

			proof := binary.BigEndian.AppendUint64([]byte{}, uint64(ts))
			for i := 0; i < len(proofs); i++ {
				proof = append(proof, proofs[i]...)
			}
			e.report.Proof = proof
			e.logger.Info(
				"broadcasting self-test info",
				zap.Uint64("current_frame", e.report.MasterHeadFrame),
			)

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

func (e *MasterClockConsensusEngine) createParallelDataClients(
	paralellism int,
) ([]protobufs.DataIPCServiceClient, error) {
	e.logger.Info(
		"connecting to data worker processes",
		zap.Int("parallelism", paralellism),
	)

	if e.engineConfig.DataWorkerBaseListenMultiaddr == "" {
		e.engineConfig.DataWorkerBaseListenMultiaddr = "/ip4/127.0.0.1/tcp/%d"
	}

	if e.engineConfig.DataWorkerBaseListenPort == 0 {
		e.engineConfig.DataWorkerBaseListenPort = 40000
	}

	clients := make([]protobufs.DataIPCServiceClient, paralellism)

	for i := 0; i < paralellism; i++ {
		ma, err := multiaddr.NewMultiaddr(
			fmt.Sprintf(
				e.engineConfig.DataWorkerBaseListenMultiaddr,
				int(e.engineConfig.DataWorkerBaseListenPort)+i,
			),
		)
		if err != nil {
			panic(err)
		}

		_, addr, err := mn.DialArgs(ma)
		if err != nil {
			panic(err)
		}

		conn, err := grpc.Dial(
			addr,
			grpc.WithTransportCredentials(
				insecure.NewCredentials(),
			),
			grpc.WithDefaultCallOptions(
				grpc.MaxCallSendMsgSize(10*1024*1024),
				grpc.MaxCallRecvMsgSize(10*1024*1024),
			),
		)
		if err != nil {
			panic(err)
		}

		clients[i] = protobufs.NewDataIPCServiceClient(conn)
	}

	e.logger.Info(
		"connected to data worker processes",
		zap.Int("parallelism", paralellism),
	)
	return clients, nil
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
	e.peerInfoManager.Stop()

	e.state = consensus.EngineStateStopped
	go func() {
		errChan <- nil
	}()
	return errChan
}

type verifyChallenge struct {
	peerID           []byte
	challenge        []byte
	timestamp        int64
	difficultyMetric int64
	proofs           [][]byte
}

func (e *MasterClockConsensusEngine) performVerifyTest(
	challenge verifyChallenge,
) {
	if !e.frameProver.VerifyChallengeProof(
		challenge.challenge,
		challenge.timestamp,
		challenge.difficultyMetric,
		challenge.proofs,
	) {
		e.logger.Warn(
			"received invalid proof from peer",
			zap.String("peer_id", peer.ID(challenge.peerID).String()),
		)
		e.pubSub.SetPeerScore(challenge.peerID, -1000)
	} else {
		e.logger.Debug(
			"received valid proof from peer",
			zap.String("peer_id", peer.ID(challenge.peerID).String()),
		)
		info := e.peerInfoManager.GetPeerInfo(challenge.peerID)
		info.LastSeen = time.Now().UnixMilli()
	}
}

func (e *MasterClockConsensusEngine) performBandwidthTest(peerID []byte) {
	result := e.pubSub.GetMultiaddrOfPeer(peerID)
	if result == "" {
		return
	}

	cc, err := e.pubSub.GetDirectChannel(peerID, "validation")
	if err != nil {
		e.logger.Debug(
			"could not connect to peer for validation",
			zap.String("peer_id", base58.Encode(peerID)),
		)

		// tag: dusk – nuke this peer for now
		e.pubSub.SetPeerScore(peerID, -1000)
		return
	}

	client := protobufs.NewValidationServiceClient(cc)
	verification := make([]byte, 1048576)
	rand.Read(verification)
	start := time.Now().UnixMilli()
	validation, err := client.PerformValidation(
		context.Background(),
		&protobufs.ValidationMessage{
			Validation: verification,
		},
	)
	end := time.Now().UnixMilli()
	if err != nil && err != io.EOF {
		cc.Close()
		e.logger.Debug(
			"peer returned error",
			zap.String("peer_id", base58.Encode(peerID)),
			zap.Error(err),
		)
		// tag: dusk – nuke this peer for now
		e.pubSub.SetPeerScore(peerID, -1000)
		return
	}
	cc.Close()

	if !bytes.Equal(verification, validation.Validation) {
		e.logger.Debug(
			"peer provided invalid verification",
			zap.String("peer_id", base58.Encode(peerID)),
		)
		// tag: dusk – nuke this peer for now
		e.pubSub.SetPeerScore(peerID, -1000)
		return
	}

	if end-start > 2000 {
		e.logger.Debug(
			"peer has slow bandwidth, scoring out",
			zap.String("peer_id", base58.Encode(peerID)),
		)
		// tag: dusk – nuke this peer for now
		e.pubSub.SetPeerScore(peerID, -1000)
		return
	}

	duration := end - start
	bandwidth := uint64(1048576*1000) / uint64(duration)
	manifest := e.peerInfoManager.GetPeerInfo(peerID)
	if manifest == nil {
		return
	}

	peerManifest := &p2p.PeerManifest{
		PeerId:             peerID,
		Difficulty:         manifest.Difficulty,
		DifficultyMetric:   manifest.DifficultyMetric,
		Commit_16Metric:    manifest.Commit_16Metric,
		Commit_128Metric:   manifest.Commit_128Metric,
		Commit_1024Metric:  manifest.Commit_1024Metric,
		Commit_65536Metric: manifest.Commit_65536Metric,
		Proof_16Metric:     manifest.Proof_16Metric,
		Proof_128Metric:    manifest.Proof_128Metric,
		Proof_1024Metric:   manifest.Proof_1024Metric,
		Proof_65536Metric:  manifest.Proof_65536Metric,
		Cores:              manifest.Cores,
		Memory:             manifest.Memory,
		Storage:            manifest.Storage,
		Capabilities:       []p2p.Capability{},
		MasterHeadFrame:    manifest.MasterHeadFrame,
		Bandwidth:          bandwidth,
	}

	for _, capability := range manifest.Capabilities {
		metadata := make([]byte, len(capability.AdditionalMetadata))
		copy(metadata[:], capability.AdditionalMetadata[:])
		peerManifest.Capabilities = append(
			peerManifest.Capabilities,
			p2p.Capability{
				ProtocolIdentifier: capability.ProtocolIdentifier,
				AdditionalMetadata: metadata,
			},
		)
	}

	e.peerInfoManager.AddPeerInfo(manifest)
}

func (
	e *MasterClockConsensusEngine,
) GetPeerManifests() *protobufs.PeerManifestsResponse {
	response := &protobufs.PeerManifestsResponse{
		PeerManifests: []*protobufs.PeerManifest{},
	}
	peerMap := e.peerInfoManager.GetPeerMap()
	for peerId, peerManifest := range peerMap {
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
			LastSeen:           peerManifest.LastSeen,
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

func (e *MasterClockConsensusEngine) addPeerManifestReport(
	peerId []byte,
	report *protobufs.SelfTestReport,
) {
	manifest := &p2p.PeerManifest{
		PeerId:             peerId,
		Difficulty:         report.Difficulty,
		DifficultyMetric:   report.DifficultyMetric,
		Commit_16Metric:    report.Commit_16Metric,
		Commit_128Metric:   report.Commit_128Metric,
		Commit_1024Metric:  report.Commit_1024Metric,
		Commit_65536Metric: report.Commit_65536Metric,
		Proof_16Metric:     report.Proof_16Metric,
		Proof_128Metric:    report.Proof_128Metric,
		Proof_1024Metric:   report.Proof_1024Metric,
		Proof_65536Metric:  report.Proof_65536Metric,
		Cores:              report.Cores,
		Memory:             report.Memory,
		Storage:            report.Storage,
		Capabilities:       []p2p.Capability{},
		MasterHeadFrame:    report.MasterHeadFrame,
		LastSeen:           time.Now().UnixMilli(),
	}

	for _, capability := range manifest.Capabilities {
		metadata := make([]byte, len(capability.AdditionalMetadata))
		copy(metadata[:], capability.AdditionalMetadata[:])
		manifest.Capabilities = append(
			manifest.Capabilities,
			p2p.Capability{
				ProtocolIdentifier: capability.ProtocolIdentifier,
				AdditionalMetadata: metadata,
			},
		)
	}

	e.peerInfoManager.AddPeerInfo(manifest)
}

func (e *MasterClockConsensusEngine) getProvingKey(
	engineConfig *config.EngineConfig,
) (gcrypto.Signer, keys.KeyType, []byte, []byte) {
	provingKey, err := e.keyManager.GetSigningKey(engineConfig.ProvingKeyId)
	if errors.Is(err, keys.KeyNotFoundErr) {
		e.logger.Info("could not get proving key, generating")
		provingKey, err = e.keyManager.CreateSigningKey(
			engineConfig.ProvingKeyId,
			keys.KeyTypeEd448,
		)
	}

	if err != nil {
		e.logger.Error("could not get proving key", zap.Error(err))
		panic(err)
	}

	rawKey, err := e.keyManager.GetRawKey(engineConfig.ProvingKeyId)
	if err != nil {
		e.logger.Error("could not get proving key type", zap.Error(err))
		panic(err)
	}

	provingKeyType := rawKey.Type

	h, err := poseidon.HashBytes(rawKey.PublicKey)
	if err != nil {
		e.logger.Error("could not hash proving key", zap.Error(err))
		panic(err)
	}

	provingKeyAddress := h.Bytes()
	provingKeyAddress = append(
		make([]byte, 32-len(provingKeyAddress)),
		provingKeyAddress...,
	)

	return provingKey, provingKeyType, rawKey.PublicKey, provingKeyAddress
}

func (e *MasterClockConsensusEngine) createCommunicationKeys() error {
	_, err := e.keyManager.GetAgreementKey("q-ratchet-idk")
	if err != nil {
		if errors.Is(err, keys.KeyNotFoundErr) {
			_, err = e.keyManager.CreateAgreementKey(
				"q-ratchet-idk",
				keys.KeyTypeX448,
			)
			if err != nil {
				return errors.Wrap(err, "create communication keys")
			}
		} else {
			return errors.Wrap(err, "create communication keys")
		}
	}

	_, err = e.keyManager.GetAgreementKey("q-ratchet-spk")
	if err != nil {
		if errors.Is(err, keys.KeyNotFoundErr) {
			_, err = e.keyManager.CreateAgreementKey(
				"q-ratchet-spk",
				keys.KeyTypeX448,
			)
			if err != nil {
				return errors.Wrap(err, "create communication keys")
			}
		} else {
			return errors.Wrap(err, "create communication keys")
		}
	}

	return nil
}
