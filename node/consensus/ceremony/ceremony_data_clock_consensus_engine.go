package ceremony

import (
	"bytes"
	"context"
	"crypto"
	"crypto/tls"
	"encoding/binary"
	"sync"
	"time"

	"github.com/multiformats/go-multiaddr"
	mn "github.com/multiformats/go-multiaddr/net"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/types/known/anypb"
	"source.quilibrium.com/quilibrium/monorepo/go-libp2p-blossomsub/pb"
	"source.quilibrium.com/quilibrium/monorepo/nekryptology/pkg/core/curves"
	"source.quilibrium.com/quilibrium/monorepo/node/config"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus"
	qtime "source.quilibrium.com/quilibrium/monorepo/node/consensus/time"
	qcrypto "source.quilibrium.com/quilibrium/monorepo/node/crypto"
	"source.quilibrium.com/quilibrium/monorepo/node/execution"
	"source.quilibrium.com/quilibrium/monorepo/node/keys"
	"source.quilibrium.com/quilibrium/monorepo/node/p2p"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/node/store"
	"source.quilibrium.com/quilibrium/monorepo/node/tries"
)

const PEER_INFO_TTL = 60 * 60 * 1000
const UNCOOPERATIVE_PEER_INFO_TTL = 5 * 60 * 1000

type InclusionMap = map[curves.PairingPoint]*protobufs.InclusionCommitment
type PolynomialMap = map[curves.PairingPoint][]curves.PairingScalar
type SyncStatusType int

const (
	SyncStatusNotSyncing = iota
	SyncStatusAwaitingResponse
	SyncStatusSynchronizing
	SyncStatusFailed
)

type peerInfo struct {
	peerId        []byte
	multiaddr     string
	maxFrame      uint64
	timestamp     int64
	lastSeen      int64
	version       []byte
	signature     []byte
	publicKey     []byte
	direct        bool
	totalDistance []byte
}

type ChannelServer = protobufs.CeremonyService_GetPublicChannelServer

type CeremonyDataClockConsensusEngine struct {
	protobufs.UnimplementedCeremonyServiceServer
	difficulty                  uint32
	logger                      *zap.Logger
	state                       consensus.EngineState
	clockStore                  store.ClockStore
	keyStore                    store.KeyStore
	pubSub                      p2p.PubSub
	keyManager                  keys.KeyManager
	masterTimeReel              *qtime.MasterTimeReel
	dataTimeReel                *qtime.DataTimeReel
	peerInfoManager             p2p.PeerInfoManager
	provingKey                  crypto.Signer
	provingKeyBytes             []byte
	provingKeyType              keys.KeyType
	provingKeyAddress           []byte
	lastFrameReceivedAt         time.Time
	latestFrameReceived         uint64
	frameProverTrie             *tries.RollingFrecencyCritbitTrie
	dependencyMap               map[string]*anypb.Any
	pendingCommits              chan *anypb.Any
	pendingCommitWorkers        int64
	inclusionProver             qcrypto.InclusionProver
	frameProver                 qcrypto.FrameProver
	stagedLobbyStateTransitions *protobufs.CeremonyLobbyStateTransition
	minimumPeersRequired        int
	statsClient                 protobufs.NodeStatsClient
	currentReceivingSyncPeersMx sync.Mutex
	currentReceivingSyncPeers   int

	frameChan                      chan *protobufs.ClockFrame
	executionEngines               map[string]execution.ExecutionEngine
	filter                         []byte
	input                          []byte
	parentSelector                 []byte
	syncingStatus                  SyncStatusType
	syncingTarget                  []byte
	previousHead                   *protobufs.ClockFrame
	engineMx                       sync.Mutex
	dependencyMapMx                sync.Mutex
	stagedLobbyStateTransitionsMx  sync.Mutex
	peerMapMx                      sync.RWMutex
	peerAnnounceMapMx              sync.Mutex
	lastKeyBundleAnnouncementFrame uint64
	peerMap                        map[string]*peerInfo
	uncooperativePeersMap          map[string]*peerInfo
	messageProcessorCh             chan *pb.Message
}

var _ consensus.DataConsensusEngine = (*CeremonyDataClockConsensusEngine)(nil)

// Creates a new data clock for ceremony execution – this is a hybrid clock,
// normally data clocks are bloom sharded and have node-specific proofs along
// with the public VDF proofs, but in this case it is a proof from the execution
// across all participating nodes.
func NewCeremonyDataClockConsensusEngine(
	engineConfig *config.EngineConfig,
	logger *zap.Logger,
	keyManager keys.KeyManager,
	clockStore store.ClockStore,
	keyStore store.KeyStore,
	pubSub p2p.PubSub,
	frameProver qcrypto.FrameProver,
	inclusionProver qcrypto.InclusionProver,
	masterTimeReel *qtime.MasterTimeReel,
	dataTimeReel *qtime.DataTimeReel,
	peerInfoManager p2p.PeerInfoManager,
	filter []byte,
	seed []byte,
) *CeremonyDataClockConsensusEngine {
	if logger == nil {
		panic(errors.New("logger is nil"))
	}

	if engineConfig == nil {
		panic(errors.New("engine config is nil"))
	}

	if keyManager == nil {
		panic(errors.New("key manager is nil"))
	}

	if clockStore == nil {
		panic(errors.New("clock store is nil"))
	}

	if keyStore == nil {
		panic(errors.New("key store is nil"))
	}

	if pubSub == nil {
		panic(errors.New("pubsub is nil"))
	}

	if frameProver == nil {
		panic(errors.New("frame prover is nil"))
	}

	if inclusionProver == nil {
		panic(errors.New("inclusion prover is nil"))
	}

	if masterTimeReel == nil {
		panic(errors.New("master time reel is nil"))
	}

	if dataTimeReel == nil {
		panic(errors.New("data time reel is nil"))
	}

	if peerInfoManager == nil {
		panic(errors.New("peer info manager is nil"))
	}

	minimumPeersRequired := engineConfig.MinimumPeersRequired
	if minimumPeersRequired == 0 {
		minimumPeersRequired = 3
	}

	difficulty := engineConfig.Difficulty
	if difficulty == 0 {
		difficulty = 10000
	}

	var statsClient protobufs.NodeStatsClient
	if engineConfig.StatsMultiaddr != "" {
		ma, err := multiaddr.NewMultiaddr(engineConfig.StatsMultiaddr)
		if err != nil {
			panic(err)
		}

		_, addr, err := mn.DialArgs(ma)
		if err != nil {
			panic(err)
		}

		cc, err := grpc.Dial(
			addr,
			grpc.WithTransportCredentials(
				credentials.NewTLS(&tls.Config{InsecureSkipVerify: false}),
			),
			grpc.WithDefaultCallOptions(
				grpc.MaxCallSendMsgSize(600*1024*1024),
				grpc.MaxCallRecvMsgSize(600*1024*1024),
			),
		)
		if err != nil {
			panic(err)
		}

		statsClient = protobufs.NewNodeStatsClient(cc)
	}

	e := &CeremonyDataClockConsensusEngine{
		difficulty:       difficulty,
		logger:           logger,
		state:            consensus.EngineStateStopped,
		clockStore:       clockStore,
		keyStore:         keyStore,
		keyManager:       keyManager,
		pubSub:           pubSub,
		frameChan:        make(chan *protobufs.ClockFrame),
		executionEngines: map[string]execution.ExecutionEngine{},
		dependencyMap:    make(map[string]*anypb.Any),
		parentSelector: []byte{
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		},
		currentReceivingSyncPeers: 0,
		lastFrameReceivedAt:       time.Time{},
		frameProverTrie:           &tries.RollingFrecencyCritbitTrie{},
		inclusionProver:           inclusionProver,
		syncingStatus:             SyncStatusNotSyncing,
		peerMap:                   map[string]*peerInfo{},
		uncooperativePeersMap:     map[string]*peerInfo{},
		minimumPeersRequired:      minimumPeersRequired,
		frameProver:               frameProver,
		masterTimeReel:            masterTimeReel,
		dataTimeReel:              dataTimeReel,
		peerInfoManager:           peerInfoManager,
		statsClient:               statsClient,
		messageProcessorCh:        make(chan *pb.Message),
	}

	logger.Info("constructing consensus engine")

	signer, keyType, bytes, address := e.GetProvingKey(
		engineConfig,
	)

	e.filter = filter
	e.input = seed
	e.provingKey = signer
	e.provingKeyType = keyType
	e.provingKeyBytes = bytes
	e.provingKeyAddress = address

	return e
}

func (e *CeremonyDataClockConsensusEngine) Start() <-chan error {
	e.logger.Info("starting ceremony consensus engine")
	e.state = consensus.EngineStateStarting
	errChan := make(chan error)
	e.state = consensus.EngineStateLoading

	e.logger.Info("loading last seen state")
	err := e.dataTimeReel.Start()
	if err != nil {
		panic(err)
	}

	e.frameProverTrie = e.dataTimeReel.GetFrameProverTrie()

	err = e.createCommunicationKeys()
	if err != nil {
		panic(err)
	}

	go e.runMessageHandler()

	e.logger.Info("subscribing to pubsub messages")
	e.pubSub.Subscribe(e.filter, e.handleMessage, true)

	go func() {
		server := grpc.NewServer(
			grpc.MaxSendMsgSize(600*1024*1024),
			grpc.MaxRecvMsgSize(600*1024*1024),
		)
		protobufs.RegisterCeremonyServiceServer(server, e)

		if err := e.pubSub.StartDirectChannelListener(
			e.pubSub.GetPeerID(),
			"",
			server,
		); err != nil {
			panic(err)
		}
	}()

	e.state = consensus.EngineStateCollecting

	go func() {
		thresholdBeforeConfirming := 4

		for {
			list := &protobufs.CeremonyPeerListAnnounce{
				PeerList: []*protobufs.CeremonyPeer{},
			}

			frame, err := e.dataTimeReel.Head()
			if err != nil {
				panic(err)
			}

			e.latestFrameReceived = frame.FrameNumber
			e.logger.Info(
				"preparing peer announce",
				zap.Uint64("frame_number", frame.FrameNumber),
			)

			timestamp := time.Now().UnixMilli()
			msg := binary.BigEndian.AppendUint64([]byte{}, frame.FrameNumber)
			msg = append(msg, config.GetVersion()...)
			msg = binary.BigEndian.AppendUint64(msg, uint64(timestamp))
			sig, err := e.pubSub.SignMessage(msg)
			if err != nil {
				panic(err)
			}

			e.peerMapMx.Lock()
			e.peerMap[string(e.pubSub.GetPeerID())] = &peerInfo{
				peerId:    e.pubSub.GetPeerID(),
				multiaddr: "",
				maxFrame:  frame.FrameNumber,
				version:   config.GetVersion(),
				signature: sig,
				publicKey: e.pubSub.GetPublicKey(),
				timestamp: timestamp,
				totalDistance: e.dataTimeReel.GetTotalDistance().FillBytes(
					make([]byte, 256),
				),
			}
			deletes := []*peerInfo{}
			list.PeerList = append(list.PeerList, &protobufs.CeremonyPeer{
				PeerId:    e.pubSub.GetPeerID(),
				Multiaddr: "",
				MaxFrame:  frame.FrameNumber,
				Version:   config.GetVersion(),
				Signature: sig,
				PublicKey: e.pubSub.GetPublicKey(),
				Timestamp: timestamp,
				TotalDistance: e.dataTimeReel.GetTotalDistance().FillBytes(
					make([]byte, 256),
				),
			})
			for _, v := range e.uncooperativePeersMap {
				if v == nil {
					continue
				}
				if v.timestamp <= time.Now().UnixMilli()-UNCOOPERATIVE_PEER_INFO_TTL ||
					thresholdBeforeConfirming > 0 {
					deletes = append(deletes, v)
				}
			}
			for _, v := range deletes {
				delete(e.uncooperativePeersMap, string(v.peerId))
			}
			e.peerMapMx.Unlock()

			if e.statsClient != nil {
				_, err := e.statsClient.PutPeerInfo(
					context.Background(),
					&protobufs.PutPeerInfoRequest{
						PeerInfo: []*protobufs.PeerInfo{
							{
								PeerId:     e.pubSub.GetPeerID(),
								Multiaddrs: []string{""},
								MaxFrame:   frame.FrameNumber,
								Version:    config.GetVersion(),
								Signature:  sig,
								PublicKey:  e.pubSub.GetPublicKey(),
								Timestamp:  timestamp,
								TotalDistance: e.dataTimeReel.GetTotalDistance().FillBytes(
									make([]byte, 256),
								),
							},
						},
						UncooperativePeerInfo: []*protobufs.PeerInfo{},
					},
				)
				if err != nil {
					e.logger.Error("could not emit stats", zap.Error(err))
				}
			}

			e.logger.Info(
				"broadcasting peer info",
				zap.Uint64("frame_number", frame.FrameNumber),
			)

			if err := e.publishMessage(e.filter, list); err != nil {
				e.logger.Debug("error publishing message", zap.Error(err))
			}

			if thresholdBeforeConfirming > 0 {
				thresholdBeforeConfirming--
			}

			time.Sleep(120 * time.Second)
		}
	}()

	go e.runLoop()

	go func() {
		errChan <- nil
	}()

	return errChan
}

func (e *CeremonyDataClockConsensusEngine) runLoop() {
	dataFrameCh := e.dataTimeReel.NewFrameCh()

	e.logger.Info("waiting for peer list mappings")
	// We need to re-tune this so that libp2p's peerstore activation threshold
	// considers DHT peers to be correct:
	time.Sleep(30 * time.Second)

	for e.state < consensus.EngineStateStopping {
		peerCount := e.pubSub.GetNetworkPeersCount()
		if peerCount < e.minimumPeersRequired {
			e.logger.Info(
				"waiting for minimum peers",
				zap.Int("peer_count", peerCount),
			)
			time.Sleep(1 * time.Second)
		} else {
			latestFrame, err := e.dataTimeReel.Head()
			if err != nil {
				panic(err)
			}
			select {
			case dataFrame := <-dataFrameCh:
				if latestFrame, err = e.collect(dataFrame); err != nil {
					e.logger.Error("could not collect", zap.Error(err))
				}

				dataFrame, err := e.dataTimeReel.Head()
				if err != nil {
					panic(err)
				}

				if latestFrame != nil &&
					dataFrame.FrameNumber > latestFrame.FrameNumber {
					latestFrame = dataFrame
				}

				if e.latestFrameReceived < latestFrame.FrameNumber {
					e.latestFrameReceived = latestFrame.FrameNumber
					go func() {
						select {
						case e.frameChan <- latestFrame:
						default:
						}
					}()
				}

				var nextFrame *protobufs.ClockFrame
				if nextFrame, err = e.prove(latestFrame); err != nil {
					e.logger.Error("could not prove", zap.Error(err))
					e.state = consensus.EngineStateCollecting
					continue
				}

				if bytes.Equal(
					e.frameProverTrie.FindNearest(e.provingKeyAddress).External.Key,
					e.provingKeyAddress,
				) {
					e.dataTimeReel.Insert(nextFrame, false)

					if err = e.publishProof(nextFrame); err != nil {
						e.logger.Error("could not publish", zap.Error(err))
						e.state = consensus.EngineStateCollecting
					}
				}
			case <-time.After(20 * time.Second):
				dataFrame, err := e.dataTimeReel.Head()
				if err != nil {
					panic(err)
				}

				if latestFrame, err = e.collect(dataFrame); err != nil {
					e.logger.Error("could not collect", zap.Error(err))
					continue
				}

				if latestFrame == nil ||
					latestFrame.FrameNumber < dataFrame.FrameNumber {
					latestFrame, err = e.dataTimeReel.Head()
					if err != nil {
						panic(err)
					}
				}

				if e.latestFrameReceived < latestFrame.FrameNumber {
					e.latestFrameReceived = latestFrame.FrameNumber
					go func() {
						select {
						case e.frameChan <- latestFrame:
						default:
						}
					}()
				}

				var nextFrame *protobufs.ClockFrame
				if nextFrame, err = e.prove(latestFrame); err != nil {
					e.logger.Error("could not prove", zap.Error(err))
					e.state = consensus.EngineStateCollecting
					continue
				}

				if bytes.Equal(
					e.frameProverTrie.FindNearest(e.provingKeyAddress).External.Key,
					e.provingKeyAddress,
				) {
					e.dataTimeReel.Insert(nextFrame, false)

					if err = e.publishProof(nextFrame); err != nil {
						e.logger.Error("could not publish", zap.Error(err))
						e.state = consensus.EngineStateCollecting
					}
				}
			}
		}
	}
}

func (e *CeremonyDataClockConsensusEngine) Stop(force bool) <-chan error {
	e.logger.Info("stopping ceremony consensus engine")
	e.state = consensus.EngineStateStopping
	errChan := make(chan error)

	wg := sync.WaitGroup{}
	wg.Add(len(e.executionEngines))
	for name := range e.executionEngines {
		name := name
		go func(name string) {
			frame, err := e.dataTimeReel.Head()
			if err != nil {
				panic(err)
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

	e.dataTimeReel.Stop()
	e.state = consensus.EngineStateStopped

	e.engineMx.Lock()
	defer e.engineMx.Unlock()
	go func() {
		errChan <- nil
	}()
	return errChan
}

func (e *CeremonyDataClockConsensusEngine) GetDifficulty() uint32 {
	return e.difficulty
}

func (e *CeremonyDataClockConsensusEngine) GetFrame() *protobufs.ClockFrame {
	frame, err := e.dataTimeReel.Head()
	if err != nil {
		panic(err)
	}

	return frame
}

func (e *CeremonyDataClockConsensusEngine) GetState() consensus.EngineState {
	return e.state
}

func (
	e *CeremonyDataClockConsensusEngine,
) GetFrameChannel() <-chan *protobufs.ClockFrame {
	return e.frameChan
}

func (
	e *CeremonyDataClockConsensusEngine,
) GetPeerInfo() *protobufs.PeerInfoResponse {
	resp := &protobufs.PeerInfoResponse{}
	e.peerMapMx.RLock()
	for _, v := range e.peerMap {
		resp.PeerInfo = append(resp.PeerInfo, &protobufs.PeerInfo{
			PeerId:        v.peerId,
			Multiaddrs:    []string{v.multiaddr},
			MaxFrame:      v.maxFrame,
			Timestamp:     v.timestamp,
			Version:       v.version,
			Signature:     v.signature,
			PublicKey:     v.publicKey,
			TotalDistance: v.totalDistance,
		})
	}
	for _, v := range e.uncooperativePeersMap {
		resp.UncooperativePeerInfo = append(
			resp.UncooperativePeerInfo,
			&protobufs.PeerInfo{
				PeerId:        v.peerId,
				Multiaddrs:    []string{v.multiaddr},
				MaxFrame:      v.maxFrame,
				Timestamp:     v.timestamp,
				Version:       v.version,
				Signature:     v.signature,
				PublicKey:     v.publicKey,
				TotalDistance: v.totalDistance,
			},
		)
	}
	e.peerMapMx.RUnlock()
	return resp
}

func (e *CeremonyDataClockConsensusEngine) createCommunicationKeys() error {
	_, err := e.keyManager.GetAgreementKey("q-ratchet-idk")
	if err != nil {
		if errors.Is(err, keys.KeyNotFoundErr) {
			_, err = e.keyManager.CreateAgreementKey(
				"q-ratchet-idk",
				keys.KeyTypeX448,
			)
			if err != nil {
				return errors.Wrap(err, "announce key bundle")
			}
		} else {
			return errors.Wrap(err, "announce key bundle")
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
				return errors.Wrap(err, "announce key bundle")
			}
		} else {
			return errors.Wrap(err, "announce key bundle")
		}
	}

	return nil
}
