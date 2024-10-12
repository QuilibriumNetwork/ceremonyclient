package data

import (
	"bytes"
	"context"
	"crypto"
	"encoding/binary"
	"fmt"
	"sync"
	"time"

	"github.com/multiformats/go-multiaddr"
	mn "github.com/multiformats/go-multiaddr/net"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/anypb"
	"source.quilibrium.com/quilibrium/monorepo/go-libp2p-blossomsub/pb"
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

type ChannelServer = protobufs.DataService_GetPublicChannelServer

type DataClockConsensusEngine struct {
	protobufs.UnimplementedDataServiceServer
	difficulty                  uint32
	engineConfig                *config.EngineConfig
	logger                      *zap.Logger
	state                       consensus.EngineState
	clockStore                  store.ClockStore
	coinStore                   store.CoinStore
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
	frameProverTries            []*tries.RollingFrecencyCritbitTrie
	dependencyMap               map[string]*anypb.Any
	pendingCommits              chan *anypb.Any
	pendingCommitWorkers        int64
	inclusionProver             qcrypto.InclusionProver
	frameProver                 qcrypto.FrameProver
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
	stagedTransactions             *protobufs.TokenRequests
	stagedTransactionsMx           sync.Mutex
	peerMapMx                      sync.RWMutex
	peerAnnounceMapMx              sync.Mutex
	lastKeyBundleAnnouncementFrame uint64
	peerMap                        map[string]*peerInfo
	uncooperativePeersMap          map[string]*peerInfo
	messageProcessorCh             chan *pb.Message
	report                         *protobufs.SelfTestReport
}

var _ consensus.DataConsensusEngine = (*DataClockConsensusEngine)(nil)

func NewDataClockConsensusEngine(
	engineConfig *config.EngineConfig,
	logger *zap.Logger,
	keyManager keys.KeyManager,
	clockStore store.ClockStore,
	coinStore store.CoinStore,
	keyStore store.KeyStore,
	pubSub p2p.PubSub,
	frameProver qcrypto.FrameProver,
	inclusionProver qcrypto.InclusionProver,
	masterTimeReel *qtime.MasterTimeReel,
	dataTimeReel *qtime.DataTimeReel,
	peerInfoManager p2p.PeerInfoManager,
	report *protobufs.SelfTestReport,
	filter []byte,
	seed []byte,
) *DataClockConsensusEngine {
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

	if coinStore == nil {
		panic(errors.New("coin store is nil"))
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
		difficulty = 100000
	}

	e := &DataClockConsensusEngine{
		difficulty:       difficulty,
		logger:           logger,
		state:            consensus.EngineStateStopped,
		clockStore:       clockStore,
		coinStore:        coinStore,
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
		frameProverTries:          []*tries.RollingFrecencyCritbitTrie{},
		inclusionProver:           inclusionProver,
		syncingStatus:             SyncStatusNotSyncing,
		peerMap:                   map[string]*peerInfo{},
		uncooperativePeersMap:     map[string]*peerInfo{},
		minimumPeersRequired:      minimumPeersRequired,
		report:                    report,
		frameProver:               frameProver,
		masterTimeReel:            masterTimeReel,
		dataTimeReel:              dataTimeReel,
		peerInfoManager:           peerInfoManager,
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

func (e *DataClockConsensusEngine) Start() <-chan error {
	e.logger.Info("starting data consensus engine")
	e.state = consensus.EngineStateStarting
	errChan := make(chan error)
	e.state = consensus.EngineStateLoading

	e.logger.Info("loading last seen state")
	err := e.dataTimeReel.Start()
	if err != nil {
		panic(err)
	}

	e.frameProverTries = e.dataTimeReel.GetFrameProverTries()

	err = e.createCommunicationKeys()
	if err != nil {
		panic(err)
	}

	go e.runMessageHandler()

	e.logger.Info("subscribing to pubsub messages")
	e.pubSub.Subscribe(e.filter, e.handleMessage)

	go func() {
		server := grpc.NewServer(
			grpc.MaxSendMsgSize(600*1024*1024),
			grpc.MaxRecvMsgSize(600*1024*1024),
		)
		protobufs.RegisterDataServiceServer(server, e)

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
			list := &protobufs.DataPeerListAnnounce{
				PeerList: []*protobufs.DataPeer{},
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
			list.PeerList = append(list.PeerList, &protobufs.DataPeer{
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

	go func() {
		frame, err := e.dataTimeReel.Head()
		if err != nil {
			panic(err)
		}

		// Let it sit until we at least have a few more peers inbound
		time.Sleep(30 * time.Second)
		parallelism := e.report.Cores - 1

		if parallelism < 3 {
			panic("invalid system configuration, minimum system configuration must be four cores")
		}

		var clients []protobufs.DataIPCServiceClient
		if len(e.engineConfig.DataWorkerMultiaddrs) != 0 {
			clients, err = e.createParallelDataClientsFromList()
			if err != nil {
				panic(err)
			}
		} else {
			clients, err = e.createParallelDataClientsFromBaseMultiaddr(
				int(parallelism),
			)
			if err != nil {
				panic(err)
			}
		}

		for {
			nextFrame, err := e.dataTimeReel.Head()
			if err != nil {
				panic(err)
			}

			if frame.FrameNumber == nextFrame.FrameNumber {
				time.Sleep(5 * time.Second)
				continue
			}

			e.PerformTimeProof(frame, frame.Difficulty, clients)
		}
	}()

	return errChan
}

func (e *DataClockConsensusEngine) PerformTimeProof(
	frame *protobufs.ClockFrame,
	difficulty uint32,
	clients []protobufs.DataIPCServiceClient,
) []byte {
	proof := []byte{}

	wg := sync.WaitGroup{}
	wg.Add(len(clients))
	for i, client := range clients {
		go func() {
			for j := 3; j >= 0; j-- {
				resp, err :=
					client.CalculateChallengeProof(
						context.Background(),
						&protobufs.ChallengeProofRequest{
							PeerId:     e.pubSub.GetPeerID(),
							ClockFrame: frame,
						},
					)
				if err != nil {
					if j == 0 {
						e.logger.Error("unable to get a response in time from worker")
					}
					if len(e.engineConfig.DataWorkerMultiaddrs) != 0 {
						e.logger.Error(
							"client failed, reconnecting after 50ms",
							zap.Uint32("client", uint32(i)),
						)
						time.Sleep(50 * time.Millisecond)
						client, err = e.createParallelDataClientsFromListAndIndex(uint32(i))
						if err != nil {
							e.logger.Error("failed to reconnect", zap.Error(err))
						}
					} else if len(e.engineConfig.DataWorkerMultiaddrs) == 0 {
						e.logger.Error(
							"client failed, reconnecting after 50ms",
						)
						time.Sleep(50 * time.Millisecond)
						client, err =
							e.createParallelDataClientsFromBaseMultiaddrAndIndex(uint32(i))
						if err != nil {
							e.logger.Error("failed to reconnect", zap.Error(err))
						}
					}
					continue
				}

				proof = resp.Output
				break
			}
			wg.Done()
		}()
	}
	wg.Wait()

	return proof
}

func (
	e *DataClockConsensusEngine,
) GetFrameProverTries() []*tries.RollingFrecencyCritbitTrie {
	return e.frameProverTries
}

func (e *DataClockConsensusEngine) runLoop() {
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

				for _, trie := range e.frameProverTries {
					var nextFrame *protobufs.ClockFrame
					if nextFrame, err = e.prove(latestFrame); err != nil {
						e.logger.Error("could not prove", zap.Error(err))
						e.state = consensus.EngineStateCollecting
						continue
					}

					if bytes.Equal(
						trie.FindNearest(e.provingKeyAddress).External.Key,
						e.provingKeyAddress,
					) {
						e.dataTimeReel.Insert(nextFrame, false)

						if err = e.publishProof(nextFrame); err != nil {
							e.logger.Error("could not publish", zap.Error(err))
							e.state = consensus.EngineStateCollecting
						}
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

				for _, trie := range e.frameProverTries {
					if bytes.Equal(
						trie.FindNearest(e.provingKeyAddress).External.Key,
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
}

func (e *DataClockConsensusEngine) Stop(force bool) <-chan error {
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

func (e *DataClockConsensusEngine) GetDifficulty() uint32 {
	return e.difficulty
}

func (e *DataClockConsensusEngine) GetFrame() *protobufs.ClockFrame {
	frame, err := e.dataTimeReel.Head()
	if err != nil {
		panic(err)
	}

	return frame
}

func (e *DataClockConsensusEngine) GetState() consensus.EngineState {
	return e.state
}

func (
	e *DataClockConsensusEngine,
) GetFrameChannel() <-chan *protobufs.ClockFrame {
	return e.frameChan
}

func (
	e *DataClockConsensusEngine,
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

func (e *DataClockConsensusEngine) createCommunicationKeys() error {
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

func (e *DataClockConsensusEngine) createParallelDataClientsFromListAndIndex(
	index uint32,
) (
	protobufs.DataIPCServiceClient,
	error,
) {
	ma, err := multiaddr.NewMultiaddr(e.engineConfig.DataWorkerMultiaddrs[index])
	if err != nil {
		return nil, errors.Wrap(err, "create parallel data client")
	}

	_, addr, err := mn.DialArgs(ma)
	if err != nil {
		return nil, errors.Wrap(err, "create parallel data client")
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
		return nil, errors.Wrap(err, "create parallel data client")
	}

	client := protobufs.NewDataIPCServiceClient(conn)

	e.logger.Info(
		"connected to data worker process",
		zap.Uint32("client", index),
	)
	return client, nil
}

func (
	e *DataClockConsensusEngine,
) createParallelDataClientsFromBaseMultiaddrAndIndex(
	index uint32,
) (
	protobufs.DataIPCServiceClient,
	error,
) {
	e.logger.Info(
		"re-connecting to data worker process",
		zap.Uint32("client", index),
	)

	if e.engineConfig.DataWorkerBaseListenMultiaddr == "" {
		e.engineConfig.DataWorkerBaseListenMultiaddr = "/ip4/127.0.0.1/tcp/%d"
	}

	if e.engineConfig.DataWorkerBaseListenPort == 0 {
		e.engineConfig.DataWorkerBaseListenPort = 40000
	}

	ma, err := multiaddr.NewMultiaddr(
		fmt.Sprintf(
			e.engineConfig.DataWorkerBaseListenMultiaddr,
			int(e.engineConfig.DataWorkerBaseListenPort)+int(index),
		),
	)
	if err != nil {
		return nil, errors.Wrap(err, "create parallel data client")
	}

	_, addr, err := mn.DialArgs(ma)
	if err != nil {
		return nil, errors.Wrap(err, "create parallel data client")
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
		return nil, errors.Wrap(err, "create parallel data client")
	}

	client := protobufs.NewDataIPCServiceClient(conn)

	e.logger.Info(
		"connected to data worker process",
		zap.Uint32("client", index),
	)
	return client, nil
}

func (e *DataClockConsensusEngine) createParallelDataClientsFromList() (
	[]protobufs.DataIPCServiceClient,
	error,
) {
	parallelism := len(e.engineConfig.DataWorkerMultiaddrs)

	e.logger.Info(
		"connecting to data worker processes",
		zap.Int("parallelism", parallelism),
	)

	clients := make([]protobufs.DataIPCServiceClient, parallelism)

	for i := 0; i < parallelism; i++ {
		ma, err := multiaddr.NewMultiaddr(e.engineConfig.DataWorkerMultiaddrs[i])
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
		zap.Int("parallelism", parallelism),
	)
	return clients, nil
}

func (e *DataClockConsensusEngine) createParallelDataClientsFromBaseMultiaddr(
	parallelism int,
) ([]protobufs.DataIPCServiceClient, error) {
	e.logger.Info(
		"connecting to data worker processes",
		zap.Int("parallelism", parallelism),
	)

	if e.engineConfig.DataWorkerBaseListenMultiaddr == "" {
		e.engineConfig.DataWorkerBaseListenMultiaddr = "/ip4/127.0.0.1/tcp/%d"
	}

	if e.engineConfig.DataWorkerBaseListenPort == 0 {
		e.engineConfig.DataWorkerBaseListenPort = 40000
	}

	clients := make([]protobufs.DataIPCServiceClient, parallelism)

	for i := 0; i < parallelism; i++ {
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
			e.logger.Warn("could not connect to client", zap.String("addr", addr))
			continue
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
			e.logger.Warn("could not dial to client", zap.String("addr", addr))
		}

		clients[i] = protobufs.NewDataIPCServiceClient(conn)
	}

	e.logger.Info(
		"connected to data worker processes",
		zap.Int("parallelism", parallelism),
	)
	return clients, nil
}
