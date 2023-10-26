package ceremony

import (
	"crypto"
	"math/big"
	"sync"
	"time"

	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/anypb"
	"source.quilibrium.com/quilibrium/monorepo/nekryptology/pkg/core/curves"
	"source.quilibrium.com/quilibrium/monorepo/node/config"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus"
	qcrypto "source.quilibrium.com/quilibrium/monorepo/node/crypto"
	"source.quilibrium.com/quilibrium/monorepo/node/execution"
	"source.quilibrium.com/quilibrium/monorepo/node/keys"
	"source.quilibrium.com/quilibrium/monorepo/node/p2p"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/node/store"
	"source.quilibrium.com/quilibrium/monorepo/node/tries"
)

const PEER_INFO_TTL = 5 * 60 * 1000
const UNCOOPERATIVE_PEER_INFO_TTL = 60 * 60 * 1000

type InclusionMap = map[curves.PairingPoint]*protobufs.InclusionCommitment
type PolynomialMap = map[curves.PairingPoint][]curves.PairingScalar
type SyncStatusType int

const (
	SyncStatusNotSyncing = iota
	SyncStatusAwaitingResponse
	SyncStatusSynchronizing
)

type peerInfo struct {
	peerId    []byte
	multiaddr string
	maxFrame  uint64
	timestamp int64
	lastSeen  int64
	direct    bool
}

type ChannelServer = protobufs.CeremonyService_GetPublicChannelServer

type CeremonyDataClockConsensusEngine struct {
	protobufs.UnimplementedCeremonyServiceServer
	frame                       uint64
	activeFrame                 *protobufs.ClockFrame
	difficulty                  uint32
	logger                      *zap.Logger
	state                       consensus.EngineState
	clockStore                  store.ClockStore
	keyStore                    store.KeyStore
	pubSub                      p2p.PubSub
	keyManager                  keys.KeyManager
	provingKey                  crypto.Signer
	provingKeyBytes             []byte
	provingKeyType              keys.KeyType
	provingKeyAddress           []byte
	lastFrameReceivedAt         time.Time
	latestFrameReceived         uint64
	frameProverTrie             *tries.RollingFrecencyCritbitTrie
	frameSeenProverTrie         *tries.RollingFrecencyCritbitTrie
	dependencyMap               map[string]*anypb.Any
	pendingCommits              chan *anypb.Any
	pendingCommitWorkers        int64
	prover                      *qcrypto.KZGProver
	stagedKeyCommits            InclusionMap
	stagedKeyPolynomials        PolynomialMap
	stagedLobbyStateTransitions *protobufs.CeremonyLobbyStateTransition
	minimumPeersRequired        int

	frameChan                      chan *protobufs.ClockFrame
	executionEngines               map[string]execution.ExecutionEngine
	filter                         []byte
	input                          []byte
	parentSelector                 []byte
	syncingStatus                  SyncStatusType
	syncingTarget                  []byte
	currentDistance                *big.Int
	engineMx                       sync.Mutex
	dependencyMapMx                sync.Mutex
	stagedKeyCommitsMx             sync.Mutex
	stagedLobbyStateTransitionsMx  sync.Mutex
	peerMapMx                      sync.Mutex
	peerAnnounceMapMx              sync.Mutex
	lastKeyBundleAnnouncementFrame uint64
	peerAnnounceMap                map[string]*protobufs.CeremonyPeerListAnnounce
	peerMap                        map[string]*peerInfo
	uncooperativePeersMap          map[string]*peerInfo
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

	minimumPeersRequired := engineConfig.MinimumPeersRequired
	if minimumPeersRequired == 0 {
		minimumPeersRequired = 6
	}

	e := &CeremonyDataClockConsensusEngine{
		frame:            0,
		difficulty:       10000,
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
		lastFrameReceivedAt:   time.Time{},
		frameProverTrie:       &tries.RollingFrecencyCritbitTrie{},
		frameSeenProverTrie:   &tries.RollingFrecencyCritbitTrie{},
		pendingCommits:        make(chan *anypb.Any),
		pendingCommitWorkers:  engineConfig.PendingCommitWorkers,
		prover:                qcrypto.DefaultKZGProver(),
		stagedKeyCommits:      make(InclusionMap),
		stagedKeyPolynomials:  make(PolynomialMap),
		syncingStatus:         SyncStatusNotSyncing,
		peerAnnounceMap:       map[string]*protobufs.CeremonyPeerListAnnounce{},
		peerMap:               map[string]*peerInfo{},
		uncooperativePeersMap: map[string]*peerInfo{},
		minimumPeersRequired:  minimumPeersRequired,
	}

	logger.Info("constructing consensus engine")

	signer, keyType, bytes, address := e.GetProvingKey(
		engineConfig,
	)

	e.provingKey = signer
	e.provingKeyType = keyType
	e.provingKeyBytes = bytes
	e.provingKeyAddress = address

	return e
}

func (e *CeremonyDataClockConsensusEngine) Start(
	filter []byte,
	seed []byte,
) <-chan error {
	e.logger.Info("starting ceremony consensus engine")
	e.state = consensus.EngineStateStarting
	errChan := make(chan error)

	e.filter = filter
	e.input = seed
	e.state = consensus.EngineStateLoading

	e.logger.Info("loading last seen state")
	latestFrame, err := e.clockStore.GetLatestDataClockFrame(
		e.filter,
		e.frameProverTrie,
	)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		panic(err)
	}

	if latestFrame != nil {
		e.setFrame(latestFrame)
	} else {
		latestFrame = e.createGenesisFrame()
	}

	e.logger.Info("subscribing to pubsub messages")
	e.pubSub.Subscribe(e.filter, e.handleMessage, true)
	e.pubSub.Subscribe(
		append(append([]byte{}, e.filter...), e.pubSub.GetPeerID()...),
		e.handleSync,
		true,
	)

	go func() {
		server := grpc.NewServer(
			grpc.MaxSendMsgSize(400*1024*1024),
			grpc.MaxRecvMsgSize(400*1024*1024),
		)
		protobufs.RegisterCeremonyServiceServer(server, e)

		if err := e.pubSub.StartDirectChannelListener(
			e.pubSub.GetPeerID(),
			server,
		); err != nil {
			panic(err)
		}
	}()

	e.state = consensus.EngineStateCollecting

	for i := int64(0); i < e.pendingCommitWorkers; i++ {
		go e.handlePendingCommits(i)
	}

	go func() {
		for {
			time.Sleep(30 * time.Second)

			list := &protobufs.CeremonyPeerListAnnounce{
				PeerList: []*protobufs.CeremonyPeer{},
			}

			e.peerMapMx.Lock()
			e.peerMap[string(e.pubSub.GetPeerID())] = &peerInfo{
				peerId:    e.pubSub.GetPeerID(),
				multiaddr: "",
				maxFrame:  e.frame,
			}
			deletes := []*peerInfo{}
			for _, v := range e.peerMap {
				if v.timestamp > time.Now().UnixMilli()-PEER_INFO_TTL {
					list.PeerList = append(list.PeerList, &protobufs.CeremonyPeer{
						PeerId:    v.peerId,
						Multiaddr: v.multiaddr,
						MaxFrame:  v.maxFrame,
						Timestamp: v.timestamp,
					})
				} else {
					deletes = append(deletes, v)
				}
			}
			for _, v := range e.uncooperativePeersMap {
				if v.timestamp <= time.Now().UnixMilli()-UNCOOPERATIVE_PEER_INFO_TTL {
					deletes = append(deletes, v)
				}
			}
			for _, v := range deletes {
				delete(e.peerMap, string(v.peerId))
				delete(e.uncooperativePeersMap, string(v.peerId))
			}
			e.peerMapMx.Unlock()

			if err := e.publishMessage(e.filter, list); err != nil {
				e.logger.Debug("error publishing message", zap.Error(err))
			}
		}
	}()

	go func() {
		latest := latestFrame
		for {
			time.Sleep(30 * time.Second)
			peerCount := e.pubSub.GetNetworkPeersCount()
			if peerCount >= e.minimumPeersRequired {
				e.logger.Info("selecting leader")
				latest, err = e.commitLongestPath(latest)
				if err != nil {
					e.logger.Error("could not collect longest path", zap.Error(err))
					latest, _, err = e.clockStore.GetDataClockFrame(e.filter, 0)
					if err != nil {
						panic(err)
					}
				}
			}
		}
	}()

	go func() {
		for e.state < consensus.EngineStateStopping {
			peerCount := e.pubSub.GetNetworkPeersCount()
			if peerCount < e.minimumPeersRequired {
				e.logger.Info(
					"waiting for minimum peers",
					zap.Int("peer_count", peerCount),
				)
				time.Sleep(1 * time.Second)
			} else {
				switch e.state {
				case consensus.EngineStateCollecting:
					if latestFrame, err = e.collect(latestFrame); err != nil {
						e.logger.Error("could not collect", zap.Error(err))
						e.state = consensus.EngineStateCollecting
						errChan <- err
					}
				case consensus.EngineStateProving:
					if latestFrame, err = e.prove(latestFrame); err != nil {
						e.logger.Error("could not prove", zap.Error(err))
						e.state = consensus.EngineStateCollecting
						errChan <- err
					}
				case consensus.EngineStatePublishing:
					if err = e.publishProof(latestFrame); err != nil {
						e.logger.Error("could not publish", zap.Error(err))
						e.state = consensus.EngineStateCollecting
						errChan <- err
					}
				}
			}
		}
	}()

	go func() {
		errChan <- nil
	}()

	return errChan
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

func (e *CeremonyDataClockConsensusEngine) GetDifficulty() uint32 {
	return e.difficulty
}

func (e *CeremonyDataClockConsensusEngine) GetFrame() uint64 {
	return e.frame
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
) GetActiveFrame() *protobufs.ClockFrame {
	return e.activeFrame
}

func (
	e *CeremonyDataClockConsensusEngine,
) GetPeerInfo() *protobufs.PeerInfoResponse {
	resp := &protobufs.PeerInfoResponse{}
	e.peerMapMx.Lock()
	for _, v := range e.peerMap {
		resp.PeerInfo = append(resp.PeerInfo, &protobufs.PeerInfo{
			PeerId:     v.peerId,
			Multiaddrs: []string{v.multiaddr},
			MaxFrame:   v.maxFrame,
			Timestamp:  v.timestamp,
		})
	}
	for _, v := range e.uncooperativePeersMap {
		resp.UncooperativePeerInfo = append(
			resp.UncooperativePeerInfo,
			&protobufs.PeerInfo{
				PeerId:     v.peerId,
				Multiaddrs: []string{v.multiaddr},
				MaxFrame:   v.maxFrame,
				Timestamp:  v.timestamp,
			},
		)
	}
	e.peerMapMx.Unlock()
	return resp
}
