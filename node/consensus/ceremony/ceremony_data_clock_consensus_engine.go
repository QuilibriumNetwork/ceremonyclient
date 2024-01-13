package ceremony

import (
	"crypto"
	"encoding/binary"
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

const PEER_INFO_TTL = 60 * 60 * 1000
const UNCOOPERATIVE_PEER_INFO_TTL = 60 * 60 * 1000

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
	peerId    []byte
	multiaddr string
	maxFrame  uint64
	timestamp int64
	lastSeen  int64
	version   []byte
	signature []byte
	publicKey []byte
	direct    bool
}

type ChannelServer = protobufs.CeremonyService_GetPublicChannelServer

type CeremonyDataClockConsensusEngine struct {
	protobufs.UnimplementedCeremonyServiceServer
	frame                       *protobufs.ClockFrame
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
	previousHead                   *protobufs.ClockFrame
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

	minimumPeersRequired := engineConfig.MinimumPeersRequired
	if minimumPeersRequired == 0 {
		minimumPeersRequired = 3
	}

	difficulty := engineConfig.Difficulty
	if difficulty == 0 {
		difficulty = 10000
	}

	e := &CeremonyDataClockConsensusEngine{
		frame:            nil,
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
	latestFrame, err := e.clockStore.GetLatestDataClockFrame(
		e.filter,
		e.frameProverTrie,
	)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		panic(err)
	}

	candidateLatestFrame, err := e.clockStore.GetLatestCandidateDataClockFrame(
		e.filter,
	)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		panic(err)
	}

	if candidateLatestFrame != nil {
		latestFrame = candidateLatestFrame
	}

	if latestFrame != nil {
		e.setFrame(latestFrame)
	} else {
		latestFrame = e.CreateGenesisFrame(nil)
	}

	err = e.createCommunicationKeys()
	if err != nil {
		panic(err)
	}

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
		thresholdBeforeConfirming := 4

		for {
			time.Sleep(30 * time.Second)

			list := &protobufs.CeremonyPeerListAnnounce{
				PeerList: []*protobufs.CeremonyPeer{},
			}

			timestamp := time.Now().UnixMilli()
			msg := binary.BigEndian.AppendUint64([]byte{}, e.frame.FrameNumber)
			msg = append(msg, consensus.GetVersion()...)
			msg = binary.BigEndian.AppendUint64(msg, uint64(timestamp))
			sig, err := e.pubSub.SignMessage(msg)
			if err != nil {
				panic(err)
			}

			e.peerMapMx.Lock()
			e.peerMap[string(e.pubSub.GetPeerID())] = &peerInfo{
				peerId:    e.pubSub.GetPeerID(),
				multiaddr: "",
				maxFrame:  e.frame.FrameNumber,
				version:   consensus.GetVersion(),
				signature: sig,
				publicKey: e.pubSub.GetPublicKey(),
				timestamp: timestamp,
			}
			deletes := []*peerInfo{}
			for _, v := range e.peerMap {
				list.PeerList = append(list.PeerList, &protobufs.CeremonyPeer{
					PeerId:    v.peerId,
					Multiaddr: v.multiaddr,
					MaxFrame:  v.maxFrame,
					Timestamp: v.timestamp,
					Version:   v.version,
					Signature: v.signature,
					PublicKey: v.publicKey,
				})
			}
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

			if err := e.publishMessage(e.filter, list); err != nil {
				e.logger.Debug("error publishing message", zap.Error(err))
			}

			if thresholdBeforeConfirming > 0 {
				thresholdBeforeConfirming--
			}
		}
	}()

	go func() {
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
				switch e.state {
				case consensus.EngineStateCollecting:
					currentFrame := latestFrame
					if latestFrame, err = e.collect(latestFrame); err != nil {
						e.logger.Error("could not collect", zap.Error(err))
						e.state = consensus.EngineStateCollecting
						latestFrame = currentFrame
					}
				case consensus.EngineStateProving:
					currentFrame := latestFrame
					if latestFrame, err = e.prove(latestFrame); err != nil {
						e.logger.Error("could not prove", zap.Error(err))
						e.state = consensus.EngineStateCollecting
						latestFrame = currentFrame
					}
				case consensus.EngineStatePublishing:
					if err = e.publishProof(latestFrame); err != nil {
						e.logger.Error("could not publish", zap.Error(err))
						e.state = consensus.EngineStateCollecting
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
			err := <-e.UnregisterExecutor(name, e.frame.FrameNumber, force)
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

func (e *CeremonyDataClockConsensusEngine) performSanityCheck(
	frame *protobufs.ClockFrame,
) *protobufs.ClockFrame {
	e.logger.Info("performing sanity check")
	start := uint64(0)
	idx := start
	end := frame.FrameNumber + 1
	var prior *protobufs.ClockFrame
	for start < end {
		tail := end
		if start+16 < tail {
			tail = start + 16
		}
		iter, err := e.clockStore.RangeDataClockFrames(
			e.filter,
			start,
			tail,
		)
		if err != nil {
			panic(err)
		}

		for iter.First(); iter.Valid(); iter.Next() {
			v, err := iter.Value()
			if err != nil {
				panic(err)
			}

			if v.FrameNumber != idx {
				e.logger.Warn(
					"discontinuity found, attempting to fix",
					zap.Uint64("expected_frame_number", idx),
					zap.Uint64("found_frame_number", v.FrameNumber),
				)

				disc := v
				for disc.FrameNumber-idx > 0 {
					frames, err := e.clockStore.GetCandidateDataClockFrames(
						e.filter,
						disc.FrameNumber-1,
					)
					if err != nil {
						panic(err)
					}

					found := false
					for _, candidate := range frames {
						selector, err := candidate.GetSelector()
						if err != nil {
							panic(err)
						}

						parentSelector, _, _, err := disc.GetParentSelectorAndDistance(nil)
						if err != nil {
							panic(err)
						}

						if selector.Cmp(parentSelector) == 0 {
							found = true
							_, priorTrie, err := e.clockStore.GetDataClockFrame(
								e.filter,
								prior.FrameNumber,
							)
							if err != nil {
								panic(err)
							}

							txn, err := e.clockStore.NewTransaction()
							if err != nil {
								panic(err)
							}

							err = e.clockStore.PutDataClockFrame(
								candidate,
								priorTrie,
								txn,
								true,
							)
							if err != nil {
								panic(err)
							}

							if err = txn.Commit(); err != nil {
								panic(err)
							}

							disc = candidate
						}
					}

					if !found {
						e.logger.Error(
							"could not resolve discontinuity, rewinding consensus head",
						)

						if err = iter.Close(); err != nil {
							panic(err)
						}

						return prior
					}
				}

				idx = v.FrameNumber
			} else {
				prior = v
			}

			idx++
		}

		if err = iter.Close(); err != nil {
			panic(err)
		}

		start += 16
	}

	return frame
}

func (e *CeremonyDataClockConsensusEngine) GetDifficulty() uint32 {
	return e.difficulty
}

func (e *CeremonyDataClockConsensusEngine) GetFrame() *protobufs.ClockFrame {
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
) GetPeerInfo() *protobufs.PeerInfoResponse {
	resp := &protobufs.PeerInfoResponse{}
	e.peerMapMx.Lock()
	for _, v := range e.peerMap {
		resp.PeerInfo = append(resp.PeerInfo, &protobufs.PeerInfo{
			PeerId:     v.peerId,
			Multiaddrs: []string{v.multiaddr},
			MaxFrame:   v.maxFrame,
			Timestamp:  v.timestamp,
			Version:    v.version,
			Signature:  v.signature,
			PublicKey:  v.publicKey,
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
				Version:    v.version,
				Signature:  v.signature,
				PublicKey:  v.publicKey,
			},
		)
	}
	e.peerMapMx.Unlock()
	return resp
}
