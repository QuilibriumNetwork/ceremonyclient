package ceremony

import (
	"bytes"
	"crypto"
	"crypto/rand"
	_ "embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"golang.org/x/crypto/sha3"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"source.quilibrium.com/quilibrium/monorepo/nekryptology/pkg/core/curves"
	"source.quilibrium.com/quilibrium/monorepo/nekryptology/pkg/vdf"
	"source.quilibrium.com/quilibrium/monorepo/node/config"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus/ceremony"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus/time"
	qcrypto "source.quilibrium.com/quilibrium/monorepo/node/crypto"
	"source.quilibrium.com/quilibrium/monorepo/node/crypto/kzg"
	"source.quilibrium.com/quilibrium/monorepo/node/execution"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/ceremony/application"
	"source.quilibrium.com/quilibrium/monorepo/node/keys"
	"source.quilibrium.com/quilibrium/monorepo/node/p2p"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/node/store"
	"source.quilibrium.com/quilibrium/monorepo/node/tries"
)

type CeremonyExecutionEngine struct {
	logger                     *zap.Logger
	clock                      *ceremony.CeremonyDataClockConsensusEngine
	clockStore                 store.ClockStore
	keyStore                   store.KeyStore
	keyManager                 keys.KeyManager
	engineConfig               *config.EngineConfig
	pubSub                     p2p.PubSub
	peerIdHash                 []byte
	provingKey                 crypto.Signer
	proverPublicKey            []byte
	provingKeyAddress          []byte
	inclusionProver            qcrypto.InclusionProver
	participantMx              sync.Mutex
	peerChannels               map[string]*p2p.PublicP2PChannel
	activeSecrets              []curves.Scalar
	activeClockFrame           *protobufs.ClockFrame
	alreadyPublishedShare      bool
	alreadyPublishedTranscript bool
	seenMessageMap             map[string]bool
	seenMessageMx              sync.Mutex
	intrinsicFilter            []byte
	frameProver                qcrypto.FrameProver
}

const validCeremonySelector = "253f3a6383dcfe91cf49abd20204b3e6ef5afd4c70c1968bb1f0b827a72af53b"

func NewCeremonyExecutionEngine(
	logger *zap.Logger,
	engineConfig *config.EngineConfig,
	keyManager keys.KeyManager,
	pubSub p2p.PubSub,
	frameProver qcrypto.FrameProver,
	inclusionProver qcrypto.InclusionProver,
	clockStore store.ClockStore,
	masterTimeReel *time.MasterTimeReel,
	peerInfoManager p2p.PeerInfoManager,
	keyStore store.KeyStore,
) *CeremonyExecutionEngine {
	if logger == nil {
		panic(errors.New("logger is nil"))
	}

	seed, err := hex.DecodeString(engineConfig.GenesisSeed)
	if err != nil {
		panic(err)
	}

	intrinsicFilter := append(
		p2p.GetBloomFilter(application.CEREMONY_ADDRESS, 256, 3),
		p2p.GetBloomFilterIndices(application.CEREMONY_ADDRESS, 65536, 24)...,
	)

	frame, _, err := clockStore.GetDataClockFrame(intrinsicFilter, 0, false)
	var origin []byte
	var inclusionProof *qcrypto.InclusionAggregateProof
	var proverKeys [][]byte

	rebuildGenesisFrame := false
	if frame != nil {
		selector, err := frame.GetSelector()
		if err != nil {
			panic(err)
		}

		if selector.Text(16) != validCeremonySelector {
			logger.Warn("corrupted genesis frame detected, rebuilding")

			err = clockStore.ResetDataClockFrames(intrinsicFilter)
			if err != nil {
				panic(err)
			}

			rebuildGenesisFrame = true
		}
	}

	if err != nil && errors.Is(err, store.ErrNotFound) || rebuildGenesisFrame {
		origin, inclusionProof, proverKeys = CreateGenesisState(
			logger,
			engineConfig,
			nil,
			inclusionProver,
		)
	}

	dataTimeReel := time.NewDataTimeReel(
		intrinsicFilter,
		logger,
		clockStore,
		engineConfig,
		frameProver,
		origin,
		inclusionProof,
		proverKeys,
	)

	clock := ceremony.NewCeremonyDataClockConsensusEngine(
		engineConfig,
		logger,
		keyManager,
		clockStore,
		keyStore,
		pubSub,
		frameProver,
		inclusionProver,
		masterTimeReel,
		dataTimeReel,
		peerInfoManager,
		intrinsicFilter,
		seed,
	)

	e := &CeremonyExecutionEngine{
		logger:                logger,
		clock:                 clock,
		engineConfig:          engineConfig,
		keyManager:            keyManager,
		clockStore:            clockStore,
		keyStore:              keyStore,
		pubSub:                pubSub,
		inclusionProver:       inclusionProver,
		frameProver:           frameProver,
		participantMx:         sync.Mutex{},
		peerChannels:          map[string]*p2p.PublicP2PChannel{},
		alreadyPublishedShare: false,
		seenMessageMx:         sync.Mutex{},
		seenMessageMap:        map[string]bool{},
		intrinsicFilter:       intrinsicFilter,
	}

	peerId := e.pubSub.GetPeerID()
	addr, err := poseidon.HashBytes(peerId)
	if err != nil {
		panic(err)
	}

	addrBytes := addr.Bytes()
	addrBytes = append(make([]byte, 32-len(addrBytes)), addrBytes...)
	e.peerIdHash = addrBytes
	provingKey, _, publicKeyBytes, provingKeyAddress := e.clock.GetProvingKey(
		engineConfig,
	)
	e.provingKey = provingKey
	e.proverPublicKey = publicKeyBytes
	e.provingKeyAddress = provingKeyAddress

	return e
}

var _ execution.ExecutionEngine = (*CeremonyExecutionEngine)(nil)

// GetName implements ExecutionEngine
func (*CeremonyExecutionEngine) GetName() string {
	return "ceremony"
}

// GetSupportedApplications implements ExecutionEngine
func (
	*CeremonyExecutionEngine,
) GetSupportedApplications() []*protobufs.Application {
	return []*protobufs.Application{
		{
			Address:          application.CEREMONY_ADDRESS,
			ExecutionContext: protobufs.ExecutionContext_EXECUTION_CONTEXT_INTRINSIC,
		},
	}
}

// 2024-01-03: 1.2.0
//
//go:embed retroactive_peers.json
var retroactivePeersJsonBinary []byte

// Creates a genesis state for the intrinsic
func CreateGenesisState(
	logger *zap.Logger,
	engineConfig *config.EngineConfig,
	testProverKeys [][]byte,
	inclusionProver qcrypto.InclusionProver,
) (
	[]byte,
	*qcrypto.InclusionAggregateProof,
	[][]byte,
) {
	seed, err := hex.DecodeString(engineConfig.GenesisSeed)

	if err != nil {
		panic(errors.New("genesis seed is nil"))
	}

	logger.Info("creating genesis frame")
	for _, l := range strings.Split(string(seed), "\n") {
		logger.Info(l)
	}

	difficulty := engineConfig.Difficulty
	if difficulty == 0 || difficulty == 10000 {
		difficulty = 100000
	}

	b := sha3.Sum256(seed)
	v := vdf.New(difficulty, b)

	v.Execute()
	o := v.GetOutput()
	inputMessage := o[:]

	// Signatories are special, they don't have an inclusion proof because they
	// have not broadcasted communication keys, but they still get contribution
	// rights prior to PoMW, because they did produce meaningful work in the
	// first phase:
	logger.Info("encoding signatories to prover trie")
	proverKeys := [][]byte{}
	if len(testProverKeys) != 0 {
		logger.Warn(
			"TEST PROVER ENTRIES BEING ADDED, YOUR NODE WILL BE KICKED IF IN" +
				" PRODUCTION",
		)
		proverKeys = testProverKeys
	} else {
		for _, s := range kzg.CeremonySignatories {
			pubkey := s.ToAffineCompressed()
			logger.Info("0x" + hex.EncodeToString(pubkey))

			proverKeys = append(proverKeys, pubkey)
		}
	}

	logger.Info("encoding ceremony and phase one signatories")
	transcript := &protobufs.CeremonyTranscript{}
	for p, s := range kzg.CeremonyBLS48581G1 {
		transcript.G1Powers = append(
			transcript.G1Powers,
			&protobufs.BLS48581G1PublicKey{
				KeyValue: s.ToAffineCompressed(),
			},
		)
		logger.Info(fmt.Sprintf("encoded G1 power %d", p))
	}
	for p, s := range kzg.CeremonyBLS48581G2 {
		transcript.G2Powers = append(
			transcript.G2Powers,
			&protobufs.BLS48581G2PublicKey{
				KeyValue: s.ToAffineCompressed(),
			},
		)
		logger.Info(fmt.Sprintf("encoded G2 power %d", p))
	}

	transcript.RunningG1_256Witnesses = append(
		transcript.RunningG1_256Witnesses,
		&protobufs.BLS48581G1PublicKey{
			KeyValue: kzg.CeremonyRunningProducts[0].ToAffineCompressed(),
		},
	)

	transcript.RunningG2_256Powers = append(
		transcript.RunningG2_256Powers,
		&protobufs.BLS48581G2PublicKey{
			KeyValue: kzg.CeremonyBLS48581G2[len(kzg.CeremonyBLS48581G2)-1].
				ToAffineCompressed(),
		},
	)

	outputProof := &protobufs.CeremonyLobbyStateTransition{
		TypeUrls:         []string{},
		TransitionInputs: [][]byte{},
	}

	proofBytes, err := proto.Marshal(outputProof)
	if err != nil {
		panic(err)
	}

	logger.Info("encoded transcript")
	logger.Info("encoding ceremony signatories into application state")

	rewardTrie := &tries.RewardCritbitTrie{}
	for _, s := range kzg.CeremonySignatories {
		pubkey := s.ToAffineCompressed()

		addr, err := poseidon.HashBytes(pubkey)
		if err != nil {
			panic(err)
		}

		addrBytes := addr.Bytes()
		addrBytes = append(make([]byte, 32-len(addrBytes)), addrBytes...)
		rewardTrie.Add(addrBytes, 0, 50)
	}

	type peerData struct {
		PeerId       string `json:"peer_id"`
		TokenBalance uint64 `json:"token_balance"`
	}
	type rewards struct {
		Rewards []peerData `json:"rewards"`
	}

	retroEntries := &rewards{}
	err = json.Unmarshal(retroactivePeersJsonBinary, retroEntries)
	if err != nil {
		panic(err)
	}

	logger.Info("adding retroactive peer reward info")
	for _, s := range retroEntries.Rewards {
		peerId := s.PeerId
		peerBytes, err := base64.StdEncoding.DecodeString(peerId)
		if err != nil {
			panic(err)
		}

		addr, err := poseidon.HashBytes(peerBytes)
		if err != nil {
			panic(err)
		}

		addrBytes := addr.Bytes()
		addrBytes = append(make([]byte, 32-len(addrBytes)), addrBytes...)
		rewardTrie.Add(addrBytes, 0, s.TokenBalance)
	}

	trieBytes, err := rewardTrie.Serialize()
	if err != nil {
		panic(err)
	}

	ceremonyLobbyState := &protobufs.CeremonyLobbyState{
		LobbyState: 0,
		CeremonyState: &protobufs.CeremonyLobbyState_CeremonyOpenState{
			CeremonyOpenState: &protobufs.CeremonyOpenState{
				JoinedParticipants:    []*protobufs.CeremonyLobbyJoin{},
				PreferredParticipants: []*protobufs.Ed448PublicKey{},
			},
		},
		LatestTranscript: transcript,
		RewardTrie:       trieBytes,
	}
	outputBytes, err := proto.Marshal(ceremonyLobbyState)
	if err != nil {
		panic(err)
	}

	intrinsicFilter := append(
		p2p.GetBloomFilter(application.CEREMONY_ADDRESS, 256, 3),
		p2p.GetBloomFilterIndices(application.CEREMONY_ADDRESS, 65536, 24)...,
	)

	// Compat: there was a bug that went unnoticed in prior versions,
	// the raw filter was used instead of the application address, which didn't
	// affect execution because we forcibly stashed it. Preserving this to ensure
	// no rebuilding of frame history is required.
	executionOutput := &protobufs.IntrinsicExecutionOutput{
		Address: intrinsicFilter,
		Output:  outputBytes,
		Proof:   proofBytes,
	}

	data, err := proto.Marshal(executionOutput)
	if err != nil {
		panic(err)
	}

	logger.Info("proving execution output for inclusion")
	commitment, err := inclusionProver.Commit(
		data,
		protobufs.IntrinsicExecutionOutputType,
	)
	if err != nil {
		panic(err)
	}

	logger.Info("creating kzg proof")
	proof, err := inclusionProver.ProveAggregate(
		[]*qcrypto.InclusionCommitment{
			commitment,
		},
	)
	if err != nil {
		panic(err)
	}

	logger.Info("finalizing execution proof")

	return inputMessage, proof, proverKeys
}

// Start implements ExecutionEngine
func (e *CeremonyExecutionEngine) Start() <-chan error {
	errChan := make(chan error)

	e.logger.Info("ceremony data loaded", zap.Binary(
		"g2_power",
		kzg.CeremonyBLS48581G2[1].ToAffineCompressed(),
	))

	go func() {
		err := <-e.clock.Start()
		if err != nil {
			panic(err)
		}

		err = <-e.clock.RegisterExecutor(e, 0)
		if err != nil {
			panic(err)
		}

		go e.RunWorker()

		errChan <- nil
	}()

	return errChan
}

// Stop implements ExecutionEngine
func (e *CeremonyExecutionEngine) Stop(force bool) <-chan error {
	errChan := make(chan error)

	go func() {
		errChan <- <-e.clock.Stop(force)
	}()

	return errChan
}

// ProcessMessage implements ExecutionEngine
func (e *CeremonyExecutionEngine) ProcessMessage(
	address []byte,
	message *protobufs.Message,
) ([]*protobufs.Message, error) {
	if bytes.Equal(address, e.GetSupportedApplications()[0].Address) {
		e.logger.Debug("processing execution message")
		any := &anypb.Any{}
		if err := proto.Unmarshal(message.Payload, any); err != nil {
			return nil, errors.Wrap(err, "process message")
		}

		switch any.TypeUrl {
		case protobufs.ClockFrameType:
			frame := &protobufs.ClockFrame{}
			if err := any.UnmarshalTo(frame); err != nil {
				return nil, errors.Wrap(err, "process message")
			}

			if frame.FrameNumber < e.clock.GetFrame().FrameNumber {
				return nil, nil
			}

			if err := e.frameProver.VerifyDataClockFrame(frame); err != nil {
				return nil, errors.Wrap(err, "process message")
			}

			if err := e.VerifyExecution(frame); err != nil {
				return nil, errors.Wrap(err, "process message")
			}
		case protobufs.CeremonyLobbyJoinType:
			fallthrough
		case protobufs.CeremonySeenProverAttestationType:
			fallthrough
		case protobufs.CeremonyDroppedProverAttestationType:
			fallthrough
		case protobufs.CeremonyTranscriptCommitType:
			fallthrough
		case protobufs.CeremonyTranscriptShareType:
			fallthrough
		case protobufs.CeremonyTranscriptType:
			hash := sha3.Sum256(any.Value)
			if any.TypeUrl == protobufs.CeremonyTranscriptType {
				e.seenMessageMx.Lock()
				ref := string(hash[:])
				if _, ok := e.seenMessageMap[ref]; !ok {
					e.seenMessageMap[ref] = true
				} else {
					return nil, errors.Wrap(
						errors.New("message already received"),
						"process message",
					)
				}
				e.seenMessageMx.Unlock()
			}
			if e.clock.IsInProverTrie(e.proverPublicKey) {
				proposedTransition := &protobufs.CeremonyLobbyStateTransition{
					TypeUrls: []string{any.TypeUrl},
					TransitionInputs: [][]byte{
						any.Value,
					},
				}

				any := &anypb.Any{}
				if err := any.MarshalFrom(proposedTransition); err != nil {
					return nil, errors.Wrap(err, "process message")
				}

				any.TypeUrl = strings.Replace(
					any.TypeUrl,
					"type.googleapis.com",
					"types.quilibrium.com",
					1,
				)

				payload, err := proto.Marshal(any)
				if err != nil {
					return nil, errors.Wrap(err, "process message")
				}

				h, err := poseidon.HashBytes(payload)
				if err != nil {
					return nil, errors.Wrap(err, "process message")
				}

				msg := &protobufs.Message{
					Hash:    h.Bytes(),
					Address: e.provingKeyAddress,
					Payload: payload,
				}
				return []*protobufs.Message{
					msg,
				}, nil
			}
		}
	}

	return nil, nil
}

func (e *CeremonyExecutionEngine) RunWorker() {
	frameChan := e.clock.GetFrameChannel()
	for {
		select {
		case frame := <-frameChan:
			e.activeClockFrame = frame
			e.logger.Info(
				"evaluating next frame",
				zap.Uint64(
					"frame_number",
					frame.FrameNumber,
				),
			)
			app, err := application.MaterializeApplicationFromFrame(frame)
			if err != nil {
				e.logger.Error(
					"error while materializing application from frame",
					zap.Error(err),
				)
				panic(err)
			}

			_, _, reward := app.RewardTrie.Get(e.provingKeyAddress)
			_, _, retro := app.RewardTrie.Get(e.peerIdHash)
			e.logger.Info(
				"current application state",
				zap.Uint64("my_balance", reward+retro),
				zap.String("lobby_state", app.LobbyState.String()),
			)

			switch app.LobbyState {
			case application.CEREMONY_APPLICATION_STATE_OPEN:
				e.alreadyPublishedShare = false
				e.alreadyPublishedTranscript = false
				alreadyJoined := false
				for _, join := range app.LobbyJoins {
					if bytes.Equal(
						join.PublicKeySignatureEd448.PublicKey.KeyValue,
						e.proverPublicKey,
					) {
						alreadyJoined = true
						break
					}
				}

				e.logger.Info(
					"lobby open for joins",
					zap.Int("joined_participants", len(app.LobbyJoins)),
					zap.Int(
						"preferred_participants",
						len(app.NextRoundPreferredParticipants),
					),
					zap.Bool("in_lobby", alreadyJoined),
					zap.Uint64("state_count", app.StateCount),
				)

				if !alreadyJoined {
					e.logger.Info(
						"joining lobby",
						zap.Binary("proving_key", e.proverPublicKey),
					)
					if err := e.announceJoin(frame); err != nil {
						e.logger.Error(
							"failed to announce join",
							zap.Error(err),
						)
					}

					e.logger.Info("preparing contribution")
					// Calculate this now after announcing, this gives 10 frames of buffer
					e.ensureSecrets(app)
				}
			case application.CEREMONY_APPLICATION_STATE_IN_PROGRESS:
				inRound := false
				for _, p := range app.ActiveParticipants {
					if bytes.Equal(
						p.PublicKeySignatureEd448.PublicKey.KeyValue,
						e.proverPublicKey,
					) {
						inRound = true
						break
					}
				}

				if len(e.activeSecrets) == 0 && inRound {
					// If we ended up in the scenario where we do not have any secrets
					// available but we're in the round, we should politely leave.
					e.publishDroppedParticipant(e.proverPublicKey)
					continue
				}

				e.logger.Info(
					"round in progress",
					zap.Any("participants", app.ActiveParticipants),
					zap.Any(
						"current_seen_attestations",
						len(app.LatestSeenProverAttestations),
					),
					zap.Any(
						"current_dropped_attestations",
						len(app.DroppedParticipantAttestations),
					),
					zap.Any(
						"preferred_participants_for_next_round",
						len(app.NextRoundPreferredParticipants),
					),
					zap.Bool("in_round", inRound),
					zap.Uint64("current_sub_round", app.RoundCount),
					zap.Uint64("stale_state_count", app.StateCount),
				)

				shouldConnect := false
				position := 0
				if len(e.peerChannels) == 0 && app.RoundCount == 1 &&
					len(app.ActiveParticipants) > 1 {
					for i, p := range app.ActiveParticipants {
						if bytes.Equal(
							p.PublicKeySignatureEd448.PublicKey.KeyValue,
							e.proverPublicKey,
						) {
							shouldConnect = true
							position = i
							break
						}
					}
				}

				if shouldConnect {
					e.logger.Info(
						"connecting to peers",
						zap.Any("participants", app.ActiveParticipants),
					)
					err := e.connectToActivePeers(app, position)
					if err != nil {
						e.logger.Error("error while connecting to peers", zap.Error(err))
						e.publishDroppedParticipant(e.proverPublicKey)
						continue
					}
				}

				if len(e.peerChannels) != 0 {
					done := false
					rounds := app.TranscriptRoundAdvanceCommits
					if len(rounds) != 0 {
						for _, c := range rounds[app.RoundCount-1].Commits {
							if bytes.Equal(
								c.ProverSignature.PublicKey.KeyValue,
								e.proverPublicKey,
							) {
								done = true
							}
						}
					}

					if !done {
						e.logger.Info(
							"participating in round",
							zap.Any("participants", app.ActiveParticipants),
							zap.Uint64("current_round", app.RoundCount),
						)
						err := e.participateRound(app)
						if err != nil {
							e.logger.Error("error while participating in round", zap.Error(err))
							e.publishDroppedParticipant(e.proverPublicKey)
						}
					}
				} else if len(app.ActiveParticipants) == 1 &&
					bytes.Equal(
						app.ActiveParticipants[0].PublicKeySignatureEd448.PublicKey.KeyValue,
						e.proverPublicKey,
					) {
					if err = e.commitRound(e.activeSecrets); err != nil {
						e.logger.Error("error while participating in round", zap.Error(err))
					}
				}
			case application.CEREMONY_APPLICATION_STATE_FINALIZING:
				e.logger.Info(
					"round contribution finalizing",
					zap.Any("participants", len(app.ActiveParticipants)),
					zap.Any(
						"current_seen_attestations",
						len(app.LatestSeenProverAttestations),
					),
					zap.Any(
						"current_dropped_attestations",
						len(app.DroppedParticipantAttestations),
					),
					zap.Any(
						"preferred_participants_for_next_round",
						len(app.NextRoundPreferredParticipants),
					),
					zap.Int("finalized_shares", len(app.TranscriptShares)),
				)

				for _, s := range app.TranscriptShares {
					if bytes.Equal(
						s.ProverSignature.PublicKey.KeyValue,
						e.proverPublicKey,
					) {
						e.alreadyPublishedShare = true
					}
				}

				shouldPublish := false
				for _, p := range app.ActiveParticipants {
					if bytes.Equal(
						p.PublicKeySignatureEd448.PublicKey.KeyValue,
						e.proverPublicKey,
					) {
						shouldPublish = true
						break
					}
				}

				if !e.alreadyPublishedShare && shouldPublish {
					if len(e.activeSecrets) == 0 {
						e.publishDroppedParticipant(e.proverPublicKey)
						continue
					}
					err := e.publishTranscriptShare(app)
					if err != nil {
						e.logger.Error(
							"error while publishing transcript share",
							zap.Error(err),
						)
					}
				}
			case application.CEREMONY_APPLICATION_STATE_VALIDATING:
				e.logger.Info("round contribution validating")
				e.alreadyPublishedShare = false
				for _, c := range e.peerChannels {
					c.Close()
				}

				e.peerChannels = map[string]*p2p.PublicP2PChannel{}
				if app.UpdatedTranscript != nil && !e.alreadyPublishedTranscript {
					if err := e.publishTranscript(app); err != nil {
						e.logger.Error(
							"error while publishing transcript",
							zap.Error(err),
						)
					}
				}
			}
		}
	}
}

func (e *CeremonyExecutionEngine) publishMessage(
	filter []byte,
	message proto.Message,
) error {
	any := &anypb.Any{}
	if err := any.MarshalFrom(message); err != nil {
		return errors.Wrap(err, "publish message")
	}

	any.TypeUrl = strings.Replace(
		any.TypeUrl,
		"type.googleapis.com",
		"types.quilibrium.com",
		1,
	)

	payload, err := proto.Marshal(any)
	if err != nil {
		return errors.Wrap(err, "publish message")
	}

	h, err := poseidon.HashBytes(payload)
	if err != nil {
		return errors.Wrap(err, "publish message")
	}

	msg := &protobufs.Message{
		Hash:    h.Bytes(),
		Address: application.CEREMONY_ADDRESS,
		Payload: payload,
	}
	data, err := proto.Marshal(msg)
	if err != nil {
		return errors.Wrap(err, "publish message")
	}
	return e.pubSub.PublishToBitmask(filter, data)
}

func (e *CeremonyExecutionEngine) announceJoin(
	frame *protobufs.ClockFrame,
) error {
	idk, err := e.keyManager.GetAgreementKey("q-ratchet-idk")
	if err != nil {
		if errors.Is(err, keys.KeyNotFoundErr) {
			idk, err = e.keyManager.CreateAgreementKey(
				"q-ratchet-idk",
				keys.KeyTypeX448,
			)
			if err != nil {
				return errors.Wrap(err, "announce join")
			}
		} else {
			return errors.Wrap(err, "announce join")
		}
	}

	spk, err := e.keyManager.GetAgreementKey("q-ratchet-spk")
	if err != nil {
		if errors.Is(err, keys.KeyNotFoundErr) {
			spk, err = e.keyManager.CreateAgreementKey(
				"q-ratchet-spk",
				keys.KeyTypeX448,
			)
			if err != nil {
				return errors.Wrap(err, "announce join")
			}
		} else {
			return errors.Wrap(err, "announce join")
		}
	}

	g := curves.ED448().Point.Generator()

	join := &protobufs.CeremonyLobbyJoin{
		FrameNumber: frame.FrameNumber,
		IdentityKey: &protobufs.X448PublicKey{
			KeyValue: g.Mul(idk).ToAffineCompressed(),
		},
		SignedPreKey: &protobufs.X448PublicKey{
			KeyValue: g.Mul(spk).ToAffineCompressed(),
		},
		PeerId: e.pubSub.GetPeerID(),
	}
	sig, err := join.SignWithProverKey(e.provingKey)
	if err != nil {
		return errors.Wrap(err, "announce join")
	}

	join.PublicKeySignatureEd448 = &protobufs.Ed448Signature{
		Signature: sig,
		PublicKey: &protobufs.Ed448PublicKey{
			KeyValue: e.proverPublicKey,
		},
	}

	return errors.Wrap(
		e.publishMessage(
			e.intrinsicFilter,
			join,
		),
		"announce join",
	)
}

func (e *CeremonyExecutionEngine) connectToActivePeers(
	app *application.CeremonyApplication,
	position int,
) error {
	idk, err := e.keyManager.GetAgreementKey("q-ratchet-idk")
	if err != nil {
		return errors.Wrap(err, "connect to active peers")
	}
	spk, err := e.keyManager.GetAgreementKey("q-ratchet-spk")
	if err != nil {
		return errors.Wrap(err, "connect to active peers")
	}

	for i, p := range app.LobbyJoins {
		if !bytes.Equal(
			p.PublicKeySignatureEd448.PublicKey.KeyValue,
			e.proverPublicKey,
		) {
			receiverIdk, err := curves.ED448().Point.FromAffineCompressed(
				p.IdentityKey.KeyValue,
			)
			if err != nil {
				return errors.Wrap(err, "connect to active peers")
			}

			receiverSpk, err := curves.ED448().Point.FromAffineCompressed(
				p.SignedPreKey.KeyValue,
			)
			if err != nil {
				return errors.Wrap(err, "connect to active peers")
			}

			client, err := e.clock.GetPublicChannelForProvingKey(
				i > position,
				p.PeerId,
				p.PublicKeySignatureEd448.PublicKey.KeyValue,
			)
			if err != nil {
				e.logger.Error(
					"peer does not support direct public channels",
					zap.Binary(
						"proving_key",
						p.PublicKeySignatureEd448.PublicKey.KeyValue,
					),
					zap.Error(err),
				)
			}
			e.peerChannels[string(
				p.PublicKeySignatureEd448.PublicKey.KeyValue,
			)], err = p2p.NewPublicP2PChannel(
				client,
				e.proverPublicKey,
				p.PublicKeySignatureEd448.PublicKey.KeyValue,
				i > position,
				idk,
				spk,
				receiverIdk,
				receiverSpk,
				curves.ED448(),
				e.keyManager,
				e.pubSub,
			)
			if err != nil {
				e.logger.Error(
					"could not establish p2p channel",
					zap.Binary(
						"proving_key",
						p.PublicKeySignatureEd448.PublicKey.KeyValue,
					),
					zap.Error(err),
				)
				return errors.Wrap(err, "connect to active peers")
			}
		}
	}

	return nil
}

func (e *CeremonyExecutionEngine) participateRound(
	app *application.CeremonyApplication,
) error {
	idk, err := e.keyManager.GetAgreementKey("q-ratchet-idk")
	if err != nil {
		return errors.Wrap(err, "participate round")
	}

	spk, err := e.keyManager.GetAgreementKey("q-ratchet-spk")
	if err != nil {
		return errors.Wrap(err, "participate round")
	}

	idkPoint := curves.ED448().Point.Generator().Mul(idk)
	idks := []curves.Point{}
	initiator := false
	for _, p := range app.ActiveParticipants {
		if !bytes.Equal(
			p.PublicKeySignatureEd448.PublicKey.KeyValue,
			e.proverPublicKey,
		) {
			ic, err := e.keyStore.GetLatestKeyBundle(
				p.PublicKeySignatureEd448.PublicKey.KeyValue,
			)
			if err != nil {
				return errors.Wrap(err, "participate round")
			}

			var kba *protobufs.KeyBundleAnnouncement
			switch ic.TypeUrl {
			case protobufs.KeyBundleAnnouncementType:
				kba = &protobufs.KeyBundleAnnouncement{}
				if err := proto.Unmarshal(
					ic.Data,
					kba,
				); err != nil {
					return errors.Wrap(err, "participate round")
				}
			}

			receiverIdk, err := curves.ED448().Point.FromAffineCompressed(
				kba.IdentityKey.GetPublicKeySignatureEd448().PublicKey.KeyValue,
			)
			if err != nil {
				return errors.Wrap(err, "participate round")
			}

			receiverSpk, err := curves.ED448().Point.FromAffineCompressed(
				kba.SignedPreKey.GetPublicKeySignatureEd448().PublicKey.KeyValue,
			)
			if err != nil {
				return errors.Wrap(err, "participate round")
			}

			if _, ok := e.peerChannels[string(
				p.PublicKeySignatureEd448.PublicKey.KeyValue,
			)]; !ok {
				client, err := e.clock.GetPublicChannelForProvingKey(
					initiator,
					p.PeerId,
					p.PublicKeySignatureEd448.PublicKey.KeyValue,
				)
				if err != nil {
					e.logger.Error(
						"peer does not support direct public channels",
						zap.Binary(
							"proving_key",
							p.PublicKeySignatureEd448.PublicKey.KeyValue,
						),
						zap.Error(err),
					)
				}
				e.peerChannels[string(
					p.PublicKeySignatureEd448.PublicKey.KeyValue,
				)], err = p2p.NewPublicP2PChannel(
					client,
					e.proverPublicKey,
					p.PublicKeySignatureEd448.PublicKey.KeyValue,
					initiator,
					idk,
					spk,
					receiverIdk,
					receiverSpk,
					curves.ED448(),
					e.keyManager,
					e.pubSub,
				)
				if err != nil {
					return errors.Wrap(err, "participate round")
				}
			}

			idks = append(idks, receiverIdk)
		} else {
			initiator = true
			idks = append(idks, idkPoint)
		}
	}

	pubKeys := [][]byte{}
	for _, p := range app.ActiveParticipants {
		pubKeys = append(
			pubKeys,
			p.PublicKeySignatureEd448.PublicKey.KeyValue,
		)
	}

	newSecrets, err := application.ProcessRound(
		e.proverPublicKey,
		idk,
		int(app.RoundCount),
		pubKeys,
		idks,
		e.activeSecrets,
		curves.BLS48581G1(),
		func(i int, receiver []byte, msg []byte) error {
			return e.peerChannels[string(receiver)].Send(msg)
		},
		func(i int, sender []byte) ([]byte, error) {
			msg, err := e.peerChannels[string(
				sender,
			)].Receive()
			if err != nil {
				e.publishDroppedParticipant(sender)
				return nil, err
			} else {
				if i == 0 {
					e.publishLastSeenParticipant(sender)
				}
				return msg, nil
			}
		},
		app.LatestTranscript.G1Powers[1].KeyValue,
	)
	if err != nil {
		return errors.Wrap(err, "participate round")
	}

	return errors.Wrap(e.commitRound(newSecrets), "participate round")
}

func (e *CeremonyExecutionEngine) commitRound(secrets []curves.Scalar) error {
	g2Pub := curves.BLS48581G2().Point.Generator().Mul(secrets[0])

	sig, err := application.SignProverKeyForCommit(
		e.proverPublicKey,
		secrets[0],
	)
	if err != nil {
		return errors.Wrap(err, "commit round")
	}

	proverSig, err := e.provingKey.Sign(
		rand.Reader,
		g2Pub.ToAffineCompressed(),
		crypto.Hash(0),
	)
	if err != nil {
		return errors.Wrap(err, "commit round")
	}

	advance := &protobufs.CeremonyTranscriptCommit{
		ProverSignature: &protobufs.Ed448Signature{
			Signature: proverSig,
			PublicKey: &protobufs.Ed448PublicKey{
				KeyValue: e.proverPublicKey,
			},
		},
		ContributionSignature: &protobufs.BLS48581Signature{
			Signature: sig,
			PublicKey: &protobufs.BLS48581G2PublicKey{
				KeyValue: g2Pub.ToAffineCompressed(),
			},
		},
	}

	if err := e.publishMessage(
		e.intrinsicFilter,
		advance,
	); err != nil {
		return errors.Wrap(err, "commit round")
	}

	e.activeSecrets = secrets
	return nil
}

// Publishes a dropped participant attestation, logs any errors but does not
// forward them on.
func (e *CeremonyExecutionEngine) publishDroppedParticipant(
	participant []byte,
) {
	frameNumber := e.clock.GetFrame().FrameNumber

	b := binary.BigEndian.AppendUint64([]byte("dropped"), frameNumber)
	b = append(b, participant...)
	sig, err := e.provingKey.Sign(rand.Reader, b, crypto.Hash(0))
	if err != nil {
		e.logger.Error(
			"error while signing dropped participant attestation",
			zap.Error(err),
		)
		return
	}

	dropped := &protobufs.CeremonyDroppedProverAttestation{
		DroppedProverKey: &protobufs.Ed448PublicKey{
			KeyValue: participant,
		},
		LastSeenFrame: frameNumber,
		ProverSignature: &protobufs.Ed448Signature{
			Signature: sig,
			PublicKey: &protobufs.Ed448PublicKey{
				KeyValue: e.proverPublicKey,
			},
		},
	}

	err = e.publishMessage(
		e.intrinsicFilter,
		dropped,
	)
	if err != nil {
		e.logger.Error(
			"error while publishing dropped participant attestation",
			zap.Error(err),
		)
		return
	}
}

// Publishes a last seen participant attestation, logs any errors but does not
// forward them on.
func (e *CeremonyExecutionEngine) publishLastSeenParticipant(
	participant []byte,
) {
	frameNumber := e.clock.GetFrame().FrameNumber

	b := binary.BigEndian.AppendUint64([]byte("lastseen"), frameNumber)
	b = append(b, participant...)
	sig, err := e.provingKey.Sign(rand.Reader, b, crypto.Hash(0))
	if err != nil {
		e.logger.Error(
			"error while signing last seen participant attestation",
			zap.Error(err),
		)
		return
	}

	seen := &protobufs.CeremonySeenProverAttestation{
		SeenProverKey: &protobufs.Ed448PublicKey{
			KeyValue: participant,
		},
		LastSeenFrame: frameNumber,
		ProverSignature: &protobufs.Ed448Signature{
			Signature: sig,
			PublicKey: &protobufs.Ed448PublicKey{
				KeyValue: e.proverPublicKey,
			},
		},
	}
	err = e.publishMessage(
		e.intrinsicFilter,
		seen,
	)
	if err != nil {
		e.logger.Error(
			"error while publishing dropped participant attestation",
			zap.Error(err),
		)
		return
	}
}

func (e *CeremonyExecutionEngine) publishTranscriptShare(
	app *application.CeremonyApplication,
) error {
	transcriptShare := &protobufs.CeremonyTranscriptShare{}
	transcriptShare.AdditiveG1Powers = make(
		[]*protobufs.BLS48581G1PublicKey,
		len(e.activeSecrets),
	)
	transcriptShare.AdditiveG2Powers = make(
		[]*protobufs.BLS48581G2PublicKey,
		len(app.LatestTranscript.G2Powers)-1,
	)

	eg := errgroup.Group{}
	eg.SetLimit(100)
	e.logger.Info("creating transcript share")
	for i, s := range e.activeSecrets {
		i := i
		s := s
		eg.Go(func() error {
			if i%100 == 0 {
				e.logger.Info(
					"writing transcript share chunk",
					zap.Int("chunk_start", i),
				)
			}

			basisG1, err := curves.BLS48581G1().Point.FromAffineCompressed(
				app.LatestTranscript.G1Powers[i+1].KeyValue,
			)
			if err != nil {
				return errors.Wrap(err, "publish transcript share")
			}

			transcriptShare.AdditiveG1Powers[i] = &protobufs.BLS48581G1PublicKey{
				KeyValue: basisG1.Mul(s).ToAffineCompressed(),
			}

			if i+1 < len(app.LatestTranscript.G2Powers) {
				basisG2, err := curves.BLS48581G2().Point.FromAffineCompressed(
					app.LatestTranscript.G2Powers[i+1].KeyValue,
				)
				if err != nil {
					return errors.Wrap(err, "publish transcript share")
				}

				transcriptShare.AdditiveG2Powers[i] = &protobufs.BLS48581G2PublicKey{
					KeyValue: basisG2.Mul(s).ToAffineCompressed(),
				}
			}
			return nil
		})
	}

	if err := eg.Wait(); err != nil {
		return err
	}

	e.logger.Info(
		"done writing transcript chunks, adding witnesses and signing",
	)

	transcriptShare.AdditiveG1_256Witness = &protobufs.BLS48581G1PublicKey{
		KeyValue: curves.BLS48581G1().Point.Generator().Mul(
			e.activeSecrets[len(app.LatestTranscript.G2Powers)-2],
		).ToAffineCompressed(),
	}

	transcriptShare.AdditiveG2_256Witness = &protobufs.BLS48581G2PublicKey{
		KeyValue: curves.BLS48581G2().Point.Generator().Mul(
			e.activeSecrets[len(app.LatestTranscript.G2Powers)-2],
		).ToAffineCompressed(),
	}

	sig, err := transcriptShare.SignWithProverKey(e.provingKey)
	if err != nil {
		errors.Wrap(err, "publish transcript share")
	}

	transcriptShare.ProverSignature = &protobufs.Ed448Signature{
		Signature: sig,
		PublicKey: &protobufs.Ed448PublicKey{
			KeyValue: e.proverPublicKey,
		},
	}

	err = errors.Wrap(
		e.publishMessage(
			e.intrinsicFilter,
			transcriptShare,
		),
		"publish transcript share",
	)
	if err != nil {
		return err
	} else {
		e.alreadyPublishedShare = true
		return nil
	}
}

func (e *CeremonyExecutionEngine) VerifyExecution(
	frame *protobufs.ClockFrame,
) error {
	if e.clock.GetFrame().FrameNumber != frame.FrameNumber-1 {
		return nil
	}

	if len(frame.AggregateProofs) > 0 {
		for _, proofs := range frame.AggregateProofs {
			for _, inclusion := range proofs.InclusionCommitments {
				if inclusion.TypeUrl == protobufs.IntrinsicExecutionOutputType {
					transition, _, err := application.GetOutputsFromClockFrame(frame)
					if err != nil {
						return errors.Wrap(err, "verify execution")
					}

					parent, err := e.clockStore.GetStagedDataClockFrame(
						append(
							p2p.GetBloomFilter(application.CEREMONY_ADDRESS, 256, 3),
							p2p.GetBloomFilterIndices(
								application.CEREMONY_ADDRESS,
								65536,
								24,
							)...,
						),
						frame.FrameNumber-1,
						frame.ParentSelector,
						false,
					)
					if err != nil && !errors.Is(err, store.ErrNotFound) {
						return errors.Wrap(err, "verify execution")
					}

					if parent == nil {
						return errors.Wrap(
							errors.New("missing parent frame"),
							"verify execution",
						)
					}

					a, err := application.MaterializeApplicationFromFrame(parent)
					if err != nil {
						return errors.Wrap(err, "verify execution")
					}

					a, _, _, err = a.ApplyTransition(frame.FrameNumber, transition, false)
					if err != nil {
						return errors.Wrap(err, "verify execution")
					}

					a2, err := application.MaterializeApplicationFromFrame(frame)
					if err != nil {
						return errors.Wrap(err, "verify execution")
					}

					if !a.Equals(a2) {
						return errors.Wrap(
							application.ErrInvalidStateTransition,
							"verify execution",
						)
					}

					return nil
				}
			}
		}
	}

	return nil
}

func (e *CeremonyExecutionEngine) publishTranscript(
	app *application.CeremonyApplication,
) error {
	e.logger.Info("publishing updated transcript")
	e.alreadyPublishedTranscript = true
	err := errors.Wrap(
		e.publishMessage(
			e.intrinsicFilter,
			app.UpdatedTranscript,
		),
		"publish transcript share",
	)
	if err != nil {
		e.alreadyPublishedTranscript = false
		return err
	} else {
		return nil
	}
}

func (e *CeremonyExecutionEngine) ensureSecrets(
	app *application.CeremonyApplication,
) {
	if len(e.activeSecrets) == 0 {
		e.activeSecrets = []curves.Scalar{}
		t := curves.BLS48581G1().Scalar.Random(rand.Reader)
		x := t.Clone()

		for i := 0; i < len(app.LatestTranscript.G1Powers)-1; i++ {
			if i%1000 == 0 {
				e.logger.Info(
					"calculating secrets for contribution",
					zap.Int("secrets_calculated", i),
					zap.Int("total_secrets", len(app.LatestTranscript.G1Powers)-1),
				)
			}
			e.activeSecrets = append(e.activeSecrets, x)
			x = x.Mul(t)
		}

		e.logger.Info(
			"done preparing contribution",
			zap.Int("secrets_calculated", len(e.activeSecrets)),
		)
	}
}

func (e *CeremonyExecutionEngine) GetPeerInfo() *protobufs.PeerInfoResponse {
	return e.clock.GetPeerInfo()
}

func (e *CeremonyExecutionEngine) GetFrame() *protobufs.ClockFrame {
	return e.clock.GetFrame()
}
