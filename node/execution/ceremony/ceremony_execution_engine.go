package ceremony

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
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
	"source.quilibrium.com/quilibrium/monorepo/node/config"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus/ceremony"
	qcrypto "source.quilibrium.com/quilibrium/monorepo/node/crypto"
	"source.quilibrium.com/quilibrium/monorepo/node/execution"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/ceremony/application"
	"source.quilibrium.com/quilibrium/monorepo/node/keys"
	"source.quilibrium.com/quilibrium/monorepo/node/p2p"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/node/store"
)

type CeremonyExecutionEngine struct {
	logger                     *zap.Logger
	clock                      *ceremony.CeremonyDataClockConsensusEngine
	clockStore                 store.ClockStore
	keyStore                   store.KeyStore
	keyManager                 keys.KeyManager
	engineConfig               *config.EngineConfig
	pubSub                     p2p.PubSub
	provingKey                 crypto.Signer
	proverPublicKey            []byte
	provingKeyAddress          []byte
	participantMx              sync.Mutex
	peerChannels               map[string]*p2p.PublicP2PChannel
	activeSecrets              []curves.Scalar
	activeClockFrame           *protobufs.ClockFrame
	alreadyPublishedShare      bool
	alreadyPublishedTranscript bool
	seenMessageMap             map[string]bool
	seenMessageMx              sync.Mutex
}

func NewCeremonyExecutionEngine(
	logger *zap.Logger,
	clock *ceremony.CeremonyDataClockConsensusEngine,
	engineConfig *config.EngineConfig,
	keyManager keys.KeyManager,
	pubSub p2p.PubSub,
	clockStore store.ClockStore,
	keyStore store.KeyStore,
) *CeremonyExecutionEngine {
	if logger == nil {
		panic(errors.New("logger is nil"))
	}

	e := &CeremonyExecutionEngine{
		logger:                logger,
		clock:                 clock,
		engineConfig:          engineConfig,
		keyManager:            keyManager,
		clockStore:            clockStore,
		keyStore:              keyStore,
		pubSub:                pubSub,
		participantMx:         sync.Mutex{},
		peerChannels:          map[string]*p2p.PublicP2PChannel{},
		alreadyPublishedShare: false,
		seenMessageMx:         sync.Mutex{},
		seenMessageMap:        map[string]bool{},
	}

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

// Start implements ExecutionEngine
func (e *CeremonyExecutionEngine) Start() <-chan error {
	errChan := make(chan error)

	e.logger.Info("ceremony data loaded", zap.Binary(
		"g2_power",
		qcrypto.CeremonyBLS48581G2[1].ToAffineCompressed(),
	))

	go func() {
		seed, err := hex.DecodeString(e.engineConfig.GenesisSeed)
		if err != nil {
			panic(err)
		}

		err = <-e.clock.Start(
			application.CEREMONY_ADDRESS,
			seed,
		)
		if err != nil {
			panic(err)
		}

		err = <-e.clock.RegisterExecutor(e, 0)
		if err != nil {
			panic(err)
		}

		go func() {
			e.RunWorker()
		}()

		errChan <- nil
	}()

	return errChan
}

// Stop implements ExecutionEngine
func (*CeremonyExecutionEngine) Stop(force bool) <-chan error {
	errChan := make(chan error)

	go func() {
		errChan <- nil
	}()

	return errChan
}

// ProcessMessage implements ExecutionEngine
func (e *CeremonyExecutionEngine) ProcessMessage(
	address []byte,
	message *protobufs.Message,
) ([]*protobufs.Message, error) {
	if bytes.Equal(address, e.GetSupportedApplications()[0].Address) {
		e.logger.Info("processing execution message")
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

			if frame.FrameNumber < e.clock.GetFrame() {
				return nil, nil
			}

			if err := frame.VerifyDataClockFrame(); err != nil {
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
			frame := e.activeClockFrame
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
				app, err := application.MaterializeApplicationFromFrame(frame)
				if err != nil {
					return nil, errors.Wrap(err, "process message")
				}
				proposedTransition := &protobufs.CeremonyLobbyStateTransition{
					TypeUrls: []string{any.TypeUrl},
					TransitionInputs: [][]byte{
						any.Value,
					},
				}

				_, err = app.ApplyTransition(frame.FrameNumber, proposedTransition)
				if err != nil {
					return nil, errors.Wrap(err, "process message")
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
		frameFromBuffer := <-frameChan
		frame := e.clock.GetActiveFrame()
		e.activeClockFrame = frame
		e.logger.Info(
			"evaluating next frame",
			zap.Int(
				"last_run_took_frames",
				int(frame.FrameNumber)-int(frameFromBuffer.FrameNumber),
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
		e.logger.Info(
			"current application state",
			zap.Uint64("my_balance", reward),
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
				zap.Int("preferred_participants", len(app.NextRoundPreferredParticipants)),
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
				if bytes.Equal(p.KeyValue, e.proverPublicKey) {
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
				zap.Any("current_seen_attestations", len(app.LatestSeenProverAttestations)),
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
			)

			shouldConnect := false
			position := 0
			if len(e.peerChannels) == 0 && app.RoundCount == 1 &&
				len(app.ActiveParticipants) > 1 {
				for i, p := range app.ActiveParticipants {
					if bytes.Equal(p.KeyValue, e.proverPublicKey) {
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
				bytes.Equal(app.ActiveParticipants[0].KeyValue, e.proverPublicKey) {
				if err = e.commitRound(e.activeSecrets); err != nil {
					e.logger.Error("error while participating in round", zap.Error(err))
				}
			}
		case application.CEREMONY_APPLICATION_STATE_FINALIZING:
			e.logger.Info(
				"round contribution finalizing",
				zap.Any("participants", len(app.ActiveParticipants)),
				zap.Any("current_seen_attestations", len(app.LatestSeenProverAttestations)),
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
				if bytes.Equal(p.KeyValue, e.proverPublicKey) {
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
			// Do a best effort to clear – Go's GC is noisy and unenforceable, but
			// this should at least mark it as dead space
			e.activeSecrets = []curves.Scalar{}
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
			application.CEREMONY_ADDRESS,
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

	for i, p := range app.ActiveParticipants {
		if !bytes.Equal(p.KeyValue, e.proverPublicKey) {
			ic, err := e.keyStore.GetLatestKeyBundle(p.KeyValue)
			if err != nil {
				return errors.Wrap(err, "connect to active peers")
			}

			var kba *protobufs.KeyBundleAnnouncement
			switch ic.TypeUrl {
			case protobufs.KeyBundleAnnouncementType:
				kba = &protobufs.KeyBundleAnnouncement{}
				if err := proto.Unmarshal(
					ic.Data,
					kba,
				); err != nil {
					return errors.Wrap(err, "connect to active peers")
				}
			}

			receiverIdk, err := curves.ED448().Point.FromAffineCompressed(
				kba.IdentityKey.GetPublicKeySignatureEd448().PublicKey.KeyValue,
			)
			if err != nil {
				return errors.Wrap(err, "connect to active peers")
			}

			receiverSpk, err := curves.ED448().Point.FromAffineCompressed(
				kba.SignedPreKey.GetPublicKeySignatureEd448().PublicKey.KeyValue,
			)
			if err != nil {
				return errors.Wrap(err, "connect to active peers")
			}

			client, err := e.clock.GetPublicChannelForProvingKey(
				i > position,
				p.KeyValue,
			)
			if err != nil {
				e.logger.Error(
					"peer does not support direct public channels",
					zap.Binary("proving_key", p.KeyValue),
					zap.Error(err),
				)
			}
			e.peerChannels[string(p.KeyValue)], err = p2p.NewPublicP2PChannel(
				client,
				e.proverPublicKey,
				p.KeyValue,
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
		if !bytes.Equal(p.KeyValue, e.proverPublicKey) {
			ic, err := e.keyStore.GetLatestKeyBundle(p.KeyValue)
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

			if _, ok := e.peerChannels[string(p.KeyValue)]; !ok {
				client, err := e.clock.GetPublicChannelForProvingKey(
					initiator,
					p.KeyValue,
				)
				if err != nil {
					e.logger.Error(
						"peer does not support direct public channels",
						zap.Binary("proving_key", p.KeyValue),
						zap.Error(err),
					)
				}
				e.peerChannels[string(p.KeyValue)], err = p2p.NewPublicP2PChannel(
					client,
					e.proverPublicKey,
					p.KeyValue,
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
		pubKeys = append(pubKeys, p.KeyValue)
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
		application.CEREMONY_ADDRESS,
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
	frameNumber := e.clock.GetFrame()

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
		application.CEREMONY_ADDRESS,
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
	frameNumber := e.clock.GetFrame()

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
		application.CEREMONY_ADDRESS,
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
			application.CEREMONY_ADDRESS,
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
	if e.clock.GetFrame() != frame.FrameNumber-1 {
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

					parent, err := e.clockStore.GetParentDataClockFrame(
						application.CEREMONY_ADDRESS,
						frame.FrameNumber-1,
						frame.ParentSelector,
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

					a, err = a.ApplyTransition(frame.FrameNumber, transition)
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
			application.CEREMONY_ADDRESS,
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
