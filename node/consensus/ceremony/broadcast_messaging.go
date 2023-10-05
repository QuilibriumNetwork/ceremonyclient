package ceremony

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"strings"
	"time"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"golang.org/x/crypto/sha3"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"source.quilibrium.com/quilibrium/monorepo/go-libp2p-blossomsub/pb"
	"source.quilibrium.com/quilibrium/monorepo/nekryptology/pkg/core/curves"
	"source.quilibrium.com/quilibrium/monorepo/nekryptology/pkg/zkp/schnorr"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus"
	qcrypto "source.quilibrium.com/quilibrium/monorepo/node/crypto"
	"source.quilibrium.com/quilibrium/monorepo/node/keys"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/node/store"
)

func (e *CeremonyDataClockConsensusEngine) handleMessage(
	message *pb.Message,
) error {
	e.logger.Debug(
		"received message",
		zap.Binary("data", message.Data),
		zap.Binary("from", message.From),
		zap.Binary("signature", message.Signature),
	)
	msg := &protobufs.Message{}

	if err := proto.Unmarshal(message.Data, msg); err != nil {
		return errors.Wrap(err, "handle message")
	}

	eg := errgroup.Group{}
	eg.SetLimit(len(e.executionEngines))

	for name := range e.executionEngines {
		name := name
		eg.Go(func() error {
			messages, err := e.executionEngines[name].ProcessMessage(
				msg.Address,
				msg,
			)
			if err != nil {
				e.logger.Debug(
					"could not process message for engine",
					zap.Error(err),
					zap.String("engine_name", name),
				)
				return errors.Wrap(err, "handle message")
			}

			for _, appMessage := range messages {
				appMsg := &anypb.Any{}
				err := proto.Unmarshal(appMessage.Payload, appMsg)
				if err != nil {
					e.logger.Error(
						"could not unmarshal app message",
						zap.Error(err),
						zap.String("engine_name", name),
					)
					return errors.Wrap(err, "handle message")
				}

				switch appMsg.TypeUrl {
				case protobufs.CeremonyLobbyStateTransitionType:
					t := &protobufs.CeremonyLobbyStateTransition{}
					err := proto.Unmarshal(appMsg.Value, t)
					if err != nil {
						return errors.Wrap(err, "handle message")
					}

					if err := e.handleCeremonyLobbyStateTransition(t); err != nil {
						return errors.Wrap(err, "handle message")
					}
				}
			}

			return nil
		})
	}

	if err := eg.Wait(); err != nil {
		e.logger.Debug("rejecting invalid message", zap.Error(err))
		return nil
	}

	any := &anypb.Any{}
	if err := proto.Unmarshal(msg.Payload, any); err != nil {
		return errors.Wrap(err, "handle message")
	}

	switch any.TypeUrl {
	case protobufs.ClockFrameType:
		if err := e.handleClockFrameData(
			message.From,
			msg.Address,
			any,
			false,
		); err != nil {
			return errors.Wrap(err, "handle message")
		}
	case protobufs.ProvingKeyRequestType:
		if err := e.handleProvingKeyRequest(
			message.From,
			msg.Address,
			any,
		); err != nil {
			return errors.Wrap(err, "handle message")
		}
	case protobufs.ProvingKeyAnnouncementType:
		if err := e.handleProvingKey(message.From, msg.Address, any); err != nil {
			return errors.Wrap(err, "handle message")
		}
	case protobufs.KeyBundleAnnouncementType:
		if err := e.handleKeyBundle(message.From, msg.Address, any); err != nil {
			return errors.Wrap(err, "handle message")
		}
	case protobufs.CeremonyPeerListAnnounceType:
		if err := e.handleCeremonyPeerListAnnounce(
			message.From,
			msg.Address,
			any,
		); err != nil {
			return errors.Wrap(err, "handle message")
		}
	}

	return nil
}

func (e *CeremonyDataClockConsensusEngine) handleCeremonyPeerListAnnounce(
	peerID []byte,
	address []byte,
	any *anypb.Any,
) error {
	if bytes.Equal(peerID, e.pubSub.GetPeerID()) {
		return nil
	}

	announce := &protobufs.CeremonyPeerListAnnounce{}
	if err := any.UnmarshalTo(announce); err != nil {
		return errors.Wrap(err, "handle ceremony peer list announce")
	}

	e.peerAnnounceMapMx.Lock()
	e.peerAnnounceMap[string(peerID)] = announce
	e.peerAnnounceMapMx.Unlock()

	e.peerMapMx.Lock()
	for _, p := range announce.PeerList {
		if _, ok := e.uncooperativePeersMap[string(p.PeerId)]; ok {
			continue
		}

		if bytes.Equal(p.PeerId, e.pubSub.GetPeerID()) {
			continue
		}

		pr, ok := e.peerMap[string(p.PeerId)]
		if !ok {
			if bytes.Equal(p.PeerId, peerID) {
				e.peerMap[string(p.PeerId)] = &peerInfo{
					peerId:    p.PeerId,
					multiaddr: e.pubSub.GetMultiaddrOfPeer(peerID),
					maxFrame:  p.MaxFrame,
					direct:    bytes.Equal(p.PeerId, peerID),
					lastSeen:  time.Now().Unix(),
				}
			} else {
				e.peerMap[string(p.PeerId)] = &peerInfo{
					peerId:    p.PeerId,
					multiaddr: p.Multiaddr,
					maxFrame:  p.MaxFrame,
					direct:    bytes.Equal(p.PeerId, peerID),
					lastSeen:  time.Now().Unix(),
				}
			}
		} else {
			if bytes.Equal(p.PeerId, peerID) {
				e.peerMap[string(p.PeerId)] = &peerInfo{
					peerId:    p.PeerId,
					multiaddr: e.pubSub.GetMultiaddrOfPeer(peerID),
					maxFrame:  p.MaxFrame,
					direct:    bytes.Equal(p.PeerId, peerID),
					lastSeen:  time.Now().Unix(),
				}
			} else {
				if pr.direct {
					dst := int64(p.MaxFrame) - int64(pr.maxFrame)
					if time.Now().Unix()-pr.lastSeen > 30 {
						e.peerMap[string(p.PeerId)] = &peerInfo{
							peerId:    p.PeerId,
							multiaddr: p.Multiaddr,
							maxFrame:  p.MaxFrame,
							direct:    false,
							lastSeen:  time.Now().Unix(),
						}
					} else if dst > 4 {
						e.logger.Warn(
							"peer sent announcement with higher frame index for peer",
							zap.String("sender_peer", peer.ID(peerID).String()),
							zap.String("announced_peer", peer.ID(pr.peerId).String()),
							zap.Int64("frame_distance", dst),
						)
					} else if dst < -4 {
						e.logger.Debug(
							"peer sent announcement with lower frame index for peer",
							zap.String("sender_peer", peer.ID(peerID).String()),
							zap.String("announced_peer", peer.ID(pr.peerId).String()),
							zap.Int64("frame_distance", dst),
						)
					} else {
						e.peerMap[string(p.PeerId)] = &peerInfo{
							peerId:    p.PeerId,
							multiaddr: p.Multiaddr,
							maxFrame:  p.MaxFrame,
							direct:    false,
							lastSeen:  time.Now().Unix(),
						}
					}
				} else {
					e.peerMap[string(p.PeerId)] = &peerInfo{
						peerId:    p.PeerId,
						multiaddr: p.Multiaddr,
						maxFrame:  p.MaxFrame,
						direct:    false,
						lastSeen:  time.Now().Unix(),
					}
				}
			}
		}
	}
	e.peerMapMx.Unlock()

	return nil
}

func (e *CeremonyDataClockConsensusEngine) handleCeremonyLobbyStateTransition(
	transition *protobufs.CeremonyLobbyStateTransition,
) error {
	if len(transition.TransitionInputs) != len(transition.TypeUrls) {
		return errors.Wrap(
			errors.New("invalid state transition"),
			"handle ceremony lobby state transition",
		)
	}

	e.stagedLobbyStateTransitionsMx.Lock()
	if e.stagedLobbyStateTransitions == nil {
		e.stagedLobbyStateTransitions = &protobufs.CeremonyLobbyStateTransition{}
	}

	found := false
	for _, ti := range e.stagedLobbyStateTransitions.TransitionInputs {
		for _, nti := range transition.TransitionInputs {
			if bytes.Equal(ti, nti) {
				found = true
			}
		}
	}

	if !found {
		for i := range transition.TransitionInputs {
			e.stagedLobbyStateTransitions.TypeUrls = append(
				e.stagedLobbyStateTransitions.TypeUrls,
				transition.TypeUrls[i],
			)
			e.stagedLobbyStateTransitions.TransitionInputs = append(
				e.stagedLobbyStateTransitions.TransitionInputs,
				transition.TransitionInputs[i],
			)
		}
	}
	e.stagedLobbyStateTransitionsMx.Unlock()
	return nil
}

func (e *CeremonyDataClockConsensusEngine) handleKeyBundle(
	peerID []byte,
	address []byte,
	any *anypb.Any,
) error {
	e.logger.Debug("received key bundle")
	keyBundleAnnouncement := &protobufs.KeyBundleAnnouncement{}
	if err := any.UnmarshalTo(keyBundleAnnouncement); err != nil {
		return errors.Wrap(err, "handle key bundle")
	}

	if len(keyBundleAnnouncement.ProvingKeyBytes) == 0 {
		return errors.Wrap(errors.New("proving key is nil"), "handle key bundle")
	}

	k, err := e.keyStore.GetLatestKeyBundle(keyBundleAnnouncement.ProvingKeyBytes)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return errors.Wrap(err, "handle key bundle")
	}

	if k != nil {
		latestAnnouncement := &protobufs.KeyBundleAnnouncement{}
		err := proto.Unmarshal(k.Data, latestAnnouncement)
		if err != nil {
			return errors.Wrap(err, "handle key bundle")
		}

		if bytes.Equal(
			latestAnnouncement.IdentityKey.Challenge,
			keyBundleAnnouncement.IdentityKey.Challenge,
		) && bytes.Equal(
			latestAnnouncement.IdentityKey.Response,
			keyBundleAnnouncement.IdentityKey.Response,
		) && bytes.Equal(
			latestAnnouncement.IdentityKey.Statement,
			keyBundleAnnouncement.IdentityKey.Statement,
		) && bytes.Equal(
			latestAnnouncement.SignedPreKey.Challenge,
			keyBundleAnnouncement.SignedPreKey.Challenge,
		) && bytes.Equal(
			latestAnnouncement.SignedPreKey.Response,
			keyBundleAnnouncement.SignedPreKey.Response,
		) && bytes.Equal(
			latestAnnouncement.SignedPreKey.Statement,
			keyBundleAnnouncement.SignedPreKey.Statement,
		) {
			// This has already been proven, ignore
			return nil
		}
	}

	var provingKey *protobufs.ProvingKeyAnnouncement
	inclusion, err := e.keyStore.GetProvingKey(
		keyBundleAnnouncement.ProvingKeyBytes,
	)
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			return errors.Wrap(err, "handle key bundle")
		}

		provingKey, err = e.keyStore.GetStagedProvingKey(
			keyBundleAnnouncement.ProvingKeyBytes,
		)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return errors.Wrap(err, "handle key bundle")
		}
	} else {
		err := proto.Unmarshal(inclusion.Data, provingKey)
		if err != nil {
			return errors.Wrap(err, "handle key bundle")
		}
	}

	// We have a matching proving key, we can set this up to be committed.
	if provingKey != nil {
		e.logger.Debug("verifying key bundle announcement")
		if err := keyBundleAnnouncement.Verify(provingKey); err != nil {
			e.logger.Debug(
				"could not verify key bundle announcement",
				zap.Error(err),
			)
			return nil
		}

		go func() {
			e.logger.Debug("adding key bundle announcement to pending commits")

			e.pendingCommits <- any
		}()

		return nil
	} else {
		e.logger.Debug("proving key not found, requesting from peers")

		if err = e.publishMessage(e.filter, &protobufs.ProvingKeyRequest{
			ProvingKeyBytes: keyBundleAnnouncement.ProvingKeyBytes,
		}); err != nil {
			return errors.Wrap(err, "handle key bundle")
		}

		e.dependencyMapMx.Lock()
		e.dependencyMap[string(keyBundleAnnouncement.ProvingKeyBytes)] = any
		e.dependencyMapMx.Unlock()
	}

	return nil
}

func (e *CeremonyDataClockConsensusEngine) handleProvingKey(
	peerID []byte,
	address []byte,
	any *anypb.Any,
) error {
	e.logger.Debug("received proving key")

	provingKeyAnnouncement := &protobufs.ProvingKeyAnnouncement{}
	if err := any.UnmarshalTo(provingKeyAnnouncement); err != nil {
		return errors.Wrap(err, "handle proving key")
	}

	if err := provingKeyAnnouncement.Verify(); err != nil {
		return errors.Wrap(err, "handle proving key")
	}

	if err := e.keyStore.StageProvingKey(provingKeyAnnouncement); err != nil {
		return errors.Wrap(err, "handle proving key")
	}

	provingKey := provingKeyAnnouncement.PublicKey()

	e.logger.Debug(
		"proving key staged",
		zap.Binary("proving_key", provingKey),
	)

	if e.dependencyMap[string(provingKey)] != nil {
		go func() {
			keyBundleAnnouncement := &protobufs.KeyBundleAnnouncement{}
			if err := proto.Unmarshal(
				e.dependencyMap[string(provingKey)].Value,
				keyBundleAnnouncement,
			); err != nil {
				e.logger.Error(
					"could not unmarshal key bundle announcement",
					zap.Error(err),
				)
			}
			if err := keyBundleAnnouncement.Verify(
				provingKeyAnnouncement,
			); err != nil {
				e.logger.Error(
					"could not verify key bundle announcement",
					zap.Error(err),
				)
			}

			e.pendingCommits <- e.dependencyMap[string(provingKey)]

			e.dependencyMapMx.Lock()
			delete(e.dependencyMap, string(provingKey))
			e.dependencyMapMx.Unlock()
		}()
	}

	return nil
}

func (e *CeremonyDataClockConsensusEngine) handleClockFrameData(
	peerID []byte,
	address []byte,
	any *anypb.Any,
	isSync bool,
) error {
	if isSync && bytes.Equal(peerID, e.pubSub.GetPeerID()) {
		return nil
	}

	frame := &protobufs.ClockFrame{}
	if err := any.UnmarshalTo(frame); err != nil {
		return errors.Wrap(err, "handle clock frame data")
	}

	addr, err := poseidon.HashBytes(
		frame.GetPublicKeySignatureEd448().PublicKey.KeyValue,
	)
	if err != nil {
		return errors.Wrap(err, "handle clock frame data")
	}

	earliestFrame, _, count := e.frameProverTrie.Get(addr.Bytes())
	_, latestFrame, _ := e.frameSeenProverTrie.Get(addr.Bytes())
	if !isSync && frame.FrameNumber == latestFrame {
		e.logger.Info(
			"already received frame from address",
			zap.Binary("address", address),
			zap.Binary("filter", frame.Filter),
			zap.Uint64("frame_number", frame.FrameNumber),
		)
		return nil
	} else if frame.FrameNumber <= earliestFrame || count == 0 {
		e.logger.Info(
			"prover not in trie at frame, address may be in fork",
			zap.Binary("address", address),
			zap.Binary("filter", frame.Filter),
			zap.Uint64("frame_number", frame.FrameNumber),
		)
		return nil
	}

	e.logger.Info(
		"got clock frame",
		zap.Binary("address", address),
		zap.Binary("filter", frame.Filter),
		zap.Uint64("frame_number", frame.FrameNumber),
		zap.Int("proof_count", len(frame.AggregateProofs)),
	)

	if err := frame.VerifyDataClockFrame(); err != nil {
		e.logger.Error("could not verify clock frame", zap.Error(err))
		return errors.Wrap(err, "handle clock frame data")
	}

	aggregateCommitments := []curves.PairingPoint{}
	for i := 0; i < (len(frame.Input)-516)/74; i++ {
		c, err := curves.BLS48581G1().NewGeneratorPoint().FromAffineCompressed(
			frame.Input[516+(i*74) : 516+(i*74)+74],
		)
		if err != nil {
			e.logger.Error("could not verify clock frame", zap.Error(err))
			return errors.Wrap(err, "handle clock frame data")
		}
		aggregateCommitments = append(aggregateCommitments, c.(curves.PairingPoint))
	}

	for i, proof := range frame.AggregateProofs {
		aggregatePoly := [][]curves.PairingScalar{}
		commitments := []curves.PairingPoint{}

		for _, commit := range proof.GetInclusionCommitments() {
			switch commit.TypeUrl {
			case protobufs.IntrinsicExecutionOutputType:
				e.logger.Debug("confirming inclusion in aggregate")
				digest := sha3.NewShake256()
				_, err := digest.Write(commit.Data)
				if err != nil {
					e.logger.Error(
						"error converting key bundle to polynomial",
						zap.Error(err),
					)
					return errors.Wrap(err, "handle clock frame data")
				}

				expand := make([]byte, 1024)
				_, err = digest.Read(expand)
				if err != nil {
					e.logger.Error(
						"error converting key bundle to polynomial",
						zap.Error(err),
					)
					return errors.Wrap(err, "handle clock frame data")
				}

				poly, err := e.prover.BytesToPolynomial(expand)
				if err != nil {
					e.logger.Error(
						"error converting key bundle to polynomial",
						zap.Error(err),
					)
					return errors.Wrap(err, "handle clock frame data")
				}

				evalPoly, err := qcrypto.FFT(
					poly,
					*curves.BLS48581(
						curves.BLS48581G1().NewGeneratorPoint(),
					),
					16,
					false,
				)
				if err != nil {
					e.logger.Error(
						"error performing fast fourier transform on key bundle",
						zap.Error(err),
					)
					return errors.Wrap(err, "handle clock frame data")
				}
				e.logger.Debug(
					"created fft of polynomial",
					zap.Int("poly_size", len(evalPoly)),
				)

				aggregatePoly = append(aggregatePoly, evalPoly)

				c, err := curves.BLS48581G1().NewGeneratorPoint().FromAffineCompressed(
					commit.Commitment,
				)
				if err != nil {
					e.logger.Error("could not verify clock frame", zap.Error(err))
					return errors.Wrap(err, "handle clock frame data")
				}
				commitments = append(commitments, c.(curves.PairingPoint))
			default:
				e.logger.Debug("confirming inclusion in aggregate")
				poly, err := e.prover.BytesToPolynomial(commit.Data)
				if err != nil {
					e.logger.Error(
						"error converting key bundle to polynomial",
						zap.Error(err),
					)
					return errors.Wrap(err, "handle clock frame data")
				}

				for i := 0; i < 128-len(poly); i++ {
					poly = append(
						poly,
						curves.BLS48581G1().Scalar.Zero().(curves.PairingScalar),
					)
				}

				evalPoly, err := qcrypto.FFT(
					poly,
					*curves.BLS48581(
						curves.BLS48581G1().NewGeneratorPoint(),
					),
					128,
					false,
				)
				if err != nil {
					e.logger.Error(
						"error performing fast fourier transform on key bundle",
						zap.Error(err),
					)
					return errors.Wrap(err, "handle clock frame data")
				}
				e.logger.Debug(
					"created fft of polynomial",
					zap.Int("poly_size", len(evalPoly)),
				)

				aggregatePoly = append(aggregatePoly, evalPoly)

				c, err := curves.BLS48581G1().NewGeneratorPoint().FromAffineCompressed(
					commit.Commitment,
				)
				if err != nil {
					e.logger.Error("could not verify clock frame", zap.Error(err))
					return errors.Wrap(err, "handle clock frame data")
				}
				commitments = append(commitments, c.(curves.PairingPoint))
			}
		}

		p, err := curves.BLS48581G1().Point.FromAffineCompressed(
			proof.Proof,
		)
		if err != nil {
			e.logger.Error("could not verify clock frame", zap.Error(err))
			return errors.Wrap(err, "handle clock frame data")
		}

		result, err := e.prover.VerifyAggregateProof(
			aggregatePoly,
			commitments,
			aggregateCommitments[i],
			p.(curves.PairingPoint),
		)
		if err != nil {
			e.logger.Error("could not verify clock frame", zap.Error(err))
			return errors.Wrap(err, "handle clock frame data")
		}

		if !result {
			e.logger.Error("could not verify clock frame", zap.Error(err))
			return errors.Wrap(
				errors.New("invalid proof"),
				"handle clock frame data",
			)
		}
	}

	e.logger.Info(
		"clock frame was valid",
		zap.Binary("address", address),
		zap.Binary("filter", frame.Filter),
		zap.Uint64("frame_number", frame.FrameNumber),
	)

	parentSelector, selector, distance, err :=
		frame.GetParentSelectorAndDistance()
	if err != nil {
		return errors.Wrap(err, "handle clock frame data")
	}
	e.logger.Debug(
		"difference between selector/discriminator",
		zap.Binary("difference", distance.Bytes()),
	)

	if _, err := e.clockStore.GetParentDataClockFrame(
		frame.Filter,
		frame.FrameNumber-1,
		frame.ParentSelector,
	); errors.Is(err, store.ErrNotFound) {
		// If this is a frame number higher than what we're already caught up to,
		// push a request to fill the gap, unless we're syncing or it's in step,
		// then just lazily seek.
		from := e.frame
		if from >= frame.FrameNumber-1 {
			from = frame.FrameNumber - 1
		}

		if err := e.publishMessage(e.filter, &protobufs.ClockFramesRequest{
			Filter:          e.filter,
			FromFrameNumber: from,
			ToFrameNumber:   frame.FrameNumber,
		}); err != nil {
			e.logger.Error(
				"could not publish clock frame parent request, skipping",
				zap.Error(err),
			)
		}
	}

	txn, err := e.clockStore.NewTransaction()
	if err != nil {
		e.logger.Error("could not save candidate clock frame", zap.Error(err))
		return errors.Wrap(err, "handle clock frame data")
	}

	if err := e.clockStore.PutCandidateDataClockFrame(
		parentSelector.Bytes(),
		distance.Bytes(),
		selector.Bytes(),
		frame,
		txn,
	); err != nil {
		e.logger.Error("could not save candidate clock frame", zap.Error(err))
		return errors.Wrap(err, "handle clock frame data")
	}

	if err := txn.Commit(); err != nil {
		e.logger.Error("could not save candidate clock frame", zap.Error(err))
		return errors.Wrap(err, "handle clock frame data")
	}

	if e.frame < frame.FrameNumber {
		e.latestFrameReceived = frame.FrameNumber
		e.lastFrameReceivedAt = time.Now().UTC()
	}
	e.frameSeenProverTrie.Add(address, frame.FrameNumber)
	return nil
}

func (e *CeremonyDataClockConsensusEngine) publishProof(
	frame *protobufs.ClockFrame,
) error {
	if e.state == consensus.EngineStatePublishing {
		e.logger.Debug(
			"publishing frame and aggregations",
			zap.Uint64("frame_number", frame.FrameNumber),
		)
		if err := e.publishMessage(e.filter, frame); err != nil {
			return errors.Wrap(
				err,
				"publish proof",
			)
		}

		e.state = consensus.EngineStateCollecting
	}

	return nil
}

func (e *CeremonyDataClockConsensusEngine) publishMessage(
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
		Address: e.provingKeyAddress,
		Payload: payload,
	}
	data, err := proto.Marshal(msg)
	if err != nil {
		return errors.Wrap(err, "publish message")
	}
	return e.pubSub.PublishToBitmask(filter, data)
}

func (e *CeremonyDataClockConsensusEngine) announceKeyBundle() error {
	e.logger.Debug("announcing key bundle")
	idk, err := e.keyManager.GetAgreementKey("q-ratchet-idk")
	if err != nil {
		if errors.Is(err, keys.KeyNotFoundErr) {
			idk, err = e.keyManager.CreateAgreementKey(
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

	spk, err := e.keyManager.GetAgreementKey("q-ratchet-spk")
	if err != nil {
		if errors.Is(err, keys.KeyNotFoundErr) {
			spk, err = e.keyManager.CreateAgreementKey(
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

	idkPoint := curves.ED448().NewGeneratorPoint().Mul(idk)
	idkProver := schnorr.NewProver(
		curves.ED448(),
		curves.ED448().NewGeneratorPoint(),
		sha3.New256(),
		[]byte{},
	)

	spkPoint := curves.ED448().NewGeneratorPoint().Mul(spk)
	spkProver := schnorr.NewProver(
		curves.ED448(),
		curves.ED448().NewGeneratorPoint(),
		sha3.New256(),
		[]byte{},
	)

	idkProof, idkCommitment, err := idkProver.ProveCommit(idk)
	if err != nil {
		return errors.Wrap(err, "announce key bundle")
	}

	spkProof, spkCommitment, err := spkProver.ProveCommit(spk)
	if err != nil {
		return errors.Wrap(err, "announce key bundle")
	}

	msg := append(
		append([]byte{}, idkCommitment...),
		spkCommitment...,
	)

	signature, err := e.provingKey.Sign(rand.Reader, msg, crypto.Hash(0))
	if err != nil {
		return errors.Wrap(err, "announce key bundle")
	}

	signatureProto := &protobufs.ProvingKeyAnnouncement_ProvingKeySignatureEd448{
		ProvingKeySignatureEd448: &protobufs.Ed448Signature{
			PublicKey: &protobufs.Ed448PublicKey{
				KeyValue: e.provingKeyBytes,
			},
			Signature: signature,
		},
	}
	provingKeyAnnouncement := &protobufs.ProvingKeyAnnouncement{
		IdentityCommitment:  idkCommitment,
		PrekeyCommitment:    spkCommitment,
		ProvingKeySignature: signatureProto,
	}

	if err := e.publishMessage(e.filter, provingKeyAnnouncement); err != nil {
		return errors.Wrap(err, "announce key bundle")
	}

	idkSignature, err := e.provingKey.Sign(
		rand.Reader,
		idkPoint.ToAffineCompressed(),
		crypto.Hash(0),
	)
	if err != nil {
		return errors.Wrap(err, "announce key bundle")
	}

	spkSignature, err := e.provingKey.Sign(
		rand.Reader,
		spkPoint.ToAffineCompressed(),
		crypto.Hash(0),
	)
	if err != nil {
		return errors.Wrap(err, "announce key bundle")
	}

	keyBundleAnnouncement := &protobufs.KeyBundleAnnouncement{
		ProvingKeyBytes: e.provingKeyBytes,
		IdentityKey: &protobufs.IdentityKey{
			Challenge: idkProof.C.Bytes(),
			Response:  idkProof.S.Bytes(),
			Statement: idkProof.Statement.ToAffineCompressed(),
			IdentityKeySignature: &protobufs.IdentityKey_PublicKeySignatureEd448{
				PublicKeySignatureEd448: &protobufs.Ed448Signature{
					PublicKey: &protobufs.Ed448PublicKey{
						KeyValue: idkPoint.ToAffineCompressed(),
					},
					Signature: idkSignature,
				},
			},
		},
		SignedPreKey: &protobufs.SignedPreKey{
			Challenge: spkProof.C.Bytes(),
			Response:  spkProof.S.Bytes(),
			Statement: spkProof.Statement.ToAffineCompressed(),
			SignedPreKeySignature: &protobufs.SignedPreKey_PublicKeySignatureEd448{
				PublicKeySignatureEd448: &protobufs.Ed448Signature{
					PublicKey: &protobufs.Ed448PublicKey{
						KeyValue: spkPoint.ToAffineCompressed(),
					},
					Signature: spkSignature,
				},
			},
		},
	}

	return errors.Wrap(
		e.publishMessage(e.filter, keyBundleAnnouncement),
		"announce key bundle",
	)
}
