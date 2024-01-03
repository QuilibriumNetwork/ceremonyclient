package ceremony

import (
	"bytes"
	"encoding/binary"
	"strings"
	"time"

	"github.com/iden3/go-iden3-crypto/poseidon"
	pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"golang.org/x/crypto/sha3"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"source.quilibrium.com/quilibrium/monorepo/go-libp2p-blossomsub/pb"
	"source.quilibrium.com/quilibrium/monorepo/nekryptology/pkg/core/curves"
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

		if p.PublicKey == nil || p.Signature == nil || p.Version == nil {
			if time.Now().After(consensus.GetMinimumVersionCutoff()) {
				if bytes.Equal(p.PeerId, peerID) {
					e.logger.Warn(
						"peer provided outdated version, penalizing app score",
						zap.Binary("peer_id", p.PeerId),
					)
					e.pubSub.SetPeerScore(p.PeerId, -100)
				}
				continue
			}
		}

		if p.PublicKey != nil && p.Signature != nil && p.Version != nil {
			key, err := pcrypto.UnmarshalEd448PublicKey(p.PublicKey)
			if err != nil {
				e.logger.Error(
					"peer announcement contained invalid pubkey",
					zap.Binary("public_key", p.PublicKey),
				)
				continue
			}

			if !(peer.ID(p.PeerId)).MatchesPublicKey(key) {
				e.logger.Error(
					"peer announcement peer id does not match pubkey",
					zap.Binary("peer_id", p.PeerId),
					zap.Binary("public_key", p.PublicKey),
				)
				continue
			}

			msg := binary.BigEndian.AppendUint64([]byte{}, p.MaxFrame)
			msg = append(msg, p.Version...)
			msg = binary.BigEndian.AppendUint64(msg, uint64(p.Timestamp))
			b, err := key.Verify(msg, p.Signature)
			if err != nil || !b {
				e.logger.Error(
					"peer provided invalid signature",
					zap.Binary("msg", msg),
					zap.Binary("public_key", p.PublicKey),
					zap.Binary("signature", p.Signature),
				)
				continue
			}

			if bytes.Compare(p.Version, consensus.GetMinimumVersion()) < 0 &&
				time.Now().After(consensus.GetMinimumVersionCutoff()) {
				e.logger.Warn(
					"peer provided outdated version, penalizing app score",
					zap.Binary("peer_id", p.PeerId),
				)
				e.pubSub.SetPeerScore(p.PeerId, -100)
				continue
			}
		}

		multiaddr := e.pubSub.GetMultiaddrOfPeer(p.PeerId)

		e.pubSub.SetPeerScore(p.PeerId, 10)
		existing, ok := e.peerMap[string(p.PeerId)]
		if ok {
			if existing.signature != nil && p.Signature == nil {
				continue
			}

			if existing.publicKey != nil && p.PublicKey == nil {
				continue
			}

			if existing.version != nil && p.Version == nil {
				continue
			}

			if existing.timestamp > p.Timestamp {
				continue
			}
		}

		e.peerMap[string(p.PeerId)] = &peerInfo{
			peerId:    p.PeerId,
			multiaddr: multiaddr,
			maxFrame:  p.MaxFrame,
			direct:    bytes.Equal(p.PeerId, peerID),
			lastSeen:  time.Now().Unix(),
			timestamp: p.Timestamp,
			version:   p.Version,
			signature: p.Signature,
			publicKey: p.PublicKey,
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
	masterFrame, err := e.clockStore.GetMasterClockFrame(
		[]byte{
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		},
		frame.FrameNumber-1,
	)
	if err != nil {
		e.logger.Info("received frame with no known master, needs sync")
		return nil
	}

	discriminator, err := masterFrame.GetSelector()
	if err != nil {
		return errors.Wrap(err, "handle clock frame data")
	}

	parentSelector, distance, selector, err :=
		frame.GetParentSelectorAndDistance(discriminator)
	if err != nil {
		return errors.Wrap(err, "handle clock frame data")
	}

	if _, err := e.clockStore.GetParentDataClockFrame(
		frame.Filter,
		frame.FrameNumber-1,
		frame.ParentSelector,
	); errors.Is(err, store.ErrNotFound) {
		// If this is a frame number higher than what we're already caught up to,
		// push a request to fill the gap, unless we're syncing or it's in step,
		// then just lazily seek.
		from := e.frame.FrameNumber
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
		parentSelector.FillBytes(make([]byte, 32)),
		distance.FillBytes(make([]byte, 32)),
		selector.FillBytes(make([]byte, 32)),
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

	if e.frame.FrameNumber < frame.FrameNumber {
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
