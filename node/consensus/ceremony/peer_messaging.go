package ceremony

import (
	"bytes"
	"time"

	"github.com/pkg/errors"
	"go.uber.org/zap"
	"golang.org/x/crypto/sha3"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"source.quilibrium.com/quilibrium/monorepo/go-libp2p-blossomsub/pb"
	"source.quilibrium.com/quilibrium/monorepo/nekryptology/pkg/core/curves"
	qcrypto "source.quilibrium.com/quilibrium/monorepo/node/crypto"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/node/store"
	"source.quilibrium.com/quilibrium/monorepo/node/tries"
)

func (e *CeremonyDataClockConsensusEngine) handleSync(
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
		return errors.Wrap(err, "handle sync")
	}

	any := &anypb.Any{}
	if err := proto.Unmarshal(msg.Payload, any); err != nil {
		return errors.Wrap(err, "handle sync")
	}

	eg := errgroup.Group{}
	eg.SetLimit(len(e.executionEngines))

	for name := range e.executionEngines {
		name := name
		eg.Go(func() error {
			// if message,err := e.executionEngines[name].ProcessMessage(
			if _, err := e.executionEngines[name].ProcessMessage(
				msg.Address,
				msg,
			); err != nil {
				e.logger.Error(
					"could not process message for engine",
					zap.Error(err),
					zap.String("engine_name", name),
				)
				return err
			}

			return nil
		})
	}

	if err := eg.Wait(); err != nil {
		e.logger.Error("rejecting invalid message", zap.Error(err))
		return errors.Wrap(err, "handle sync")
	}

	switch any.TypeUrl {
	case protobufs.ClockFramesResponseType:
		if err := e.handleClockFramesResponse(
			message.From,
			msg.Address,
			any,
		); err != nil {
			return errors.Wrap(err, "handle sync")
		}
	case protobufs.ClockFramesRequestType:
		if err := e.handleClockFramesRequest(
			message.From,
			msg.Address,
			any,
		); err != nil {
			return errors.Wrap(err, "handle sync")
		}
	case protobufs.ProvingKeyAnnouncementType:
		if err := e.handleProvingKey(
			message.From,
			msg.Address,
			any,
		); err != nil {
			return errors.Wrap(err, "handle sync")
		}
	case protobufs.KeyBundleAnnouncementType:
		if err := e.handleKeyBundle(
			message.From,
			msg.Address,
			any,
		); err != nil {
			return errors.Wrap(err, "handle sync")
		}
	}

	return nil
}

func (e *CeremonyDataClockConsensusEngine) createPeerReceiveChannel(
	peerID []byte,
) []byte {
	return append(
		append(append([]byte{}, e.filter...), peerID...),
		e.pubSub.GetPeerID()...,
	)
}

func (e *CeremonyDataClockConsensusEngine) createPeerSendChannel(
	peerID []byte,
) []byte {
	return append(
		append(append([]byte{}, e.filter...), e.pubSub.GetPeerID()...),
		peerID...,
	)
}

func (e *CeremonyDataClockConsensusEngine) handleClockFramesResponse(
	peerID []byte,
	address []byte,
	any *anypb.Any,
) error {
	if bytes.Equal(address, e.provingKeyAddress) {
		return nil
	}

	if !bytes.Equal(peerID, e.syncingTarget) {
		e.logger.Warn(
			"received clock frames response from unexpected target",
			zap.Binary("peer_id", peerID),
			zap.Binary("expected_peer_id", e.syncingTarget),
		)
		return nil
	}

	e.syncingStatus = SyncStatusSynchronizing

	defer func() { e.syncingStatus = SyncStatusNotSyncing }()

	response := &protobufs.ClockFramesResponse{}
	if err := any.UnmarshalTo(response); err != nil {
		return errors.Wrap(err, "handle clock frames response")
	}

	trieCopyBytes, err := e.frameProverTrie.Serialize()
	if err != nil {
		return errors.Wrap(err, "handle clock frames response")
	}

	trieCopy := &tries.RollingFrecencyCritbitTrie{}
	if err = trieCopy.Deserialize(trieCopyBytes); err != nil {
		return errors.Wrap(err, "handle clock frames response")
	}

	for _, frame := range response.ClockFrames {
		prover, err := frame.GetAddress()
		if err != nil {
			return errors.Wrap(err, "handle clock frames response")
		}

		earliestFrame, _, count := trieCopy.Get(prover)
		if count == 0 || earliestFrame >= frame.FrameNumber {
			return errors.Wrap(
				errors.New("prover not in trie"),
				"handle clock frame response",
			)
		}

		e.logger.Info(
			"processing clock frame",
			zap.Binary("sender_address", address),
			zap.Binary("prover_address", prover),
			zap.Binary("filter", frame.Filter),
			zap.Uint64("frame_number", frame.FrameNumber),
		)

		if err := frame.VerifyDataClockFrame(); err != nil {
			e.logger.Error("could not verify clock frame", zap.Error(err))
			return errors.Wrap(err, "handle clock frame response")
		}

		aggregateCommitments := []curves.PairingPoint{}
		for i := 0; i < (len(frame.Input)-516)/74; i++ {
			c, err := curves.BLS48581G1().NewGeneratorPoint().FromAffineCompressed(
				frame.Input[516+(i*74) : 516+(i*74)+74],
			)
			if err != nil {
				e.logger.Error("could not verify clock frame", zap.Error(err))
				return errors.Wrap(err, "handle clock frame response")
			}
			aggregateCommitments = append(
				aggregateCommitments,
				c.(curves.PairingPoint),
			)
		}

		for i, proof := range frame.AggregateProofs {
			aggregatePoly := [][]curves.PairingScalar{}
			commitments := []curves.PairingPoint{}

			for _, commit := range proof.GetInclusionCommitments() {
				switch commit.TypeUrl {
				case protobufs.IntrinsicExecutionOutputType:
					e.logger.Info("confirming inclusion in aggregate")
					digest := sha3.NewShake256()
					_, err := digest.Write(commit.Data)
					if err != nil {
						e.logger.Error(
							"error converting key bundle to polynomial",
							zap.Error(err),
						)
						return errors.Wrap(err, "handle clock frame response")
					}

					expand := make([]byte, 1024)
					_, err = digest.Read(expand)
					if err != nil {
						e.logger.Error(
							"error converting key bundle to polynomial",
							zap.Error(err),
						)
						return errors.Wrap(err, "handle clock frame response")
					}

					poly, err := e.prover.BytesToPolynomial(expand)
					if err != nil {
						e.logger.Error(
							"error converting key bundle to polynomial",
							zap.Error(err),
						)
						return errors.Wrap(err, "handle clock frame response")
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
						return errors.Wrap(err, "handle clock frame response")
					}
					e.logger.Info(
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
					poly, err := e.prover.BytesToPolynomial(commit.Data)
					if err != nil {
						e.logger.Error(
							"error converting key bundle to polynomial",
							zap.Error(err),
						)
						return errors.Wrap(err, "handle clock frame response")
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
						return errors.Wrap(err, "handle clock frame response")
					}

					aggregatePoly = append(aggregatePoly, evalPoly)

					c, err := curves.BLS48581G1().NewGeneratorPoint().FromAffineCompressed(
						commit.Commitment,
					)
					if err != nil {
						e.logger.Error("could not verify clock frame", zap.Error(err))
						return errors.Wrap(err, "handle clock frame response")
					}
					commitments = append(commitments, c.(curves.PairingPoint))
				}
			}

			p, err := curves.BLS48581G1().NewGeneratorPoint().FromAffineCompressed(
				proof.Proof,
			)
			if err != nil {
				e.logger.Error("could not verify clock frame", zap.Error(err))
				return errors.Wrap(err, "handle clock frame response")
			}

			result, err := e.prover.VerifyAggregateProof(
				aggregatePoly,
				commitments,
				aggregateCommitments[i],
				p.(curves.PairingPoint),
			)
			if err != nil {
				e.logger.Error("could not verify clock frame", zap.Error(err))
				return errors.Wrap(err, "handle clock frame response")
			}

			if !result {
				e.logger.Error("could not verify clock frame", zap.Error(err))
				return errors.Wrap(
					errors.New("invalid proof"),
					"handle clock frame response",
				)
			}
		}

		e.logger.Info(
			"clock frame was valid",
			zap.Binary("sender_address", address),
			zap.Binary("prover_address", prover),
			zap.Binary("filter", frame.Filter),
			zap.Uint64("frame_number", frame.FrameNumber),
		)

		parentSelector, selector, distance, err :=
			frame.GetParentSelectorAndDistance()
		if err != nil {
			return errors.Wrap(err, "handle clock frame data")
		}
		e.logger.Info(
			"difference between selector/discriminator",
			zap.Binary("difference", distance.Bytes()),
		)

		txn, err := e.clockStore.NewTransaction()
		if err != nil {
			e.logger.Error("could not save candidate clock frame", zap.Error(err))
			return errors.Wrap(err, "handle clock frame response")
		}

		if err := e.clockStore.PutCandidateDataClockFrame(
			parentSelector.Bytes(),
			distance.Bytes(),
			selector.Bytes(),
			frame,
			txn,
		); err != nil {
			e.logger.Error("could not save candidate clock frame", zap.Error(err))
			return errors.Wrap(err, "handle clock frame response")
		}

		if err := txn.Commit(); err != nil {
			e.logger.Error("could not save candidate clock frame", zap.Error(err))
			return errors.Wrap(err, "handle clock frame response")
		}

		if e.frame < frame.FrameNumber {
			e.latestFrameReceived = frame.FrameNumber
			e.lastFrameReceivedAt = time.Now().UTC()
		}
		trieCopy.Add(prover, frame.FrameNumber)
		e.frameSeenProverTrie.Add(prover, frame.FrameNumber)
	}

	return nil
}

func (e *CeremonyDataClockConsensusEngine) handleProvingKeyRequest(
	peerID []byte,
	address []byte,
	any *anypb.Any,
) error {
	if bytes.Equal(address, e.provingKeyAddress) {
		return nil
	}

	request := &protobufs.ProvingKeyRequest{}
	if err := any.UnmarshalTo(request); err != nil {
		return errors.Wrap(err, "handle proving key request")
	}

	if len(request.ProvingKeyBytes) == 0 {
		e.logger.Warn(
			"received proving key request for empty key",
			zap.Binary("peer_id", peerID),
			zap.Binary("address", address),
		)
		return errors.Wrap(
			errors.New("empty proving key"),
			"handle proving key request",
		)
	}

	channel := e.createPeerSendChannel(peerID)
	e.pubSub.Subscribe(channel, e.handleSync, true)

	e.logger.Info(
		"received proving key request",
		zap.Binary("peer_id", peerID),
		zap.Binary("address", address),
		zap.Binary("proving_key", request.ProvingKeyBytes),
	)

	var provingKey *protobufs.ProvingKeyAnnouncement
	inclusion, err := e.keyStore.GetProvingKey(request.ProvingKeyBytes)
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			e.logger.Error(
				"peer asked for proving key that returned error",
				zap.Binary("peer_id", peerID),
				zap.Binary("address", address),
				zap.Binary("proving_key", request.ProvingKeyBytes),
			)
			return errors.Wrap(err, "handle proving key request")
		}

		provingKey, err = e.keyStore.GetStagedProvingKey(request.ProvingKeyBytes)
		if !errors.Is(err, store.ErrNotFound) {
			e.logger.Error(
				"peer asked for proving key that returned error",
				zap.Binary("peer_id", peerID),
				zap.Binary("address", address),
				zap.Binary("proving_key", request.ProvingKeyBytes),
			)
			return errors.Wrap(err, "handle proving key request")
		} else if err != nil {
			e.logger.Warn(
				"peer asked for unknown proving key",
				zap.Binary("peer_id", peerID),
				zap.Binary("address", address),
				zap.Binary("proving_key", request.ProvingKeyBytes),
			)
			return nil
		}
	} else {
		err := proto.Unmarshal(inclusion.Data, provingKey)
		if err != nil {
			e.logger.Error(
				"inclusion commitment could not be deserialized",
				zap.Binary("peer_id", peerID),
				zap.Binary("address", address),
				zap.Binary("proving_key", request.ProvingKeyBytes),
			)
			return errors.Wrap(err, "handle proving key request")
		}
	}

	if err := e.publishMessage(channel, provingKey); err != nil {
		return errors.Wrap(err, "handle proving key request")
	}

	return nil
}

func (e *CeremonyDataClockConsensusEngine) handleClockFramesRequest(
	peerID []byte,
	address []byte,
	any *anypb.Any,
) error {
	if bytes.Equal(address, e.provingKeyAddress) {
		return nil
	}

	request := &protobufs.ClockFramesRequest{}
	if err := any.UnmarshalTo(request); err != nil {
		return errors.Wrap(err, "handle clock frame request")
	}

	channel := e.createPeerSendChannel(peerID)

	e.pubSub.Subscribe(channel, e.handleSync, true)

	e.logger.Info(
		"received clock frame request",
		zap.Binary("peer_id", peerID),
		zap.Binary("address", address),
		zap.Uint64("from_frame_number", request.FromFrameNumber),
		zap.Uint64("to_frame_number", request.ToFrameNumber),
	)

	from := request.FromFrameNumber

	base, _, err := e.clockStore.GetDataClockFrame(
		request.Filter,
		from,
	)
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			e.logger.Error(
				"peer asked for frame that returned error",
				zap.Binary("peer_id", peerID),
				zap.Binary("address", address),
				zap.Uint64("frame_number", request.FromFrameNumber),
			)
			return errors.Wrap(err, "handle clock frame request")
		} else {
			e.logger.Info(
				"peer asked for undiscovered frame",
				zap.Binary("peer_id", peerID),
				zap.Binary("address", address),
				zap.Uint64("frame_number", request.FromFrameNumber),
			)

			if err = e.publishMessage(channel, &protobufs.ClockFramesResponse{
				Filter:          request.Filter,
				FromFrameNumber: 0,
				ToFrameNumber:   0,
				ClockFrames:     []*protobufs.ClockFrame{},
			}); err != nil {
				return errors.Wrap(err, "handle clock frame request")
			}

			return nil
		}
	}

	to := request.ToFrameNumber
	if to == 0 || to-request.FromFrameNumber > 128 {
		to = request.FromFrameNumber + 127
	}

	set := []*protobufs.ClockFrame{base}
	noMoreFinalized := false
	searchSpan := []*protobufs.ClockFrame{base}
	currentNumber := 1

	for len(searchSpan) != 0 && from+uint64(currentNumber) <= to {
		e.logger.Info(
			"scanning frames to add to response",
			zap.Binary("peer_id", peerID),
			zap.Binary("address", address),
			zap.Uint64("from", from),
			zap.Uint64("to", to),
			zap.Uint64("current_number", uint64(currentNumber)),
		)
		nextSpan := []*protobufs.ClockFrame{}
		for _, s := range searchSpan {
			selector, err := s.GetSelector()
			if err != nil {
				return errors.Wrap(err, "handle clock frame request")
			}

			if !noMoreFinalized {
				frame, _, err := e.clockStore.GetDataClockFrame(
					s.Filter,
					s.FrameNumber+1,
				)
				if err != nil {
					if errors.Is(err, store.ErrNotFound) {
						noMoreFinalized = true
					} else {
						e.logger.Error(
							"fetching clock frame produced error",
							zap.Binary("peer_id", peerID),
							zap.Binary("address", address),
							zap.Uint64("frame_number", s.FrameNumber+1),
						)
						return errors.Wrap(err, "handle clock frame request")
					}
				} else {
					nextSpan = append(nextSpan, frame)
					set = append(set, frame)
				}
			}

			if noMoreFinalized {
				iter, err := e.clockStore.RangeCandidateDataClockFrames(
					s.Filter,
					selector.Bytes(),
					s.FrameNumber+1,
				)
				if err != nil {
					e.logger.Error(
						"peer asked for frame that returned error while iterating",
						zap.Binary("peer_id", peerID),
						zap.Binary("address", address),
						zap.Binary("parent_selector", s.ParentSelector),
						zap.Uint64("frame_number", s.FrameNumber+1),
					)
					return errors.Wrap(err, "handle clock frame request")
				}

				for iter.First(); iter.Valid(); iter.Next() {
					frame, err := iter.Value()

					if err != nil {
						e.logger.Error(
							"peer asked for frame that returned error while getting value",
							zap.Binary("peer_id", peerID),
							zap.Binary("address", address),
							zap.Binary("parent_selector", selector.Bytes()),
							zap.Uint64("frame_number", s.FrameNumber+1),
						)
						return errors.Wrap(err, "handle clock frame request")
					}

					nextSpan = append(nextSpan, frame)
					set = append(set, frame)
				}

				iter.Close()
			}
		}
		currentNumber++
		searchSpan = nextSpan
	}

	e.logger.Info(
		"sending response",
		zap.Binary("peer_id", peerID),
		zap.Binary("address", address),
		zap.Uint64("from", from),
		zap.Uint64("to", to),
		zap.Uint64("total_frames", uint64(len(set))),
	)

	if err = e.publishMessage(channel, &protobufs.ClockFramesResponse{
		Filter:          request.Filter,
		FromFrameNumber: request.FromFrameNumber,
		ToFrameNumber:   to,
		ClockFrames:     set,
	}); err != nil {
		return errors.Wrap(err, "handle clock frame request")
	}

	return nil
}
