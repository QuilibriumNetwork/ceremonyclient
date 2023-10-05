package ceremony

import (
	"bytes"
	"context"
	"time"

	"github.com/pkg/errors"
	"go.uber.org/zap"
	"golang.org/x/crypto/sha3"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"source.quilibrium.com/quilibrium/monorepo/go-libp2p-blossomsub/pb"
	"source.quilibrium.com/quilibrium/monorepo/nekryptology/pkg/core/curves"
	qcrypto "source.quilibrium.com/quilibrium/monorepo/node/crypto"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/ceremony/application"
	"source.quilibrium.com/quilibrium/monorepo/node/p2p"
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
	if bytes.Equal(message.From, e.pubSub.GetPeerID()) {
		return nil
	}

	msg := &protobufs.Message{}

	if err := proto.Unmarshal(message.Data, msg); err != nil {
		return errors.Wrap(err, "handle sync")
	}

	any := &anypb.Any{}
	if err := proto.Unmarshal(msg.Payload, any); err != nil {
		return errors.Wrap(err, "handle sync")
	}

	switch any.TypeUrl {
	case protobufs.ClockFrameType:
		if err := e.handleClockFrameData(
			message.From,
			msg.Address,
			any,
			true,
		); err != nil {
			return errors.Wrap(err, "handle sync")
		}
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

// GetCompressedSyncFrames implements protobufs.CeremonyServiceServer.
func (e *CeremonyDataClockConsensusEngine) GetCompressedSyncFrames(
	request *protobufs.ClockFramesRequest,
	server protobufs.CeremonyService_GetCompressedSyncFramesServer,
) error {
	e.logger.Info(
		"received clock frame request",
		zap.Uint64("from_frame_number", request.FromFrameNumber),
		zap.Uint64("to_frame_number", request.ToFrameNumber),
	)

	from := request.FromFrameNumber

	_, _, err := e.clockStore.GetDataClockFrame(
		request.Filter,
		from,
	)
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			e.logger.Error(
				"peer asked for frame that returned error",
				zap.Uint64("frame_number", request.FromFrameNumber),
			)
			return errors.Wrap(err, "get compressed sync frames")
		} else {
			e.logger.Debug(
				"peer asked for undiscovered frame",
				zap.Uint64("frame_number", request.FromFrameNumber),
			)

			if err := server.SendMsg(
				&protobufs.ClockFramesResponse{
					Filter:          request.Filter,
					FromFrameNumber: 0,
					ToFrameNumber:   0,
					ClockFrames:     []*protobufs.ClockFrame{},
				},
			); err != nil {
				return errors.Wrap(err, "get compressed sync frames")
			}

			return nil
		}
	}

	max := e.frame
	to := request.ToFrameNumber

	for {
		if to == 0 || to-from > 32 {
			if max > from+31 {
				to = from + 31
			} else {
				to = max
			}
		}

		syncMsg, err := e.clockStore.GetCompressedDataClockFrames(
			e.filter,
			from,
			to,
		)
		if err != nil {
			return errors.Wrap(err, "get compressed sync frames")
		}

		if err := server.SendMsg(syncMsg); err != nil {
			return errors.Wrap(err, "get compressed sync frames")
		}

		if (request.ToFrameNumber == 0 || request.ToFrameNumber > to) && max > to {
			from = to + 1
			if request.ToFrameNumber > to {
				to = request.ToFrameNumber
			} else {
				to = 0
			}
		} else {
			break
		}
	}

	return nil
}

func (e *CeremonyDataClockConsensusEngine) decompressAndStoreCandidates(
	syncMsg *protobufs.CeremonyCompressedSync,
) error {
	for _, frame := range syncMsg.TruncatedClockFrames {
		commits := (len(frame.Input) - 516) / 74
		e.logger.Info(
			"processing frame",
			zap.Uint64("frame_number", frame.FrameNumber),
			zap.Int("aggregate_commits", commits),
		)
		for j := 0; j < commits; j++ {
			e.logger.Info(
				"processing commit",
				zap.Uint64("frame_number", frame.FrameNumber),
				zap.Int("commit_index", j),
			)
			commit := frame.Input[516+(j*74) : 516+((j+1)*74)]
			var aggregateProof *protobufs.InclusionProofsMap
			for _, a := range syncMsg.Proofs {
				if bytes.Equal(a.FrameCommit, commit) {
					e.logger.Info(
						"found matching proof",
						zap.Uint64("frame_number", frame.FrameNumber),
						zap.Int("commit_index", j),
					)
					aggregateProof = a
					break
				}
			}
			if aggregateProof == nil {
				e.logger.Error(
					"could not find matching proof",
					zap.Uint64("frame_number", frame.FrameNumber),
					zap.Int("commit_index", j),
					zap.Binary("proof", aggregateProof.Proof),
				)
				return errors.Wrap(
					store.ErrInvalidData,
					"decompress and store candidates",
				)
			}
			inc := &protobufs.InclusionAggregateProof{
				Filter:               e.filter,
				FrameNumber:          frame.FrameNumber,
				InclusionCommitments: []*protobufs.InclusionCommitment{},
				Proof:                aggregateProof.Proof,
			}

			for k, c := range aggregateProof.Commitments {
				e.logger.Info(
					"adding inclusion commitment",
					zap.Uint64("frame_number", frame.FrameNumber),
					zap.Int("commit_index", j),
					zap.Int("inclusion_commit_index", k),
					zap.String("type_url", c.TypeUrl),
				)
				incCommit := &protobufs.InclusionCommitment{
					Filter:      e.filter,
					FrameNumber: frame.FrameNumber,
					Position:    uint32(k),
					TypeUrl:     c.TypeUrl,
					Data:        []byte{},
					Commitment:  c.Commitment,
				}
				var output *protobufs.IntrinsicExecutionOutput
				if c.TypeUrl == protobufs.IntrinsicExecutionOutputType {
					output = &protobufs.IntrinsicExecutionOutput{}
				}
				for l, h := range c.SegmentHashes {
					for _, s := range syncMsg.Segments {
						if bytes.Equal(s.Hash, h) {
							if output != nil {
								if l == 0 {
									e.logger.Info(
										"found first half of matching segment data",
										zap.Uint64("frame_number", frame.FrameNumber),
										zap.Int("commit_index", j),
										zap.Int("inclusion_commit_index", k),
										zap.String("type_url", c.TypeUrl),
									)
									output.Address = s.Data[:32]
									output.Output = s.Data[32:]
								} else {
									e.logger.Info(
										"found second half of matching segment data",
										zap.Uint64("frame_number", frame.FrameNumber),
										zap.Int("commit_index", j),
										zap.Int("inclusion_commit_index", k),
										zap.String("type_url", c.TypeUrl),
									)
									output.Proof = s.Data
									b, err := proto.Marshal(output)
									if err != nil {
										return errors.Wrap(err, "decompress and store candidates")
									}
									incCommit.Data = b
									break
								}
							} else {
								e.logger.Info(
									"found matching segment data",
									zap.Uint64("frame_number", frame.FrameNumber),
									zap.Int("commit_index", j),
									zap.Int("inclusion_commit_index", k),
									zap.String("type_url", c.TypeUrl),
								)
								incCommit.Data = append(incCommit.Data, s.Data...)
								break
							}
						}
					}
				}
				inc.InclusionCommitments = append(
					inc.InclusionCommitments,
					incCommit,
				)
			}

			frame.AggregateProofs = append(
				frame.AggregateProofs,
				inc,
			)
		}

		f, err := proto.Marshal(frame)
		if err != nil {
			return errors.Wrap(err, "decompress and store candidates")
		}

		any := &anypb.Any{
			TypeUrl: protobufs.ClockFrameType,
			Value:   f,
		}
		if err = e.handleClockFrameData(
			e.syncingTarget,
			application.CEREMONY_ADDRESS,
			any,
			true,
		); err != nil {
			return errors.Wrap(err, "decompress and store candidates")
		}
	}

	e.logger.Info(
		"decompressed and stored sync for range",
		zap.Uint64("from", syncMsg.FromFrameNumber),
		zap.Uint64("to", syncMsg.ToFrameNumber),
	)
	return nil
}

type svr struct {
	protobufs.UnimplementedCeremonyServiceServer
	svrChan chan protobufs.CeremonyService_GetPublicChannelServer
}

func (e *svr) GetCompressedSyncFrames(
	request *protobufs.ClockFramesRequest,
	server protobufs.CeremonyService_GetCompressedSyncFramesServer,
) error {
	return errors.New("not supported")
}

func (e *svr) GetPublicChannel(
	server protobufs.CeremonyService_GetPublicChannelServer,
) error {
	go func() {
		e.svrChan <- server
	}()
	<-server.Context().Done()
	return nil
}

func (e *CeremonyDataClockConsensusEngine) GetPublicChannelForProvingKey(
	initiator bool,
	provingKey []byte,
) (p2p.PublicChannelClient, error) {
	if initiator {
		svrChan := make(
			chan protobufs.CeremonyService_GetPublicChannelServer,
		)
		after := time.After(20 * time.Second)
		go func() {
			server := grpc.NewServer(
				grpc.MaxSendMsgSize(400*1024*1024),
				grpc.MaxRecvMsgSize(400*1024*1024),
			)

			s := &svr{
				svrChan: svrChan,
			}
			protobufs.RegisterCeremonyServiceServer(server, s)

			if err := e.pubSub.StartDirectChannelListener(
				provingKey,
				server,
			); err != nil {
				e.logger.Error(
					"could not get public channel for proving key",
					zap.Error(err),
				)
				svrChan <- nil
			}
		}()
		select {
		case s := <-svrChan:
			return s, nil
		case <-after:
			return nil, errors.Wrap(
				errors.New("timed out"),
				"get public channel for proving key",
			)
		}
	} else {
		cc, err := e.pubSub.GetDirectChannel(provingKey)
		if err != nil {
			e.logger.Error(
				"could not get public channel for proving key",
				zap.Error(err),
			)
			return nil, nil
		}
		client := protobufs.NewCeremonyServiceClient(cc)
		s, err := client.GetPublicChannel(
			context.Background(),
			grpc.MaxCallSendMsgSize(400*1024*1024),
			grpc.MaxCallRecvMsgSize(400*1024*1024),
		)
		return s, nil
	}
}

// GetPublicChannel implements protobufs.CeremonyServiceServer.
func (e *CeremonyDataClockConsensusEngine) GetPublicChannel(
	server protobufs.CeremonyService_GetPublicChannelServer,
) error {
	return errors.New("not supported")
}

func (e *CeremonyDataClockConsensusEngine) handleClockFramesResponse(
	peerID []byte,
	address []byte,
	any *anypb.Any,
) error {
	if bytes.Equal(peerID, e.pubSub.GetPeerID()) {
		return nil
	}

	if !bytes.Equal(peerID, e.syncingTarget) {
		e.logger.Debug(
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
					e.logger.Debug("confirming inclusion in aggregate")
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
		e.logger.Debug(
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
	if bytes.Equal(peerID, e.pubSub.GetPeerID()) {
		return nil
	}

	request := &protobufs.ProvingKeyRequest{}
	if err := any.UnmarshalTo(request); err != nil {
		return nil
	}

	if len(request.ProvingKeyBytes) == 0 {
		e.logger.Debug(
			"received proving key request for empty key",
			zap.Binary("peer_id", peerID),
			zap.Binary("address", address),
		)
		return nil
	}

	e.pubSub.Subscribe(
		append(append([]byte{}, e.filter...), peerID...),
		e.handleSync,
		true,
	)

	e.logger.Debug(
		"received proving key request",
		zap.Binary("peer_id", peerID),
		zap.Binary("address", address),
		zap.Binary("proving_key", request.ProvingKeyBytes),
	)

	var provingKey *protobufs.ProvingKeyAnnouncement
	inclusion, err := e.keyStore.GetProvingKey(request.ProvingKeyBytes)
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			e.logger.Debug(
				"peer asked for proving key that returned error",
				zap.Binary("peer_id", peerID),
				zap.Binary("address", address),
				zap.Binary("proving_key", request.ProvingKeyBytes),
			)
			return nil
		}

		provingKey, err = e.keyStore.GetStagedProvingKey(request.ProvingKeyBytes)
		if !errors.Is(err, store.ErrNotFound) {
			e.logger.Debug(
				"peer asked for proving key that returned error",
				zap.Binary("peer_id", peerID),
				zap.Binary("address", address),
				zap.Binary("proving_key", request.ProvingKeyBytes),
			)
			return nil
		} else if err != nil {
			e.logger.Debug(
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
			e.logger.Debug(
				"inclusion commitment could not be deserialized",
				zap.Binary("peer_id", peerID),
				zap.Binary("address", address),
				zap.Binary("proving_key", request.ProvingKeyBytes),
			)
			return nil
		}
	}

	if err := e.publishMessage(
		append(append([]byte{}, e.filter...), peerID...),
		provingKey,
	); err != nil {
		return nil
	}

	return nil
}

func (e *CeremonyDataClockConsensusEngine) handleClockFramesRequest(
	peerID []byte,
	address []byte,
	any *anypb.Any,
) error {
	if bytes.Equal(peerID, e.pubSub.GetPeerID()) {
		return nil
	}

	request := &protobufs.ClockFramesRequest{}
	if err := any.UnmarshalTo(request); err != nil {
		return errors.Wrap(err, "handle clock frame request")
	}

	e.pubSub.Subscribe(
		append(append([]byte{}, e.filter...), peerID...),
		e.handleSync,
		true,
	)

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
			e.logger.Debug(
				"peer asked for undiscovered frame",
				zap.Binary("peer_id", peerID),
				zap.Binary("address", address),
				zap.Uint64("frame_number", request.FromFrameNumber),
			)

			if err = e.publishMessage(
				append(append([]byte{}, e.filter...), peerID...),
				&protobufs.ClockFramesResponse{
					Filter:          request.Filter,
					FromFrameNumber: 0,
					ToFrameNumber:   0,
					ClockFrames:     []*protobufs.ClockFrame{},
				},
			); err != nil {
				return errors.Wrap(err, "handle clock frame request")
			}

			return nil
		}
	}

	to := request.ToFrameNumber
	if to == 0 || to-request.FromFrameNumber > 32 {
		to = request.FromFrameNumber + 31
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
					if err = e.publishMessage(
						append(append([]byte{}, e.filter...), peerID...),
						frame,
					); err != nil {
						return errors.Wrap(err, "handle clock frame request")
					}
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

					if err = e.publishMessage(
						append(append([]byte{}, e.filter...), peerID...),
						frame,
					); err != nil {
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

	return nil
}
