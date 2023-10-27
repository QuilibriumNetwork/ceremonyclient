package ceremony

import (
	"bytes"
	"context"
	"time"

	"github.com/pkg/errors"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"source.quilibrium.com/quilibrium/monorepo/go-libp2p-blossomsub/pb"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/ceremony/application"
	"source.quilibrium.com/quilibrium/monorepo/node/p2p"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/node/store"
)

var ErrNoNewFrames = errors.New("peer reported no frames")

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

	frame, _, err := e.clockStore.GetDataClockFrame(
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

	parent := request.ParentSelector
	if parent != nil {
		if !bytes.Equal(frame.ParentSelector, parent) {
			e.logger.Info(
				"peer specified out of consensus head, seeking backwards for fork",
			)
		}

		for !bytes.Equal(frame.ParentSelector, parent) {
			ours, err := e.clockStore.GetParentDataClockFrame(
				e.filter,
				frame.FrameNumber-1,
				frame.ParentSelector,
			)
			if err != nil {
				from = 1
				e.logger.Info("peer fully out of sync, rewinding sync head to start")
				break
			}

			theirs, err := e.clockStore.GetParentDataClockFrame(
				e.filter,
				frame.FrameNumber-1,
				parent,
			)
			if err != nil {
				from = 1
				e.logger.Info("peer fully out of sync, rewinding sync head to start")
				break
			}

			from--
			frame = ours
			parent = theirs.ParentSelector
		}
	}

	max := e.frame
	to := request.ToFrameNumber

	for {
		if to == 0 || to-from > 32 {
			if max > from+31 {
				to = from + 32
			} else {
				to = max + 1
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
	loggerFunc func(msg string, fields ...zapcore.Field),
) (*protobufs.ClockFrame, error) {
	if len(syncMsg.TruncatedClockFrames) == 0 {
		return nil, ErrNoNewFrames
	}

	if len(syncMsg.TruncatedClockFrames) != int(
		syncMsg.ToFrameNumber-syncMsg.FromFrameNumber+1,
	) {
		return nil, errors.New("invalid continuity for compressed sync response")
	}

	var final *protobufs.ClockFrame
	for _, frame := range syncMsg.TruncatedClockFrames {
		frame := frame
		commits := (len(frame.Input) - 516) / 74
		loggerFunc(
			"processing frame",
			zap.Uint64("frame_number", frame.FrameNumber),
			zap.Int("aggregate_commits", commits),
		)
		for j := 0; j < commits; j++ {
			loggerFunc(
				"processing commit",
				zap.Uint64("frame_number", frame.FrameNumber),
				zap.Int("commit_index", j),
			)
			commit := frame.Input[516+(j*74) : 516+((j+1)*74)]
			var aggregateProof *protobufs.InclusionProofsMap
			for _, a := range syncMsg.Proofs {
				a := a
				if bytes.Equal(a.FrameCommit, commit) {
					loggerFunc(
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
				return nil, errors.Wrap(
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
				k := k
				c := c
				loggerFunc(
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
					l := l
					h := h

					for _, s := range syncMsg.Segments {
						s := s

						if bytes.Equal(s.Hash, h) {
							if output != nil {
								if l == 0 {
									loggerFunc(
										"found first half of matching segment data",
										zap.Uint64("frame_number", frame.FrameNumber),
										zap.Int("commit_index", j),
										zap.Int("inclusion_commit_index", k),
										zap.String("type_url", c.TypeUrl),
									)
									output.Address = s.Data[:32]
									output.Output = s.Data[32:]
								} else {
									loggerFunc(
										"found second half of matching segment data",
										zap.Uint64("frame_number", frame.FrameNumber),
										zap.Int("commit_index", j),
										zap.Int("inclusion_commit_index", k),
										zap.String("type_url", c.TypeUrl),
									)
									output.Proof = s.Data
									b, err := proto.Marshal(output)
									if err != nil {
										return nil, errors.Wrap(
											err,
											"decompress and store candidates",
										)
									}
									incCommit.Data = b
									break
								}
							} else {
								loggerFunc(
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
			return nil, errors.Wrap(err, "decompress and store candidates")
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
			return nil, errors.Wrap(err, "decompress and store candidates")
		}
		final = frame
	}

	loggerFunc(
		"decompressed and stored sync for range",
		zap.Uint64("from", syncMsg.FromFrameNumber),
		zap.Uint64("to", syncMsg.ToFrameNumber),
	)
	return final, nil
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
				grpc.MaxSendMsgSize(600*1024*1024),
				grpc.MaxRecvMsgSize(600*1024*1024),
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
			grpc.MaxCallSendMsgSize(600*1024*1024),
			grpc.MaxCallRecvMsgSize(600*1024*1024),
		)
		return s, errors.Wrap(err, "get public channel for proving key")
	}
}

// GetPublicChannel implements protobufs.CeremonyServiceServer.
func (e *CeremonyDataClockConsensusEngine) GetPublicChannel(
	server protobufs.CeremonyService_GetPublicChannelServer,
) error {
	return errors.New("not supported")
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
