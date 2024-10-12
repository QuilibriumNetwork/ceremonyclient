package data

import (
	"bytes"
	"context"
	"time"

	"github.com/mr-tron/base58"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/token/application"
	"source.quilibrium.com/quilibrium/monorepo/node/p2p"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/node/store"
)

var ErrNoNewFrames = errors.New("peer reported no frames")

func (e *DataClockConsensusEngine) GetDataFrame(
	ctx context.Context,
	request *protobufs.GetDataFrameRequest,
) (*protobufs.DataFrameResponse, error) {
	e.logger.Debug(
		"received frame request",
		zap.Uint64("frame_number", request.FrameNumber),
	)
	var frame *protobufs.ClockFrame
	var err error
	if request.FrameNumber == 0 {
		frame, err = e.dataTimeReel.Head()
		if frame.FrameNumber == 0 {
			return nil, errors.Wrap(
				errors.New("not currently syncable"),
				"get data frame",
			)
		}
	} else {
		frame, _, err = e.clockStore.GetDataClockFrame(
			e.filter,
			request.FrameNumber,
			false,
		)
	}

	if err != nil {
		e.logger.Error(
			"received error while fetching time reel head",
			zap.Error(err),
		)
		return nil, errors.Wrap(err, "get data frame")
	}

	idx, err := e.frameProver.GenerateWeakRecursiveProofIndex(frame)
	if err != nil {
		return nil, errors.Wrap(err, "get data frame")
	}

	indexFrame, _, err := e.clockStore.GetDataClockFrame(e.filter, idx, false)
	if err != nil {
		return &protobufs.DataFrameResponse{
			ClockFrame: frame,
		}, nil
	}

	proof := e.frameProver.FetchRecursiveProof(indexFrame)

	e.logger.Debug(
		"sending frame response",
		zap.Uint64("frame_number", frame.FrameNumber),
	)

	return &protobufs.DataFrameResponse{
		ClockFrame: frame,
		Proof:      proof,
	}, nil
}

func (e *DataClockConsensusEngine) NegotiateCompressedSyncFrames(
	server protobufs.DataService_NegotiateCompressedSyncFramesServer,
) error {
	return nil
}

// Deprecated: Use NegotiateCompressedSyncFrames.
// GetCompressedSyncFrames implements protobufs.DataServiceServer.
func (e *DataClockConsensusEngine) GetCompressedSyncFrames(
	request *protobufs.ClockFramesRequest,
	server protobufs.DataService_GetCompressedSyncFramesServer,
) error {
	e.logger.Debug(
		"received clock frame request",
		zap.Uint64("from_frame_number", request.FromFrameNumber),
		zap.Uint64("to_frame_number", request.ToFrameNumber),
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

func (e *DataClockConsensusEngine) decompressAndStoreCandidates(
	peerId []byte,
	syncMsg *protobufs.DataCompressedSync,
) (*protobufs.ClockFrame, error) {
	if len(syncMsg.TruncatedClockFrames) == 0 {
		return nil, ErrNoNewFrames
	}

	head, err := e.dataTimeReel.Head()
	if err != nil {
		panic(err)
	}

	if len(syncMsg.TruncatedClockFrames) < int(
		syncMsg.ToFrameNumber-syncMsg.FromFrameNumber+1,
	) {
		e.peerMapMx.Lock()
		if _, ok := e.peerMap[string(peerId)]; ok {
			e.uncooperativePeersMap[string(peerId)] = e.peerMap[string(peerId)]
			e.uncooperativePeersMap[string(peerId)].timestamp = time.Now().UnixMilli()
			delete(e.peerMap, string(peerId))
		}
		e.peerMapMx.Unlock()
		return nil, errors.New("invalid continuity for compressed sync response")
	}

	var final *protobufs.ClockFrame
	for _, frame := range syncMsg.TruncatedClockFrames {
		frame := frame
		commits := (len(frame.Input) - 516) / 74
		e.logger.Info(
			"processing frame",
			zap.Uint64("frame_number", frame.FrameNumber),
			zap.Int("aggregate_commits", commits),
		)
		for j := 0; j < commits; j++ {
			e.logger.Debug(
				"processing commit",
				zap.Uint64("frame_number", frame.FrameNumber),
				zap.Int("commit_index", j),
			)
			commit := frame.Input[516+(j*74) : 516+((j+1)*74)]
			var aggregateProof *protobufs.InclusionProofsMap
			for _, a := range syncMsg.Proofs {
				a := a
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
				e.logger.Debug(
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
									e.logger.Debug(
										"found first half of matching segment data",
										zap.Uint64("frame_number", frame.FrameNumber),
										zap.Int("commit_index", j),
										zap.Int("inclusion_commit_index", k),
										zap.String("type_url", c.TypeUrl),
									)
									output.Address = s.Data[:32]
									output.Output = s.Data[32:]
								} else {
									e.logger.Debug(
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
								e.logger.Debug(
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
			p2p.GetBloomFilter(application.TOKEN_ADDRESS, 256, 3),
			any,
			// We'll tell the time reel to process it (isSync = false) if we're caught
			// up beyond the head and frame number is divisible by 100 (limited to
			// avoid thrash):
			head.FrameNumber > frame.FrameNumber || frame.FrameNumber%100 != 0,
		); err != nil {
			return nil, errors.Wrap(err, "decompress and store candidates")
		}

		final = frame
	}

	e.logger.Info(
		"decompressed and stored sync for range",
		zap.Uint64("from", syncMsg.FromFrameNumber),
		zap.Uint64("to", syncMsg.ToFrameNumber),
	)
	return final, nil
}

type svr struct {
	protobufs.UnimplementedDataServiceServer
	svrChan chan protobufs.DataService_GetPublicChannelServer
}

func (e *svr) GetCompressedSyncFrames(
	request *protobufs.ClockFramesRequest,
	server protobufs.DataService_GetCompressedSyncFramesServer,
) error {
	return errors.New("not supported")
}

func (e *svr) NegotiateCompressedSyncFrames(
	server protobufs.DataService_NegotiateCompressedSyncFramesServer,
) error {
	return errors.New("not supported")
}

func (e *svr) GetPublicChannel(
	server protobufs.DataService_GetPublicChannelServer,
) error {
	go func() {
		e.svrChan <- server
	}()
	<-server.Context().Done()
	return nil
}

func (e *DataClockConsensusEngine) GetPublicChannelForProvingKey(
	initiator bool,
	peerID []byte,
	provingKey []byte,
) (p2p.PublicChannelClient, error) {
	if initiator {
		svrChan := make(
			chan protobufs.DataService_GetPublicChannelServer,
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
			protobufs.RegisterDataServiceServer(server, s)

			if err := e.pubSub.StartDirectChannelListener(
				peerID,
				base58.Encode(provingKey),
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
		cc, err := e.pubSub.GetDirectChannel(peerID, base58.Encode(provingKey))
		if err != nil {
			e.logger.Error(
				"could not get public channel for proving key",
				zap.Error(err),
			)
			return nil, nil
		}
		client := protobufs.NewDataServiceClient(cc)
		s, err := client.GetPublicChannel(
			context.Background(),
			grpc.MaxCallSendMsgSize(600*1024*1024),
			grpc.MaxCallRecvMsgSize(600*1024*1024),
		)
		return s, errors.Wrap(err, "get public channel for proving key")
	}
}

// GetPublicChannel implements protobufs.DataServiceServer.
func (e *DataClockConsensusEngine) GetPublicChannel(
	server protobufs.DataService_GetPublicChannelServer,
) error {
	return errors.New("not supported")
}
