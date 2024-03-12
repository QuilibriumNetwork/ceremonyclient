package ceremony

import (
	"bytes"
	"context"
	"io"
	"time"

	"github.com/mr-tron/base58"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/ceremony/application"
	"source.quilibrium.com/quilibrium/monorepo/node/p2p"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/node/store"
)

var ErrNoNewFrames = errors.New("peer reported no frames")

// Compressed sync negotiation:
// Recipients of the sync                                 Servers providing sync
// |                                                                           |
// |---------[Preflight{HEAD, HEAD-16, HEAD-32, HEAD-64, ..., 1}]------------->|
// |<--------[Preflight{HEAD, HEAD-16, HEAD-32, HEAD-64, ..., M}]--------------|
// |                    M = matching selector or 1                             |
// |------------------------------[Request{N}]-------------------------------->|
// |                    N = matching higher selector or M                      |
// |<-------------------------[Response{N...N+16}]-----------------------------|
// |<--------------------------[Response{N+17...}]-----------------------------|
// |<--------------------------[Response{...HEAD}]-----------------------------|
func (e *CeremonyDataClockConsensusEngine) NegotiateCompressedSyncFrames(
	server protobufs.CeremonyService_NegotiateCompressedSyncFramesServer,
) error {
	e.currentReceivingSyncPeersMx.Lock()
	if e.currentReceivingSyncPeers > 4 {
		e.currentReceivingSyncPeersMx.Unlock()

		e.logger.Debug(
			"currently processing maximum sync requests, returning",
		)

		if err := server.SendMsg(
			&protobufs.CeremonyCompressedSyncResponseMessage{
				SyncMessage: &protobufs.CeremonyCompressedSyncResponseMessage_Response{
					Response: &protobufs.CeremonyCompressedSync{
						FromFrameNumber: 0,
						ToFrameNumber:   0,
					},
				},
			},
		); err != nil {
			return errors.Wrap(err, "negotiate compressed sync frames")
		}

		return nil
	}
	e.currentReceivingSyncPeers++
	e.currentReceivingSyncPeersMx.Unlock()

	defer func() {
		e.currentReceivingSyncPeersMx.Lock()
		e.currentReceivingSyncPeers--
		e.currentReceivingSyncPeersMx.Unlock()
	}()

	for {
		request, err := server.Recv()
		if err == io.EOF {
			return nil
		}

		if err != nil {
			return errors.Wrap(err, "negotiate compressed sync frames")
		}

		switch msg := request.SyncMessage.(type) {
		case *protobufs.CeremonyCompressedSyncRequestMessage_Preflight:
			e.logger.Debug(
				"received clock frame preflight",
				zap.Int("selector_count", len(msg.Preflight.RangeParentSelectors)),
			)

			from := uint64(1)

			preflightResponse := []*protobufs.ClockFrameParentSelectors{}
			for _, selector := range msg.Preflight.RangeParentSelectors {
				frame, _, err := e.clockStore.GetDataClockFrame(
					e.filter,
					selector.FrameNumber,
					true,
				)
				if err == nil && frame != nil {
					from = selector.FrameNumber
					break
				}
			}

			head, err := e.dataTimeReel.Head()
			if err != nil {
				return errors.Wrap(err, "negotiate compressed sync frames")
			}

			to := head.FrameNumber
			selector, err := head.GetSelector()
			if err != nil {
				return errors.Wrap(err, "negotiate compressed sync frames")
			}

			preflightResponse = append(
				preflightResponse,
				&protobufs.ClockFrameParentSelectors{
					FrameNumber:    to,
					ParentSelector: selector.FillBytes(make([]byte, 32)),
				},
			)
			rangeSubtract := uint64(16)
			for {
				parentNumber := to - uint64(rangeSubtract)

				if parentNumber < from {
					break
				}
				rangeSubtract *= 2
				parent, _, err := e.clockStore.GetDataClockFrame(
					e.filter,
					parentNumber,
					true,
				)
				if err != nil {
					break
				}

				parentSelector, err := parent.GetSelector()
				if err != nil {
					return errors.Wrap(err, "negotiate compressed sync frames")
				}

				preflightResponse = append(
					preflightResponse,
					&protobufs.ClockFrameParentSelectors{
						FrameNumber:    parent.FrameNumber,
						ParentSelector: parentSelector.FillBytes(make([]byte, 32)),
					},
				)
			}
			err = server.Send(&protobufs.CeremonyCompressedSyncResponseMessage{
				SyncMessage: &protobufs.CeremonyCompressedSyncResponseMessage_Preflight{
					Preflight: &protobufs.ClockFramesPreflight{
						RangeParentSelectors: preflightResponse,
					},
				},
			})
			if err != nil {
				return errors.Wrap(err, "negotiate compressed sync frames")
			}
		case *protobufs.CeremonyCompressedSyncRequestMessage_Request:
			e.logger.Info(
				"received clock frame request",
				zap.Uint64("from_frame_number", msg.Request.FromFrameNumber),
				zap.Uint64("to_frame_number", msg.Request.ToFrameNumber),
			)
			from := msg.Request.FromFrameNumber
			_, _, err := e.clockStore.GetDataClockFrame(
				e.filter,
				from,
				true,
			)
			if err != nil {
				if !errors.Is(err, store.ErrNotFound) {
					e.logger.Error(
						"peer asked for frame that returned error",
						zap.Uint64("frame_number", msg.Request.FromFrameNumber),
					)

					return errors.Wrap(err, "negotiate compressed sync frames")
				} else {
					from = 1
				}
			}

			head, err := e.dataTimeReel.Head()
			if err != nil {
				panic(err)
			}

			max := head.FrameNumber
			to := msg.Request.ToFrameNumber

			// We need to slightly rewind, to compensate for unconfirmed frame heads
			// on a given branch
			if from >= 2 {
				from--
			}

			for {
				if to == 0 || to-from > 16 {
					if max > from+15 {
						to = from + 16
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
					return errors.Wrap(err, "negotiate compressed sync frames")
				}

				if err := server.Send(&protobufs.CeremonyCompressedSyncResponseMessage{
					SyncMessage: &protobufs.
						CeremonyCompressedSyncResponseMessage_Response{
						Response: syncMsg,
					},
				}); err != nil {
					return errors.Wrap(err, "negotiate compressed sync frames")
				}

				if (msg.Request.ToFrameNumber == 0 || msg.Request.ToFrameNumber > to) &&
					max > to {
					from = to + 1
					if msg.Request.ToFrameNumber > to {
						to = msg.Request.ToFrameNumber
					} else {
						to = 0
					}
				} else {
					break
				}
			}

			return nil
		}
	}
}

// Deprecated: Use NegotiateCompressedSyncFrames.
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

	e.currentReceivingSyncPeersMx.Lock()
	if e.currentReceivingSyncPeers > 4 {
		e.currentReceivingSyncPeersMx.Unlock()

		e.logger.Info(
			"currently processing maximum sync requests, returning",
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

	e.currentReceivingSyncPeers++
	e.currentReceivingSyncPeersMx.Unlock()

	defer func() {
		e.currentReceivingSyncPeersMx.Lock()
		e.currentReceivingSyncPeers--
		e.currentReceivingSyncPeersMx.Unlock()
	}()

	from := request.FromFrameNumber
	parent := request.ParentSelector

	frame, _, err := e.clockStore.GetDataClockFrame(
		request.Filter,
		from,
		true,
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

	if parent != nil {
		if !bytes.Equal(frame.ParentSelector, parent) {
			e.logger.Debug(
				"peer specified out of consensus head, seeking backwards for fork",
			)
		}

		for !bytes.Equal(frame.ParentSelector, parent) {
			ours, err := e.clockStore.GetStagedDataClockFrame(
				e.filter,
				frame.FrameNumber-1,
				frame.ParentSelector,
				true,
			)
			if err != nil {
				from = 1
				e.logger.Debug("peer fully out of sync, rewinding sync head to start")
				break
			}

			theirs, err := e.clockStore.GetStagedDataClockFrame(
				e.filter,
				frame.FrameNumber-1,
				parent,
				true,
			)
			if err != nil {
				from = 1
				e.logger.Debug("peer fully out of sync, rewinding sync head to start")
				break
			}

			from--
			frame = ours
			parent = theirs.ParentSelector
		}
	}

	if request.RangeParentSelectors != nil {
		for _, selector := range request.RangeParentSelectors {
			frame, err := e.clockStore.GetStagedDataClockFrame(
				e.filter,
				selector.FrameNumber,
				selector.ParentSelector,
				true,
			)
			if err == nil && frame != nil {
				from = selector.FrameNumber
				break
			}
		}
	}

	head, err := e.dataTimeReel.Head()
	if err != nil {
		panic(err)
	}

	max := head.FrameNumber
	to := request.ToFrameNumber

	// We need to slightly rewind, to compensate for unconfirmed frame heads on a
	// given branch
	if from >= 2 {
		from--
	}

	for {
		if to == 0 || to-from > 16 {
			if max > from+15 {
				to = from + 16
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
	peerId []byte,
	syncMsg *protobufs.CeremonyCompressedSync,
) (*protobufs.ClockFrame, error) {
	if len(syncMsg.TruncatedClockFrames) == 0 {
		return nil, ErrNoNewFrames
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
			append(
				p2p.GetBloomFilter(application.CEREMONY_ADDRESS, 256, 3),
				p2p.GetBloomFilterIndices(application.CEREMONY_ADDRESS, 65536, 24)...,
			),
			any,
			true,
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
	protobufs.UnimplementedCeremonyServiceServer
	svrChan chan protobufs.CeremonyService_GetPublicChannelServer
}

func (e *svr) GetCompressedSyncFrames(
	request *protobufs.ClockFramesRequest,
	server protobufs.CeremonyService_GetCompressedSyncFramesServer,
) error {
	return errors.New("not supported")
}

func (e *svr) NegotiateCompressedSyncFrames(
	server protobufs.CeremonyService_NegotiateCompressedSyncFramesServer,
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
	peerID []byte,
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
