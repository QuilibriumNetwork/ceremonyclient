package ceremony

import (
	"bytes"
	"context"
	"time"

	"source.quilibrium.com/quilibrium/monorepo/node/config"

	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus"
	qcrypto "source.quilibrium.com/quilibrium/monorepo/node/crypto"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/ceremony/application"
	"source.quilibrium.com/quilibrium/monorepo/node/p2p"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
)

func (e *CeremonyDataClockConsensusEngine) prove(
	previousFrame *protobufs.ClockFrame,
) (*protobufs.ClockFrame, error) {
	if !e.frameProverTrie.Contains(e.provingKeyAddress) {
		e.stagedLobbyStateTransitionsMx.Lock()
		e.stagedLobbyStateTransitions = &protobufs.CeremonyLobbyStateTransition{}
		e.stagedLobbyStateTransitionsMx.Unlock()

		e.state = consensus.EngineStateCollecting
		return previousFrame, nil
	}

	e.stagedLobbyStateTransitionsMx.Lock()
	executionOutput := &protobufs.IntrinsicExecutionOutput{}
	app, err := application.MaterializeApplicationFromFrame(previousFrame)
	if err != nil {
		e.stagedLobbyStateTransitions = &protobufs.CeremonyLobbyStateTransition{}
		e.stagedLobbyStateTransitionsMx.Unlock()
		return nil, errors.Wrap(err, "prove")
	}

	if e.stagedLobbyStateTransitions == nil {
		e.stagedLobbyStateTransitions = &protobufs.CeremonyLobbyStateTransition{}
	}

	e.logger.Info(
		"proving new frame",
		zap.Int("state_transitions", len(e.stagedLobbyStateTransitions.TypeUrls)),
	)

	var validLobbyTransitions *protobufs.CeremonyLobbyStateTransition
	var skippedTransition *protobufs.CeremonyLobbyStateTransition
	app, validLobbyTransitions, skippedTransition, err = app.ApplyTransition(
		previousFrame.FrameNumber,
		e.stagedLobbyStateTransitions,
		true,
	)
	if err != nil {
		e.stagedLobbyStateTransitions = &protobufs.CeremonyLobbyStateTransition{}
		e.stagedLobbyStateTransitionsMx.Unlock()
		return nil, errors.Wrap(err, "prove")
	}

	e.stagedLobbyStateTransitions = skippedTransition
	defer e.stagedLobbyStateTransitionsMx.Unlock()

	lobbyState, err := app.MaterializeLobbyStateFromApplication()
	if err != nil {
		return nil, errors.Wrap(err, "prove")
	}

	executionOutput.Address = application.CEREMONY_ADDRESS
	executionOutput.Output, err = proto.Marshal(lobbyState)
	if err != nil {
		return nil, errors.Wrap(err, "prove")
	}

	executionOutput.Proof, err = proto.Marshal(validLobbyTransitions)
	if err != nil {
		return nil, errors.Wrap(err, "prove")
	}

	data, err := proto.Marshal(executionOutput)
	if err != nil {
		return nil, errors.Wrap(err, "prove")
	}

	e.logger.Debug("encoded execution output")

	commitment, err := e.inclusionProver.Commit(
		data,
		protobufs.IntrinsicExecutionOutputType,
	)
	if err != nil {
		return nil, errors.Wrap(err, "prove")
	}

	e.logger.Debug("creating kzg proof")
	proof, err := e.inclusionProver.ProveAggregate(
		[]*qcrypto.InclusionCommitment{commitment},
	)
	if err != nil {
		return nil, errors.Wrap(err, "prove")
	}

	e.logger.Debug("finalizing execution proof")

	frame, err := e.frameProver.ProveDataClockFrame(
		previousFrame,
		[][]byte{proof.AggregateCommitment},
		[]*protobufs.InclusionAggregateProof{
			{
				Filter:      e.filter,
				FrameNumber: previousFrame.FrameNumber + 1,
				InclusionCommitments: []*protobufs.InclusionCommitment{
					{
						Filter:      e.filter,
						FrameNumber: previousFrame.FrameNumber + 1,
						TypeUrl:     proof.InclusionCommitments[0].TypeUrl,
						Commitment:  proof.InclusionCommitments[0].Commitment,
						Data:        data,
						Position:    0,
					},
				},
				Proof: proof.Proof,
			},
		},
		e.provingKey,
		time.Now().UnixMilli(),
		e.difficulty,
	)
	if err != nil {
		return nil, errors.Wrap(err, "prove")
	}
	e.logger.Info(
		"returning new proven frame",
		zap.Uint64("frame_number", frame.FrameNumber),
		zap.Int("proof_count", len(frame.AggregateProofs)),
		zap.Int("commitment_count", len(frame.Input[516:])/74),
	)
	return frame, nil
}

func (e *CeremonyDataClockConsensusEngine) GetMostAheadPeer(
	frameNumber uint64,
) (
	[]byte,
	uint64,
	error,
) {
	e.logger.Info(
		"checking peer list",
		zap.Int("peers", len(e.peerMap)),
		zap.Int("uncooperative_peers", len(e.uncooperativePeersMap)),
		zap.Uint64("current_head_frame", frameNumber),
	)

	max := frameNumber
	var peer []byte = nil
	e.peerMapMx.RLock()
	for _, v := range e.peerMap {
		e.logger.Debug(
			"checking peer info",
			zap.Binary("peer_id", v.peerId),
			zap.Uint64("max_frame_number", v.maxFrame),
			zap.Int64("timestamp", v.timestamp),
			zap.Binary("version", v.version),
		)
		_, ok := e.uncooperativePeersMap[string(v.peerId)]
		if v.maxFrame > max &&
			v.timestamp > config.GetMinimumVersionCutoff().UnixMilli() &&
			bytes.Compare(v.version, config.GetMinimumVersion()) >= 0 && !ok {
			peer = v.peerId
			max = v.maxFrame
		}
	}
	e.peerMapMx.RUnlock()

	if peer == nil {
		return nil, 0, p2p.ErrNoPeersAvailable
	}

	return peer, max, nil
}

func (e *CeremonyDataClockConsensusEngine) sync(
	currentLatest *protobufs.ClockFrame,
	maxFrame uint64,
	peerId []byte,
) (*protobufs.ClockFrame, error) {
	latest := currentLatest
	e.logger.Info("polling peer for new frames", zap.Binary("peer_id", peerId))
	cc, err := e.pubSub.GetDirectChannel(peerId, "")
	if err != nil {
		e.logger.Debug(
			"could not establish direct channel",
			zap.Error(err),
		)
		e.peerMapMx.Lock()
		if _, ok := e.peerMap[string(peerId)]; ok {
			e.uncooperativePeersMap[string(peerId)] = e.peerMap[string(peerId)]
			e.uncooperativePeersMap[string(peerId)].timestamp = time.Now().UnixMilli()
			delete(e.peerMap, string(peerId))
		}
		e.peerMapMx.Unlock()
		return latest, errors.Wrap(err, "sync")
	}

	client := protobufs.NewCeremonyServiceClient(cc)

	response, err := client.GetDataFrame(
		context.TODO(),
		&protobufs.GetDataFrameRequest{
			FrameNumber: 0,
		},
		grpc.MaxCallRecvMsgSize(600*1024*1024),
	)
	if err != nil {
		e.logger.Debug(
			"could not get frame",
			zap.Error(err),
		)
		e.peerMapMx.Lock()
		if _, ok := e.peerMap[string(peerId)]; ok {
			e.uncooperativePeersMap[string(peerId)] = e.peerMap[string(peerId)]
			e.uncooperativePeersMap[string(peerId)].timestamp = time.Now().UnixMilli()
			delete(e.peerMap, string(peerId))
		}
		e.peerMapMx.Unlock()
		if err := cc.Close(); err != nil {
			e.logger.Error("error while closing connection", zap.Error(err))
		}
		return latest, errors.Wrap(err, "sync")
	}

	if response == nil {
		e.logger.Debug("received no response from peer")
		if err := cc.Close(); err != nil {
			e.logger.Error("error while closing connection", zap.Error(err))
		}
		return latest, nil
	}

	e.logger.Info(
		"received new leading frame",
		zap.Uint64("frame_number", response.ClockFrame.FrameNumber),
	)
	if err := cc.Close(); err != nil {
		e.logger.Error("error while closing connection", zap.Error(err))
	}

	e.dataTimeReel.Insert(response.ClockFrame, false)

	return response.ClockFrame, nil
}

func (e *CeremonyDataClockConsensusEngine) collect(
	currentFramePublished *protobufs.ClockFrame,
) (*protobufs.ClockFrame, error) {
	e.logger.Info("collecting vdf proofs")

	latest := currentFramePublished

	for {
		peerId, maxFrame, err := e.GetMostAheadPeer(latest.FrameNumber)
		if maxFrame > latest.FrameNumber {
			e.syncingStatus = SyncStatusSynchronizing
			if err != nil {
				e.logger.Info("no peers available for sync, waiting")
				time.Sleep(5 * time.Second)
			} else if maxFrame > latest.FrameNumber {
				masterHead, err := e.masterTimeReel.Head()
				if err != nil {
					panic(err)
				}

				if masterHead.FrameNumber < maxFrame {
					e.logger.Info(
						"master frame synchronization needed to continue, waiting",
						zap.Uint64("master_frame_head", masterHead.FrameNumber),
						zap.Uint64("max_data_frame_target", maxFrame),
					)

					time.Sleep(30 * time.Second)
					continue
				}

				latest, err = e.sync(latest, maxFrame, peerId)
				if err == nil {
					break
				}
			}
		} else {
			break
		}
	}

	e.syncingStatus = SyncStatusNotSyncing

	if latest.FrameNumber < currentFramePublished.FrameNumber {
		latest = currentFramePublished
	}

	e.logger.Info(
		"returning leader frame",
		zap.Uint64("frame_number", latest.FrameNumber),
	)

	return latest, nil
}
