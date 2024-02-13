package master

import (
	"time"

	"github.com/pkg/errors"
	"go.uber.org/zap"
	"source.quilibrium.com/quilibrium/monorepo/go-libp2p-blossomsub/pb"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus"
	"source.quilibrium.com/quilibrium/monorepo/node/p2p"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
)

func (e *MasterClockConsensusEngine) prove(
	previousFrame *protobufs.ClockFrame,
) (*protobufs.ClockFrame, error) {
	e.logger.Debug("proving new frame")

	frame, err := e.frameProver.ProveMasterClockFrame(
		previousFrame,
		time.Now().UnixMilli(),
		e.difficulty,
	)
	if err != nil {
		return nil, errors.Wrap(err, "prove")
	}

	e.state = consensus.EngineStatePublishing
	e.logger.Debug("returning new proven frame")
	return frame, nil
}

func (e *MasterClockConsensusEngine) collect(
	currentFramePublished *protobufs.ClockFrame,
) (*protobufs.ClockFrame, error) {
	e.logger.Debug("collecting vdf proofs")

	latest, err := e.masterTimeReel.Head()
	if err != nil {
		panic(err)
	}

	if e.syncingStatus == SyncStatusNotSyncing {
		peer, err := e.pubSub.GetRandomPeer(e.filter)
		if err != nil {
			if errors.Is(err, p2p.ErrNoPeersAvailable) {
				e.logger.Debug("no peers available, skipping sync")
			} else {
				e.logger.Error("error while fetching random peer", zap.Error(err))
			}
		} else {
			e.syncingStatus = SyncStatusAwaitingResponse
			e.logger.Debug("setting syncing target", zap.Binary("peer_id", peer))
			e.syncingTarget = peer

			channel := e.createPeerReceiveChannel(peer)
			e.logger.Debug(
				"listening on peer receive channel",
				zap.Binary("channel", channel),
			)
			e.pubSub.Subscribe(channel, e.handleSync, true)
			e.pubSub.Subscribe(
				peer,
				func(message *pb.Message) error { return nil },
				true,
			)

			go func() {
				time.Sleep(2 * time.Second)
				if err := e.publishMessage(peer, &protobufs.ClockFramesRequest{
					Filter:          e.filter,
					FromFrameNumber: latest.FrameNumber + 1,
				}); err != nil {
					e.logger.Error(
						"could not publish clock frame request",
						zap.Error(err),
					)
				}
			}()
		}
	}

	waitDecay := time.Duration(2000)
	for e.syncingStatus != SyncStatusNotSyncing {
		e.logger.Debug(
			"waiting for sync to complete...",
			zap.Duration("wait_decay", waitDecay),
		)

		time.Sleep(waitDecay * time.Millisecond)

		waitDecay = waitDecay * 2
		if waitDecay >= (100 * (2 << 6)) {
			if e.syncingStatus == SyncStatusAwaitingResponse {
				e.logger.Debug("maximum wait for sync response, skipping sync")
				e.syncingStatus = SyncStatusNotSyncing
				break
			} else {
				waitDecay = 100 * (2 << 6)
			}
		}
	}

	return latest, nil
}
