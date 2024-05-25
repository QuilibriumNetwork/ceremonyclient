package master

import (
	"context"
	"time"

	"github.com/mr-tron/base58"
	"github.com/pkg/errors"
	"go.uber.org/zap"
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

func (e *MasterClockConsensusEngine) GetMostAheadPeers() (
	[][]byte,
	error,
) {
	frame, err := e.masterTimeReel.Head()
	if err != nil {
		panic(err)
	}

	// Needs to be enough to make the sync worthwhile:
	max := frame.FrameNumber + 10

	var peers [][]byte = [][]byte{}
	peerMap := e.peerInfoManager.GetPeerMap()
	for peerId, v := range peerMap {
		if v.MasterHeadFrame > max {
			peers = append(peers, []byte(peerId))
		}

		if len(peers) >= 30 {
			break
		}
	}

	if len(peers) == 0 {
		return nil, p2p.ErrNoPeersAvailable
	}

	return peers, nil
}

func (e *MasterClockConsensusEngine) collect(
	currentFramePublished *protobufs.ClockFrame,
) (*protobufs.ClockFrame, error) {
	e.logger.Debug("collecting vdf proofs")

	latest, err := e.masterTimeReel.Head()
	if err != nil {
		panic(err)
	}

	// With the increase of network size, constrain down to top thirty
	peers, err := e.GetMostAheadPeers()
	if err != nil {
		return latest, nil
	}

	for i := 0; i < len(peers); i++ {
		peer := peers[i]
		e.logger.Info("setting syncing target", zap.Binary("peer_id", peer))

		cc, err := e.pubSub.GetDirectChannel(peer, "validation")
		if err != nil {
			e.logger.Error(
				"could not connect for sync",
				zap.String("peer_id", base58.Encode(peer)),
			)
			continue
		}
		client := protobufs.NewValidationServiceClient(cc)
		syncClient, err := client.Sync(
			context.Background(),
			&protobufs.SyncRequest{
				FramesRequest: &protobufs.ClockFramesRequest{
					Filter:          e.filter,
					FromFrameNumber: latest.FrameNumber,
					ToFrameNumber:   0,
				},
			},
		)
		if err != nil {
			cc.Close()
			continue
		}

		for msg, err := syncClient.Recv(); msg != nil &&
			err == nil; msg, err = syncClient.Recv() {
			if msg.FramesResponse == nil {
				break
			}

			for _, frame := range msg.FramesResponse.ClockFrames {
				frame := frame

				if frame.FrameNumber < latest.FrameNumber {
					continue
				}

				if e.difficulty != frame.Difficulty {
					e.logger.Debug(
						"frame difficulty mismatched",
						zap.Uint32("difficulty", frame.Difficulty),
					)
					break
				}

				if err := e.frameProver.VerifyMasterClockFrame(frame); err != nil {
					e.logger.Error(
						"peer returned invalid frame",
						zap.String("peer_id", base58.Encode(peer)))
					e.pubSub.SetPeerScore(peer, -1000)
					break
				}

				e.masterTimeReel.Insert(frame, false)
				latest = frame
			}
		}
		if err != nil {
			cc.Close()
			break
		}
		cc.Close()
		break
	}

	return latest, nil
}
