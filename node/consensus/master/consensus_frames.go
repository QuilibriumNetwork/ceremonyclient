package master

import (
	"time"

	"github.com/pkg/errors"
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
	latest, err := e.masterTimeReel.Head()
	if err != nil {
		panic(err)
	}

	return latest, nil
}
