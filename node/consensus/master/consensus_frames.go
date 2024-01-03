package master

import (
	"bytes"
	"encoding/binary"
	"sort"
	"time"

	"github.com/pkg/errors"
	"go.uber.org/zap"
	"golang.org/x/crypto/sha3"
	"source.quilibrium.com/quilibrium/monorepo/go-libp2p-blossomsub/pb"
	"source.quilibrium.com/quilibrium/monorepo/nekryptology/pkg/vdf"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus"
	"source.quilibrium.com/quilibrium/monorepo/node/p2p"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
)

func (e *MasterClockConsensusEngine) prove(
	previousFrame *protobufs.ClockFrame,
) (*protobufs.ClockFrame, error) {
	if e.state == consensus.EngineStateProving {
		e.logger.Debug("proving new frame")

		frame, err := protobufs.ProveMasterClockFrame(
			previousFrame,
			e.difficulty,
		)
		if err != nil {
			return nil, errors.Wrap(err, "prove")
		}

		e.state = consensus.EngineStatePublishing
		e.logger.Debug("returning new proven frame")
		return frame, nil
	}

	return nil, nil
}

func (e *MasterClockConsensusEngine) setFrame(frame *protobufs.ClockFrame) {
	previousSelectorBytes := [516]byte{}
	copy(previousSelectorBytes[:], frame.Output[:516])

	e.logger.Debug("set frame", zap.Uint64("frame_number", frame.FrameNumber))
	e.frame = frame

	go func() {
		e.frameChan <- e.frame
	}()
}

func (
	e *MasterClockConsensusEngine,
) CreateGenesisFrame() *protobufs.ClockFrame {
	e.logger.Debug("creating genesis frame")
	b := sha3.Sum256(e.input)
	v := vdf.New(e.difficulty, b)

	v.Execute()
	o := v.GetOutput()
	inputMessage := o[:]

	e.logger.Debug("proving genesis frame")
	input := []byte{}
	input = append(input, e.filter...)
	input = binary.BigEndian.AppendUint64(input, 0)
	input = binary.BigEndian.AppendUint32(input, e.difficulty)
	if bytes.Equal(e.input, []byte{0x00}) {
		value := [516]byte{}
		input = append(input, value[:]...)
	} else {
		input = append(input, e.input...)
	}

	b = sha3.Sum256(input)
	v = vdf.New(e.difficulty, b)

	v.Execute()
	o = v.GetOutput()

	frame := &protobufs.ClockFrame{
		Filter:      e.filter,
		FrameNumber: 0,
		Timestamp:   0,
		Difficulty:  e.difficulty,
		Input:       inputMessage,
		Output:      o[:],
		ParentSelector: []byte{
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		},
		AggregateProofs:    []*protobufs.InclusionAggregateProof{},
		PublicKeySignature: nil,
	}

	e.setFrame(frame)
	return frame
}

func (e *MasterClockConsensusEngine) collect(
	currentFramePublished *protobufs.ClockFrame,
) (*protobufs.ClockFrame, error) {
	if e.state == consensus.EngineStateCollecting {
		e.logger.Debug("collecting vdf proofs")

		latest := e.frame

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

		e.logger.Debug("selecting leader")
		latestFrame, err := e.confirmLatestFrame()
		if err != nil {
			e.logger.Error("could not confirm latest frame", zap.Error(err))
			return nil, errors.Wrap(err, "collect")
		}

		e.logger.Debug(
			"returning leader frame",
			zap.Uint64("frame_number", latestFrame.FrameNumber),
		)

		e.state = consensus.EngineStateProving
		return latestFrame, nil
	}

	return nil, nil
}

func (
	e *MasterClockConsensusEngine,
) confirmLatestFrame() (*protobufs.ClockFrame, error) {
	e.seenFramesMx.Lock()
	defer e.seenFramesMx.Unlock()

	sort.Slice(e.seenFrames, func(i, j int) bool {
		return e.seenFrames[i].FrameNumber < e.seenFrames[j].FrameNumber
	})

	if len(e.seenFrames) == 0 {
		return e.frame, nil
	}

	prev := e.frame
	committedSet := []*protobufs.ClockFrame{}

	for len(e.seenFrames) > 0 {
		curr := e.seenFrames[0]
		e.seenFrames = e.seenFrames[1:]

		e.logger.Debug(
			"checking continuity for frame",
			zap.Uint64("frame_number", curr.FrameNumber),
		)

		if prev.FrameNumber+1 < curr.FrameNumber ||
			prev.FrameNumber > curr.FrameNumber {
			e.logger.Debug(
				"continuity break found",
				zap.Uint64("prev_frame_number", prev.FrameNumber),
				zap.Uint64("curr_frame_number", curr.FrameNumber),
			)
			break
		}

		if bytes.Equal(prev.Output, curr.Input[:516]) {
			prev = curr
			committedSet = append(committedSet, prev)
		} else {
			e.logger.Debug("frame mismatch on input/output")
		}
	}

	txn, err := e.clockStore.NewTransaction()
	if err != nil {
		e.logger.Error("error while creating transaction", zap.Error(err))
		return nil, errors.Wrap(err, "confirm latest frame")
	}

	for _, frame := range committedSet {
		frame := frame
		if err = e.clockStore.PutMasterClockFrame(frame, txn); err != nil {
			e.logger.Error("error while committing frame", zap.Error(err))
			return nil, errors.Wrap(err, "confirm latest frame")
		}
	}

	if err = txn.Commit(); err != nil {
		e.logger.Error("error while committing transaction", zap.Error(err))
		return nil, errors.Wrap(err, "confirm latest frame")
	}

	e.logger.Debug("stored frames", zap.Int("frame_count", len(committedSet)))

	e.historicFramesMx.Lock()

	e.historicFrames = append(e.historicFrames, committedSet...)
	if len(e.historicFrames) > 256 {
		e.historicFrames = e.historicFrames[len(e.historicFrames)-256:]
	}

	e.historicFramesMx.Unlock()

	e.setFrame(prev)

	return prev, nil
}
