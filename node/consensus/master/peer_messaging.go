package master

import (
	"bytes"

	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"source.quilibrium.com/quilibrium/monorepo/go-libp2p-blossomsub/pb"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
)

func (e *MasterClockConsensusEngine) handleSync(message *pb.Message) error {
	e.logger.Debug(
		"received peer message",
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

	switch any.TypeUrl {
	case protobufs.ClockFramesResponseType:
		if err := e.handleClockFramesResponse(
			message.From,
			any,
		); err != nil {
			return errors.Wrap(err, "handle sync")
		}
	case protobufs.ClockFramesRequestType:
		if err := e.handleClockFramesRequest(
			message.From,
			any,
		); err != nil {
			return errors.Wrap(err, "handle sync")
		}
	}

	return nil
}

func (e *MasterClockConsensusEngine) createPeerReceiveChannel(
	peerID []byte,
) []byte {
	return append(append([]byte{}, peerID...), e.pubSub.GetPeerID()...)
}

func (e *MasterClockConsensusEngine) createPeerSendChannel(
	peerID []byte,
) []byte {
	return append(append([]byte{}, e.pubSub.GetPeerID()...), peerID...)
}

func (e *MasterClockConsensusEngine) handleClockFramesResponse(
	peerID []byte,
	any *anypb.Any,
) error {
	if bytes.Equal(peerID, e.pubSub.GetPeerID()) {
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

	for _, frame := range response.ClockFrames {
		frame := frame
		e.logger.Debug(
			"processing clock frame",
			zap.Binary("sender", peerID),
			zap.Binary("filter", frame.Filter),
			zap.Uint64("frame_number", frame.FrameNumber),
		)

		if err := frame.VerifyMasterClockFrame(); err != nil {
			e.logger.Error("could not verify clock frame", zap.Error(err))
			return errors.Wrap(err, "handle clock frame response")
		}

		e.logger.Debug(
			"clock frame was valid",
			zap.Binary("sender", peerID),
			zap.Binary("filter", frame.Filter),
			zap.Uint64("frame_number", frame.FrameNumber),
		)

		if e.frame.FrameNumber < frame.FrameNumber {
			if err := e.enqueueSeenFrame(frame); err != nil {
				e.logger.Error("could not enqueue seen clock frame", zap.Error(err))
				return errors.Wrap(err, "handle clock frame response")
			}
		}
	}

	return nil
}

func (e *MasterClockConsensusEngine) handleClockFramesRequest(
	peerID []byte,
	any *anypb.Any,
) error {
	if bytes.Equal(peerID, e.pubSub.GetPeerID()) {
		return nil
	}

	request := &protobufs.ClockFramesRequest{}
	if err := any.UnmarshalTo(request); err != nil {
		return errors.Wrap(err, "handle clock frame request")
	}

	channel := e.createPeerSendChannel(peerID)

	e.pubSub.Subscribe(channel, e.handleSync, true)

	e.logger.Debug(
		"received clock frame request",
		zap.Binary("peer_id", peerID),
		zap.Uint64("from_frame_number", request.FromFrameNumber),
		zap.Uint64("to_frame_number", request.ToFrameNumber),
	)

	from := request.FromFrameNumber

	if e.frame.FrameNumber < from || len(e.historicFrames) == 0 {
		e.logger.Debug(
			"peer asked for undiscovered frame",
			zap.Binary("peer_id", peerID),
			zap.Uint64("frame_number", request.FromFrameNumber),
		)

		if err := e.publishMessage(channel, &protobufs.ClockFramesResponse{
			Filter:          request.Filter,
			FromFrameNumber: 0,
			ToFrameNumber:   0,
			ClockFrames:     []*protobufs.ClockFrame{},
		}); err != nil {
			return errors.Wrap(err, "handle clock frame request")
		}

		return nil
	}

	to := request.ToFrameNumber
	if to == 0 || to-request.FromFrameNumber > 128 {
		to = request.FromFrameNumber + 127
	}

	if int(to) > int(e.frame.FrameNumber) {
		to = e.frame.FrameNumber
	}

	e.logger.Debug(
		"sending response",
		zap.Binary("peer_id", peerID),
		zap.Uint64("from", from),
		zap.Uint64("to", to),
		zap.Uint64("total_frames", uint64(to-from+1)),
	)

	iter, err := e.clockStore.RangeMasterClockFrames(
		request.Filter,
		from,
		to,
	)
	if err != nil {
		return errors.Wrap(err, "handle clock frame request")
	}

	response := []*protobufs.ClockFrame{}

	for iter.First(); iter.Valid(); iter.Next() {
		frame, err := iter.Value()
		if err != nil {
			return errors.Wrap(err, "handle clock frame request")
		}

		response = append(response, frame)
	}

	if err = iter.Close(); err != nil {
		return errors.Wrap(err, "handle clock frame request")
	}

	if err := e.publishMessage(channel, &protobufs.ClockFramesResponse{
		Filter:          request.Filter,
		FromFrameNumber: request.FromFrameNumber,
		ToFrameNumber:   to,
		ClockFrames:     response,
	}); err != nil {
		return errors.Wrap(err, "handle clock frame request")
	}

	return nil
}
