package master

import (
	"bytes"
	"strings"
	"time"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"source.quilibrium.com/quilibrium/monorepo/go-libp2p-blossomsub/pb"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
)

func (e *MasterClockConsensusEngine) handleMessage(message *pb.Message) error {
	e.logger.Debug(
		"received message",
		zap.Binary("data", message.Data),
		zap.Binary("from", message.From),
		zap.Binary("signature", message.Signature),
	)
	msg := &protobufs.Message{}

	if err := proto.Unmarshal(message.Data, msg); err != nil {
		return errors.Wrap(err, "handle message")
	}

	any := &anypb.Any{}
	if err := proto.Unmarshal(msg.Payload, any); err != nil {
		return errors.Wrap(err, "handle message")
	}

	eg := errgroup.Group{}
	eg.SetLimit(len(e.executionEngines))

	for name := range e.executionEngines {
		name := name
		eg.Go(func() error {
			messages, err := e.executionEngines[name].ProcessMessage(
				msg.Address,
				msg,
			)
			if err != nil {
				e.logger.Error(
					"could not process message for engine",
					zap.Error(err),
					zap.String("engine_name", name),
				)
				return errors.Wrap(err, "handle message")
			}

			for _, m := range messages {
				if err := e.publishMessage(m.Address, m); err != nil {
					e.logger.Error(
						"could not publish message for engine",
						zap.Error(err),
						zap.String("engine_name", name),
					)
					return errors.Wrap(err, "handle message")
				}
			}

			return nil
		})
	}

	if err := eg.Wait(); err != nil {
		e.logger.Error("rejecting invalid message", zap.Error(err))
		return errors.Wrap(err, "execution failed")
	}

	switch any.TypeUrl {
	case protobufs.ClockFrameType:
		if err := e.handleClockFrameData(
			message.From,
			any,
		); err != nil {
			return errors.Wrap(err, "handle message")
		}
	}

	return nil
}

func (e *MasterClockConsensusEngine) handleClockFrameData(
	peerID []byte,
	any *anypb.Any,
) error {
	frame := &protobufs.ClockFrame{}
	if err := any.UnmarshalTo(frame); err != nil {
		return errors.Wrap(err, "handle clock frame data")
	}

	if e.frame > frame.FrameNumber {
		e.logger.Info(
			"received anachronistic frame",
			zap.Binary("sender", peerID),
			zap.Binary("filter", frame.Filter),
			zap.Uint64("frame_number", frame.FrameNumber),
			zap.Int("proof_count", len(frame.AggregateProofs)),
		)
		return nil
	}

	if e.difficulty != frame.Difficulty {
		e.logger.Info(
			"frame difficulty mismatched",
			zap.Uint32("difficulty", frame.Difficulty),
		)
		return errors.Wrap(
			errors.New("frame difficulty"),
			"handle clock frame data",
		)
	}

	e.logger.Info(
		"got clock frame",
		zap.Binary("sender", peerID),
		zap.Binary("filter", frame.Filter),
		zap.Uint64("frame_number", frame.FrameNumber),
		zap.Int("proof_count", len(frame.AggregateProofs)),
	)

	if err := frame.VerifyMasterClockFrame(); err != nil {
		e.logger.Error("could not verify clock frame", zap.Error(err))
		return errors.Wrap(err, "handle clock frame data")
	}

	if e.frame < frame.FrameNumber {
		if err := e.enqueueSeenFrame(frame); err != nil {
			e.logger.Error("could not enqueue seen clock frame", zap.Error(err))
			return errors.Wrap(err, "handle clock frame data")
		}
	}

	return nil
}

func (e *MasterClockConsensusEngine) enqueueSeenFrame(
	frame *protobufs.ClockFrame,
) error {
	e.seenFramesMx.Lock()
	found := false
	for _, f := range e.seenFrames {
		if f.FrameNumber == frame.FrameNumber &&
			bytes.Equal(f.Input, frame.Input) &&
			f.Difficulty == frame.Difficulty &&
			bytes.Equal(f.Output, frame.Output) {
			found = true
		}
	}
	if !found {
		e.logger.Info(
			"enqueuing frame for consensus",
			zap.Uint64("frame_number", frame.FrameNumber),
		)
		e.seenFrames = append(e.seenFrames, frame)
		e.lastFrameReceivedAt = time.Now().UTC()
	}
	e.seenFramesMx.Unlock()
	return nil
}

func (e *MasterClockConsensusEngine) publishProof(
	frame *protobufs.ClockFrame,
) error {
	if e.state == consensus.EngineStatePublishing {
		e.logger.Info(
			"publishing frame",
			zap.Uint64("frame_number", frame.FrameNumber),
		)
		e.enqueueSeenFrame(frame)
		if err := e.publishMessage(e.filter, frame); err != nil {
			return errors.Wrap(
				err,
				"publish proof",
			)
		}

		e.state = consensus.EngineStateCollecting
	}

	return nil
}

func (e *MasterClockConsensusEngine) publishMessage(
	filter []byte,
	message proto.Message,
) error {
	any := &anypb.Any{}
	if err := any.MarshalFrom(message); err != nil {
		return errors.Wrap(err, "publish message")
	}

	// annoying protobuf any hack
	any.TypeUrl = strings.Replace(
		any.TypeUrl,
		"type.googleapis.com",
		"types.quilibrium.com",
		1,
	)

	payload, err := proto.Marshal(any)
	if err != nil {
		return errors.Wrap(err, "publish message")
	}

	h, err := poseidon.HashBytes(payload)
	if err != nil {
		return errors.Wrap(err, "publish message")
	}

	msg := &protobufs.Message{
		Hash:    h.Bytes(),
		Address: e.filter,
		Payload: payload,
	}
	data, err := proto.Marshal(msg)
	if err != nil {
		return errors.Wrap(err, "publish message")
	}
	return e.pubSub.PublishToBitmask(filter, data)
}
