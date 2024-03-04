package master

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"strings"
	"time"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/mr-tron/base58"
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
				m := m
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
	case protobufs.SelfTestReportType:
		if err := e.handleSelfTestReport(
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

	if e.difficulty != frame.Difficulty {
		e.logger.Debug(
			"frame difficulty mismatched",
			zap.Uint32("difficulty", frame.Difficulty),
		)
		return errors.Wrap(
			errors.New("frame difficulty"),
			"handle clock frame data",
		)
	}

	e.logger.Debug(
		"got clock frame",
		zap.Binary("sender", peerID),
		zap.Binary("filter", frame.Filter),
		zap.Uint64("frame_number", frame.FrameNumber),
		zap.Int("proof_count", len(frame.AggregateProofs)),
	)

	if err := e.frameProver.VerifyMasterClockFrame(frame); err != nil {
		e.logger.Error("could not verify clock frame", zap.Error(err))
		return errors.Wrap(err, "handle clock frame data")
	}

	e.masterTimeReel.Insert(frame)

	return nil
}

func (e *MasterClockConsensusEngine) handleSelfTestReport(
	peerID []byte,
	any *anypb.Any,
) error {
	if bytes.Equal(peerID, e.pubSub.GetPeerID()) {
		return nil
	}

	report := &protobufs.SelfTestReport{}
	if err := any.UnmarshalTo(report); err != nil {
		return errors.Wrap(err, "handle self test report")
	}

	e.peerMapMx.Lock()
	if _, ok := e.peerMap[string(peerID)]; ok {
		e.peerMapMx.Unlock()
		return nil
	}
	e.peerMap[string(peerID)] = report
	e.peerMapMx.Unlock()

	memory := binary.BigEndian.Uint64(report.Memory)
	e.logger.Info(
		"received self test report",
		zap.String("peer_id", base58.Encode(peerID)),
		zap.Uint32("difficulty", report.Difficulty),
		zap.Int64("difficulty_metric", report.DifficultyMetric),
		zap.Int64("commit_16_metric", report.Commit_16Metric),
		zap.Int64("commit_128_metric", report.Commit_128Metric),
		zap.Int64("commit_1024_metric", report.Commit_1024Metric),
		zap.Int64("commit_65536_metric", report.Commit_65536Metric),
		zap.Int64("proof_16_metric", report.Proof_16Metric),
		zap.Int64("proof_128_metric", report.Proof_128Metric),
		zap.Int64("proof_1024_metric", report.Proof_1024Metric),
		zap.Int64("proof_65536_metric", report.Proof_65536Metric),
		zap.Uint32("cores", report.Cores),
		zap.Uint64("memory", memory),
		zap.Uint64("storage", binary.BigEndian.Uint64(report.Storage)),
	)

	if report.Cores < 3 || memory < 16000000000 {
		e.logger.Info(
			"peer reported invalid configuration",
			zap.String("peer_id", base58.Encode(peerID)),
			zap.Uint32("difficulty", report.Difficulty),
			zap.Int64("difficulty_metric", report.DifficultyMetric),
			zap.Int64("commit_16_metric", report.Commit_16Metric),
			zap.Int64("commit_128_metric", report.Commit_128Metric),
			zap.Int64("commit_1024_metric", report.Commit_1024Metric),
			zap.Int64("commit_65536_metric", report.Commit_65536Metric),
			zap.Int64("proof_16_metric", report.Proof_16Metric),
			zap.Int64("proof_128_metric", report.Proof_128Metric),
			zap.Int64("proof_1024_metric", report.Proof_1024Metric),
			zap.Int64("proof_65536_metric", report.Proof_65536Metric),
			zap.Uint32("cores", report.Cores),
			zap.Uint64("memory", memory),
			zap.Uint64("storage", binary.BigEndian.Uint64(report.Storage)),
		)

		// tag: dusk – nuke this peer for now
		e.pubSub.SetPeerScore(peerID, -1000)
		return nil
	}

	cc, err := e.pubSub.GetDirectChannel(peerID, "validation")
	if err != nil {
		e.logger.Error(
			"could not connect for validation",
			zap.String("peer_id", base58.Encode(peerID)),
			zap.Uint32("difficulty", report.Difficulty),
			zap.Int64("difficulty_metric", report.DifficultyMetric),
			zap.Int64("commit_16_metric", report.Commit_16Metric),
			zap.Int64("commit_128_metric", report.Commit_128Metric),
			zap.Int64("commit_1024_metric", report.Commit_1024Metric),
			zap.Int64("commit_65536_metric", report.Commit_65536Metric),
			zap.Int64("proof_16_metric", report.Proof_16Metric),
			zap.Int64("proof_128_metric", report.Proof_128Metric),
			zap.Int64("proof_1024_metric", report.Proof_1024Metric),
			zap.Int64("proof_65536_metric", report.Proof_65536Metric),
			zap.Uint32("cores", report.Cores),
			zap.Uint64("memory", memory),
			zap.Uint64("storage", binary.BigEndian.Uint64(report.Storage)),
		)
		return errors.Wrap(err, "handle self test report")
	}
	client := protobufs.NewValidationServiceClient(cc)
	verification := make([]byte, 1048576)
	rand.Read(verification)
	start := time.Now().UnixMilli()
	validation, err := client.PerformValidation(
		context.Background(),
		&protobufs.ValidationMessage{
			Validation: verification,
		},
	)
	end := time.Now().UnixMilli()
	if err != nil {
		cc.Close()
		return errors.Wrap(err, "handle self test report")
	}
	cc.Close()

	if !bytes.Equal(verification, validation.Validation) {
		e.logger.Error(
			"provided invalid verification",
			zap.String("peer_id", base58.Encode(peerID)),
			zap.Uint32("difficulty", report.Difficulty),
			zap.Int64("difficulty_metric", report.DifficultyMetric),
			zap.Int64("commit_16_metric", report.Commit_16Metric),
			zap.Int64("commit_128_metric", report.Commit_128Metric),
			zap.Int64("commit_1024_metric", report.Commit_1024Metric),
			zap.Int64("commit_65536_metric", report.Commit_65536Metric),
			zap.Int64("proof_16_metric", report.Proof_16Metric),
			zap.Int64("proof_128_metric", report.Proof_128Metric),
			zap.Int64("proof_1024_metric", report.Proof_1024Metric),
			zap.Int64("proof_65536_metric", report.Proof_65536Metric),
			zap.Uint32("cores", report.Cores),
			zap.Uint64("memory", memory),
			zap.Uint64("storage", binary.BigEndian.Uint64(report.Storage)),
		)
		return nil
	}

	if end-start > 2000 {
		e.logger.Error(
			"slow bandwidth, scoring out",
			zap.String("peer_id", base58.Encode(peerID)),
			zap.Uint32("difficulty", report.Difficulty),
			zap.Int64("difficulty_metric", report.DifficultyMetric),
			zap.Int64("commit_16_metric", report.Commit_16Metric),
			zap.Int64("commit_128_metric", report.Commit_128Metric),
			zap.Int64("commit_1024_metric", report.Commit_1024Metric),
			zap.Int64("commit_65536_metric", report.Commit_65536Metric),
			zap.Int64("proof_16_metric", report.Proof_16Metric),
			zap.Int64("proof_128_metric", report.Proof_128Metric),
			zap.Int64("proof_1024_metric", report.Proof_1024Metric),
			zap.Int64("proof_65536_metric", report.Proof_65536Metric),
			zap.Uint32("cores", report.Cores),
			zap.Uint64("memory", memory),
			zap.Uint64("storage", binary.BigEndian.Uint64(report.Storage)),
		)
		// tag: dusk – nuke this peer for now
		e.pubSub.SetPeerScore(peerID, -1000)
	}

	return nil
}

func (e *MasterClockConsensusEngine) publishProof(
	frame *protobufs.ClockFrame,
) error {
	e.logger.Debug(
		"publishing frame",
		zap.Uint64("frame_number", frame.FrameNumber),
	)

	e.masterTimeReel.Insert(frame)

	if err := e.publishMessage(e.filter, frame); err != nil {
		return errors.Wrap(
			err,
			"publish proof",
		)
	}

	e.state = consensus.EngineStateCollecting

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
