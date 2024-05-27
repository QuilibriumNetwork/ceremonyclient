package master

import (
	"bytes"
	"context"
	"encoding/binary"
	"strings"
	"time"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/mr-tron/base58"
	"github.com/pkg/errors"
	"go.uber.org/zap"
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

	switch any.TypeUrl {
	case protobufs.ClockFrameType:
		if err := e.handleClockFrameData(
			message.From,
			any,
		); err != nil {
			return errors.Wrap(err, "handle message")
		}
		return nil
	case protobufs.SelfTestReportType:
		if err := e.handleSelfTestReport(
			message.From,
			any,
		); err != nil {
			return errors.Wrap(err, "handle message")
		}
		return nil
	}

	return errors.Wrap(errors.New("invalid message"), "handle message")
}

func (e *MasterClockConsensusEngine) handleClockFrameData(
	peerID []byte,
	any *anypb.Any,
) error {
	frame := &protobufs.ClockFrame{}
	if err := any.UnmarshalTo(frame); err != nil {
		return errors.Wrap(err, "handle clock frame data")
	}

	head, err := e.masterTimeReel.Head()
	if err != nil {
		panic(err)
	}

	if frame.FrameNumber < head.FrameNumber {
		return nil
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

	go func() {
		select {
		case e.frameValidationCh <- frame:
		default:
			e.logger.Debug(
				"dropped frame due to overwhelmed queue",
				zap.Binary("sender", peerID),
				zap.Binary("filter", frame.Filter),
				zap.Uint64("frame_number", frame.FrameNumber),
				zap.Int("proof_count", len(frame.AggregateProofs)),
			)
		}
	}()

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

	// minimum proof size is one timestamp, one vdf proof, must match one fewer
	// than core count
	if len(report.Proof) < 516+8 ||
		((len(report.Proof)-8)/516) != int(report.Cores-1) {
		e.logger.Warn(
			"received invalid proof from peer",
			zap.String("peer_id", peer.ID(peerID).String()),
			zap.Int("proof_size", len(report.Proof)),
			zap.Uint32("cores", report.Cores),
		)
		e.pubSub.SetPeerScore(peerID, -1000)
		return errors.Wrap(errors.New("invalid report"), "handle self test report")
	}

	e.logger.Debug(
		"received proof from peer",
		zap.String("peer_id", peer.ID(peerID).String()),
	)

	info := e.peerInfoManager.GetPeerInfo(peerID)
	if info != nil {
		if (time.Now().UnixMilli() - info.LastSeen) < (270 * 1000) {
			return nil
		}

		info.DifficultyMetric = report.DifficultyMetric
		info.MasterHeadFrame = report.MasterHeadFrame

		if info.Bandwidth <= 1048576 {
			go func() {
				ctx, cancel := context.WithTimeout(context.TODO(), 5*time.Minute)
				defer cancel()
				ch := e.pubSub.GetMultiaddrOfPeerStream(ctx, peerID)
				select {
				case <-ch:
					go func() {
						e.bandwidthTestCh <- peerID
					}()
				case <-ctx.Done():
				}
			}()
		}

		proof := report.Proof
		timestamp := binary.BigEndian.Uint64(proof[:8])
		proof = proof[8:]

		// Ignore outdated reports, give 3 minutes + proof time for propagation
		// delay
		if int64(timestamp) < (time.Now().UnixMilli() - (480 * 1000)) {
			return nil
		}

		challenge := binary.BigEndian.AppendUint64([]byte{}, report.MasterHeadFrame)
		challenge = append(challenge, peerID...)

		proofs := make([][]byte, (len(report.Proof)-8)/516)
		for i := 0; i < len(proofs); i++ {
			proofs[i] = proof[i*516 : (i+1)*516]
		}
		go func() {
			e.verifyTestCh <- verifyChallenge{
				peerID:           peerID,
				challenge:        challenge,
				timestamp:        int64(timestamp),
				difficultyMetric: report.DifficultyMetric,
				proofs:           proofs,
			}
		}()

		return nil
	}

	e.addPeerManifestReport(peerID, report)

	memory := binary.BigEndian.Uint64(report.Memory)
	e.logger.Debug(
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
		e.logger.Debug(
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

	go func() {
		ctx, cancel := context.WithTimeout(context.TODO(), 5*time.Minute)
		defer cancel()
		ch := e.pubSub.GetMultiaddrOfPeerStream(ctx, peerID)
		select {
		case <-ch:
			go func() {
				e.bandwidthTestCh <- peerID
			}()
		case <-ctx.Done():
		}
	}()

	return nil
}

// This does not publish any longer, frames strictly are picked up from sync
func (e *MasterClockConsensusEngine) publishProof(
	frame *protobufs.ClockFrame,
) error {
	e.logger.Debug(
		"publishing frame",
		zap.Uint64("frame_number", frame.FrameNumber),
	)

	e.masterTimeReel.Insert(frame, false)

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
