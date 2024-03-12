package ceremony

import (
	"bytes"
	"encoding/binary"
	"strings"
	"time"

	"github.com/iden3/go-iden3-crypto/poseidon"
	pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"source.quilibrium.com/quilibrium/monorepo/go-libp2p-blossomsub/pb"
	"source.quilibrium.com/quilibrium/monorepo/node/consensus"
	"source.quilibrium.com/quilibrium/monorepo/node/keys"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
)

func (e *CeremonyDataClockConsensusEngine) handleMessage(
	message *pb.Message,
) error {
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
				e.logger.Debug(
					"could not process message for engine",
					zap.Error(err),
					zap.String("engine_name", name),
				)
				return errors.Wrap(err, "handle message")
			}

			for _, appMessage := range messages {
				appMsg := &anypb.Any{}
				err := proto.Unmarshal(appMessage.Payload, appMsg)
				if err != nil {
					e.logger.Error(
						"could not unmarshal app message",
						zap.Error(err),
						zap.String("engine_name", name),
					)
					return errors.Wrap(err, "handle message")
				}

				switch appMsg.TypeUrl {
				case protobufs.CeremonyLobbyStateTransitionType:
					t := &protobufs.CeremonyLobbyStateTransition{}
					err := proto.Unmarshal(appMsg.Value, t)
					if err != nil {
						return errors.Wrap(err, "handle message")
					}

					if err := e.handleCeremonyLobbyStateTransition(t); err != nil {
						return errors.Wrap(err, "handle message")
					}
				}
			}

			return nil
		})
	}

	if err := eg.Wait(); err != nil {
		e.logger.Debug("rejecting invalid message", zap.Error(err))
		return nil
	}

	any := &anypb.Any{}
	if err := proto.Unmarshal(msg.Payload, any); err != nil {
		return errors.Wrap(err, "handle message")
	}

	switch any.TypeUrl {
	case protobufs.ClockFrameType:
		e.peerMapMx.Lock()
		if peer, ok := e.peerMap[string(message.From)]; !ok ||
			bytes.Compare(peer.version, consensus.GetMinimumVersion()) < 0 {
			return nil
		}
		e.peerMapMx.Unlock()
		if err := e.handleClockFrameData(
			message.From,
			msg.Address,
			any,
			false,
		); err != nil {
			return errors.Wrap(err, "handle message")
		}
	case protobufs.CeremonyPeerListAnnounceType:
		if err := e.handleCeremonyPeerListAnnounce(
			message.From,
			msg.Address,
			any,
		); err != nil {
			return errors.Wrap(err, "handle message")
		}
	}

	return nil
}

func (e *CeremonyDataClockConsensusEngine) handleCeremonyPeerListAnnounce(
	peerID []byte,
	address []byte,
	any *anypb.Any,
) error {
	announce := &protobufs.CeremonyPeerListAnnounce{}
	if err := any.UnmarshalTo(announce); err != nil {
		return errors.Wrap(err, "handle ceremony peer list announce")
	}

	for _, p := range announce.PeerList {
		e.peerMapMx.Lock()
		if _, ok := e.uncooperativePeersMap[string(p.PeerId)]; ok {
			e.peerMapMx.Unlock()
			continue
		}
		e.peerMapMx.Unlock()

		if bytes.Equal(p.PeerId, e.pubSub.GetPeerID()) {
			continue
		}

		if !bytes.Equal(p.PeerId, peerID) {
			continue
		}

		if p.PublicKey == nil || p.Signature == nil || p.Version == nil {
			continue
		}

		if p.PublicKey != nil && p.Signature != nil && p.Version != nil {
			key, err := pcrypto.UnmarshalEd448PublicKey(p.PublicKey)
			if err != nil {
				e.logger.Warn(
					"peer announcement contained invalid pubkey",
					zap.Binary("public_key", p.PublicKey),
				)
				continue
			}

			if !(peer.ID(p.PeerId)).MatchesPublicKey(key) {
				e.logger.Warn(
					"peer announcement peer id does not match pubkey",
					zap.Binary("peer_id", p.PeerId),
					zap.Binary("public_key", p.PublicKey),
				)
				continue
			}

			msg := binary.BigEndian.AppendUint64([]byte{}, p.MaxFrame)
			msg = append(msg, p.Version...)
			msg = binary.BigEndian.AppendUint64(msg, uint64(p.Timestamp))
			b, err := key.Verify(msg, p.Signature)
			if err != nil || !b {
				e.logger.Warn(
					"peer provided invalid signature",
					zap.Binary("msg", msg),
					zap.Binary("public_key", p.PublicKey),
					zap.Binary("signature", p.Signature),
				)
				continue
			}

			if bytes.Compare(p.Version, consensus.GetMinimumVersion()) < 0 &&
				p.Timestamp > consensus.GetMinimumVersionCutoff().UnixMilli() {
				e.logger.Debug(
					"peer provided outdated version, penalizing app score",
					zap.Binary("peer_id", p.PeerId),
				)
				e.pubSub.SetPeerScore(p.PeerId, -10000)
				continue
			}
		}

		multiaddr := e.pubSub.GetMultiaddrOfPeer(p.PeerId)

		e.pubSub.SetPeerScore(p.PeerId, 10)

		e.peerMapMx.Lock()
		existing, ok := e.peerMap[string(p.PeerId)]
		e.peerMapMx.Unlock()

		if ok {
			if existing.signature != nil && p.Signature == nil {
				continue
			}

			if existing.publicKey != nil && p.PublicKey == nil {
				continue
			}

			if existing.version != nil && p.Version == nil {
				continue
			}

			if existing.timestamp > p.Timestamp {
				continue
			}
		}

		e.peerMapMx.Lock()
		e.peerMap[string(p.PeerId)] = &peerInfo{
			peerId:        p.PeerId,
			multiaddr:     multiaddr,
			maxFrame:      p.MaxFrame,
			direct:        bytes.Equal(p.PeerId, peerID),
			lastSeen:      time.Now().Unix(),
			timestamp:     p.Timestamp,
			version:       p.Version,
			signature:     p.Signature,
			publicKey:     p.PublicKey,
			totalDistance: p.TotalDistance,
		}
		e.peerMapMx.Unlock()
	}

	return nil
}

func (e *CeremonyDataClockConsensusEngine) handleCeremonyLobbyStateTransition(
	transition *protobufs.CeremonyLobbyStateTransition,
) error {
	if len(transition.TransitionInputs) != len(transition.TypeUrls) {
		return errors.Wrap(
			errors.New("invalid state transition"),
			"handle ceremony lobby state transition",
		)
	}

	e.stagedLobbyStateTransitionsMx.Lock()
	if e.stagedLobbyStateTransitions == nil {
		e.stagedLobbyStateTransitions = &protobufs.CeremonyLobbyStateTransition{}
	}

	found := false
	for _, ti := range e.stagedLobbyStateTransitions.TransitionInputs {
		for _, nti := range transition.TransitionInputs {
			if bytes.Equal(ti, nti) {
				found = true
			}
		}
	}

	if !found {
		for i := range transition.TransitionInputs {
			e.stagedLobbyStateTransitions.TypeUrls = append(
				e.stagedLobbyStateTransitions.TypeUrls,
				transition.TypeUrls[i],
			)
			e.stagedLobbyStateTransitions.TransitionInputs = append(
				e.stagedLobbyStateTransitions.TransitionInputs,
				transition.TransitionInputs[i],
			)
		}
	}
	e.stagedLobbyStateTransitionsMx.Unlock()
	return nil
}

func (e *CeremonyDataClockConsensusEngine) handleClockFrameData(
	peerID []byte,
	address []byte,
	any *anypb.Any,
	isSync bool,
) error {
	frame := &protobufs.ClockFrame{}
	if err := any.UnmarshalTo(frame); err != nil {
		return errors.Wrap(err, "handle clock frame data")
	}

	addr, err := poseidon.HashBytes(
		frame.GetPublicKeySignatureEd448().PublicKey.KeyValue,
	)
	if err != nil {
		return errors.Wrap(err, "handle clock frame data")
	}

	prover := e.frameProverTrie.FindNearest(addr.Bytes())
	if !bytes.Equal(prover.External.Key, addr.Bytes()) {
		e.logger.Info(
			"prover not in trie at frame, address may be in fork",
			zap.Binary("address", address),
			zap.Binary("filter", frame.Filter),
			zap.Uint64("frame_number", frame.FrameNumber),
		)
		return nil
	}

	e.logger.Info(
		"got clock frame",
		zap.Binary("address", address),
		zap.Binary("filter", frame.Filter),
		zap.Uint64("frame_number", frame.FrameNumber),
		zap.Int("proof_count", len(frame.AggregateProofs)),
	)

	if err := e.frameProver.VerifyDataClockFrame(frame); err != nil {
		e.logger.Error("could not verify clock frame", zap.Error(err))
		return errors.Wrap(err, "handle clock frame data")
	}

	if err := e.inclusionProver.VerifyFrame(frame); err != nil {
		e.logger.Error("could not verify clock frame", zap.Error(err))
		return errors.Wrap(err, "handle clock frame data")
	}

	e.logger.Info(
		"clock frame was valid",
		zap.Binary("address", address),
		zap.Binary("filter", frame.Filter),
		zap.Uint64("frame_number", frame.FrameNumber),
	)

	e.dataTimeReel.Insert(frame)
	return nil
}

func (e *CeremonyDataClockConsensusEngine) publishProof(
	frame *protobufs.ClockFrame,
) error {
	e.logger.Debug(
		"publishing frame and aggregations",
		zap.Uint64("frame_number", frame.FrameNumber),
	)
	if err := e.publishMessage(e.filter, frame); err != nil {
		return errors.Wrap(
			err,
			"publish proof",
		)
	}

	return nil
}

func (e *CeremonyDataClockConsensusEngine) publishMessage(
	filter []byte,
	message proto.Message,
) error {
	any := &anypb.Any{}
	if err := any.MarshalFrom(message); err != nil {
		return errors.Wrap(err, "publish message")
	}

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
		Address: e.provingKeyAddress,
		Payload: payload,
	}
	data, err := proto.Marshal(msg)
	if err != nil {
		return errors.Wrap(err, "publish message")
	}
	return e.pubSub.PublishToBitmask(filter, data)
}

func (e *CeremonyDataClockConsensusEngine) createCommunicationKeys() error {
	_, err := e.keyManager.GetAgreementKey("q-ratchet-idk")
	if err != nil {
		if errors.Is(err, keys.KeyNotFoundErr) {
			_, err = e.keyManager.CreateAgreementKey(
				"q-ratchet-idk",
				keys.KeyTypeX448,
			)
			if err != nil {
				return errors.Wrap(err, "announce key bundle")
			}
		} else {
			return errors.Wrap(err, "announce key bundle")
		}
	}

	_, err = e.keyManager.GetAgreementKey("q-ratchet-spk")
	if err != nil {
		if errors.Is(err, keys.KeyNotFoundErr) {
			_, err = e.keyManager.CreateAgreementKey(
				"q-ratchet-spk",
				keys.KeyTypeX448,
			)
			if err != nil {
				return errors.Wrap(err, "announce key bundle")
			}
		} else {
			return errors.Wrap(err, "announce key bundle")
		}
	}

	return nil
}
