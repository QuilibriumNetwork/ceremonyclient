package p2p

import (
	"crypto/rand"
	"encoding/binary"
	"sync"

	"github.com/pkg/errors"
	"google.golang.org/protobuf/proto"
	"source.quilibrium.com/quilibrium/monorepo/go-libp2p-blossomsub/pb"
	"source.quilibrium.com/quilibrium/monorepo/nekryptology/pkg/core/curves"
	"source.quilibrium.com/quilibrium/monorepo/node/crypto/channel"
	"source.quilibrium.com/quilibrium/monorepo/node/keys"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
)

// A simplified P2P channel – the pair of actors communicating is public
// knowledge, even though the data itself is encrypted.
type PublicP2PChannel struct {
	participant         *channel.DoubleRatchetParticipant
	sendMap             map[uint64][]byte
	receiveMap          map[uint64][]byte
	pubSub              PubSub
	sendFilter          []byte
	receiveFilter       []byte
	initiator           bool
	senderSeqNo         uint64
	receiverSeqNo       uint64
	receiveChan         chan []byte
	receiveMx           sync.Mutex
	publicChannelClient PublicChannelClient
}

type PublicChannelClient interface {
	Send(m *protobufs.P2PChannelEnvelope) error
	Recv() (*protobufs.P2PChannelEnvelope, error)
}

func NewPublicP2PChannel(
	publicChannelClient PublicChannelClient,
	senderIdentifier, receiverIdentifier []byte,
	initiator bool,
	sendingIdentityPrivateKey curves.Scalar,
	sendingSignedPrePrivateKey curves.Scalar,
	receivingIdentityKey curves.Point,
	receivingSignedPreKey curves.Point,
	curve *curves.Curve,
	keyManager keys.KeyManager,
	pubSub PubSub,
) (*PublicP2PChannel, error) {
	sendFilter := append(
		append([]byte{}, senderIdentifier...),
		receiverIdentifier...,
	)
	receiveFilter := append(
		append([]byte{}, receiverIdentifier...),
		senderIdentifier...,
	)

	ch := &PublicP2PChannel{
		publicChannelClient: publicChannelClient,
		sendMap:             map[uint64][]byte{},
		receiveMap:          map[uint64][]byte{},
		initiator:           initiator,
		sendFilter:          sendFilter,
		receiveFilter:       receiveFilter,
		pubSub:              pubSub,
		senderSeqNo:         0,
		receiverSeqNo:       0,
		receiveChan:         make(chan []byte),
	}

	var err error
	var participant *channel.DoubleRatchetParticipant
	if initiator {
		sendingEphemeralPrivateKey := curve.Scalar.Random(
			rand.Reader,
		)
		x3dh := channel.SenderX3DH(
			sendingIdentityPrivateKey,
			sendingSignedPrePrivateKey,
			receivingIdentityKey,
			receivingSignedPreKey,
			96,
		)
		participant, err = channel.NewDoubleRatchetParticipant(
			x3dh[:32],
			x3dh[32:64],
			x3dh[64:],
			true,
			sendingEphemeralPrivateKey,
			receivingSignedPreKey,
			curve,
			keyManager,
		)
		if err != nil {
			return nil, errors.Wrap(err, "new public p2p channel")
		}
	} else {
		x3dh := channel.SenderX3DH(
			sendingIdentityPrivateKey,
			sendingSignedPrePrivateKey,
			receivingIdentityKey,
			receivingSignedPreKey,
			96,
		)
		participant, err = channel.NewDoubleRatchetParticipant(
			x3dh[:32],
			x3dh[32:64],
			x3dh[64:],
			false,
			sendingSignedPrePrivateKey,
			nil,
			curve,
			keyManager,
		)
		if err != nil {
			return nil, errors.Wrap(err, "new public p2p channel")
		}
	}

	ch.participant = participant

	return ch, nil
}

func (c *PublicP2PChannel) handleReceive(message *pb.Message) error {
	envelope := &protobufs.P2PChannelEnvelope{}
	if err := proto.Unmarshal(message.Data, envelope); err != nil {
		return errors.Wrap(err, "handle receive")
	}

	c.receiveMx.Lock()
	rawData, err := c.participant.RatchetDecrypt(envelope)
	c.receiveMx.Unlock()
	if err != nil {
		return errors.Wrap(err, "handle receive")
	}

	seqNo := binary.BigEndian.Uint64(rawData[:8])

	if seqNo == c.receiverSeqNo {
		c.receiveChan <- rawData[8:]
	} else {
		c.receiveMx.Lock()
		c.receiveMap[seqNo] = rawData[8:]
		c.receiveMx.Unlock()
	}

	return nil
}

func (c *PublicP2PChannel) Send(message []byte) error {
	c.senderSeqNo++
	message = append(
		binary.BigEndian.AppendUint64(nil, c.senderSeqNo),
		message...,
	)

	envelope, err := c.participant.RatchetEncrypt(message)
	if err != nil {
		return errors.Wrap(err, "send")
	}

	return errors.Wrap(
		c.publicChannelClient.Send(envelope),
		"send",
	)
}

func (c *PublicP2PChannel) Receive() ([]byte, error) {
	c.receiverSeqNo++

	msg, err := c.publicChannelClient.Recv()
	if err != nil {
		return nil, errors.Wrap(err, "receive")
	}

	rawData, err := c.participant.RatchetDecrypt(msg)
	if err != nil {
		return nil, errors.Wrap(err, "receive")
	}

	seqNo := binary.BigEndian.Uint64(rawData[:8])

	if seqNo == c.receiverSeqNo {
		return rawData[8:], nil
	} else {
		c.receiveMx.Lock()
		c.receiveMap[seqNo] = rawData[8:]
		c.receiveMx.Unlock()
	}

	return nil, nil
}

func (c *PublicP2PChannel) Close() {
}
