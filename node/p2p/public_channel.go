package p2p

import (
	"crypto/rand"
	"encoding/binary"
	"sync"
	"time"

	"github.com/pkg/errors"
	"google.golang.org/protobuf/proto"
	"source.quilibrium.com/quilibrium/monorepo/go-libp2p-blossomsub/pb"
	"source.quilibrium.com/quilibrium/monorepo/nekryptology/pkg/core/curves"
	"source.quilibrium.com/quilibrium/monorepo/node/crypto"
	"source.quilibrium.com/quilibrium/monorepo/node/keys"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
)

// A simplified P2P channel – the pair of actors communicating is public
// knowledge, even though the data itself is encrypted.
type PublicP2PChannel struct {
	participant   *crypto.DoubleRatchetParticipant
	sendMap       map[uint64][]byte
	receiveMap    map[uint64][]byte
	pubSub        PubSub
	sendFilter    []byte
	receiveFilter []byte
	initiator     bool
	senderSeqNo   uint64
	receiverSeqNo uint64
	receiveChan   chan []byte
	receiveMx     sync.Mutex
}

func NewPublicP2PChannel(
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

	channel := &PublicP2PChannel{
		sendMap:       map[uint64][]byte{},
		receiveMap:    map[uint64][]byte{},
		initiator:     initiator,
		sendFilter:    sendFilter,
		receiveFilter: receiveFilter,
		pubSub:        pubSub,
		senderSeqNo:   0,
		receiverSeqNo: 0,
		receiveChan:   make(chan []byte),
	}

	var err error
	var participant *crypto.DoubleRatchetParticipant
	if initiator {
		sendingEphemeralPrivateKey := curve.Scalar.Random(
			rand.Reader,
		)
		x3dh := crypto.SenderX3DH(
			sendingIdentityPrivateKey,
			sendingSignedPrePrivateKey,
			receivingIdentityKey,
			receivingSignedPreKey,
			96,
		)
		participant, err = crypto.NewDoubleRatchetParticipant(
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
		x3dh := crypto.SenderX3DH(
			sendingIdentityPrivateKey,
			sendingSignedPrePrivateKey,
			receivingIdentityKey,
			receivingSignedPreKey,
			96,
		)
		participant, err = crypto.NewDoubleRatchetParticipant(
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

	channel.participant = participant

	pubSub.Subscribe(
		sendFilter,
		func(message *pb.Message) error { return nil },
		true,
	)

	pubSub.Subscribe(
		receiveFilter,
		channel.handleReceive,
		true,
	)

	return channel, nil
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

	rawBytes, err := proto.Marshal(envelope)
	if err != nil {
		return errors.Wrap(err, "send")
	}

	c.sendMap[c.senderSeqNo] = rawBytes

	return errors.Wrap(c.pubSub.PublishToBitmask(c.sendFilter, rawBytes), "send")
}

func (c *PublicP2PChannel) Receive() ([]byte, error) {
	c.receiverSeqNo++
	after := time.After(20 * time.Second)
	select {
	case msg := <-c.receiveChan:
		return msg, nil
	case <-after:
		return nil, errors.Wrap(errors.New("timed out"), "receive")
	}
}

func (c *PublicP2PChannel) Close() {
	c.pubSub.Unsubscribe(c.sendFilter, true)
	c.pubSub.Unsubscribe(c.receiveFilter, true)
}
