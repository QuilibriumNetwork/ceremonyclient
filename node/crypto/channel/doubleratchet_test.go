package channel_test

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"source.quilibrium.com/quilibrium/monorepo/nekryptology/pkg/core/curves"
	"source.quilibrium.com/quilibrium/monorepo/node/crypto/channel"
)

func TestRatchetEncrypt(t *testing.T) {
	x448SendingIdentityPrivateKey := curves.ED448().Scalar.Random(rand.Reader)
	x448SendingEphemeralPrivateKey := curves.ED448().Scalar.Random(rand.Reader)
	x448ReceivingIdentityPrivateKey := curves.ED448().Scalar.Random(rand.Reader)
	x448ReceivingSignedPrePrivateKey := curves.ED448().Scalar.Random(rand.Reader)
	x448SendingIdentityKey := curves.ED448().NewGeneratorPoint().Mul(x448SendingIdentityPrivateKey)
	x448SendingEphemeralKey := curves.ED448().NewGeneratorPoint().Mul(x448SendingEphemeralPrivateKey)
	x448ReceivingIdentityKey := curves.ED448().NewGeneratorPoint().Mul(x448ReceivingIdentityPrivateKey)
	x448ReceivingSignedPreKey := curves.ED448().NewGeneratorPoint().Mul(x448ReceivingSignedPrePrivateKey)

	senderResult := channel.SenderX3DH(
		x448SendingIdentityPrivateKey,
		x448SendingEphemeralPrivateKey,
		x448ReceivingIdentityKey,
		x448ReceivingSignedPreKey,
		96,
	)

	receiverResult := channel.ReceiverX3DH(
		x448ReceivingIdentityPrivateKey,
		x448ReceivingSignedPrePrivateKey,
		x448SendingIdentityKey,
		x448SendingEphemeralKey,
		96,
	)

	sender, err := channel.NewDoubleRatchetParticipant(
		senderResult[:32],
		senderResult[32:64],
		senderResult[64:],
		true,
		x448SendingEphemeralPrivateKey,
		x448ReceivingSignedPreKey,
		curves.ED448(),
		nil,
	)
	require.NoError(t, err)

	receiver, err := channel.NewDoubleRatchetParticipant(
		receiverResult[:32],
		receiverResult[32:64],
		receiverResult[64:],
		false,
		x448ReceivingSignedPrePrivateKey,
		x448SendingEphemeralKey,
		curves.ED448(),
		nil,
	)
	require.NoError(t, err)

	envelope1, err := sender.RatchetEncrypt([]byte("hello there"))
	require.NoError(t, err)

	envelope2, err := sender.RatchetEncrypt([]byte("general kenobi"))
	require.NoError(t, err)

	plaintext1, err := receiver.RatchetDecrypt(envelope1)
	require.NoError(t, err)

	plaintext2, err := receiver.RatchetDecrypt(envelope2)
	require.NoError(t, err)

	envelope3, err := receiver.RatchetEncrypt([]byte("you are a bold one"))
	require.NoError(t, err)

	envelope4, err := receiver.RatchetEncrypt([]byte("[mechanical laughing]"))
	require.NoError(t, err)

	plaintext3, err := sender.RatchetDecrypt(envelope3)
	require.NoError(t, err)

	plaintext4, err := sender.RatchetDecrypt(envelope4)
	require.NoError(t, err)

	// confirm large messages
	msg5 := make([]byte, 1024*1024*10)
	msg6 := make([]byte, 1024*1024*10)
	msg7 := make([]byte, 1024*1024*10)
	msg8 := make([]byte, 1024*1024*10)
	rand.Read(msg5)
	rand.Read(msg6)
	rand.Read(msg7)
	rand.Read(msg8)

	envelope5, err := sender.RatchetEncrypt(msg5)
	require.NoError(t, err)

	envelope6, err := sender.RatchetEncrypt(msg6)
	require.NoError(t, err)

	plaintext5, err := receiver.RatchetDecrypt(envelope5)
	require.NoError(t, err)

	plaintext6, err := receiver.RatchetDecrypt(envelope6)
	require.NoError(t, err)

	envelope7, err := receiver.RatchetEncrypt(msg7)
	require.NoError(t, err)

	envelope8, err := receiver.RatchetEncrypt(msg8)
	require.NoError(t, err)

	plaintext7, err := sender.RatchetDecrypt(envelope7)
	require.NoError(t, err)

	plaintext8, err := sender.RatchetDecrypt(envelope8)
	require.NoError(t, err)

	require.Equal(t, []byte("hello there"), plaintext1)
	require.Equal(t, []byte("general kenobi"), plaintext2)
	require.Equal(t, []byte("you are a bold one"), plaintext3)
	require.Equal(t, []byte("[mechanical laughing]"), plaintext4)
	require.Equal(t, msg5, plaintext5)
	require.Equal(t, msg6, plaintext6)
	require.Equal(t, msg7, plaintext7)
	require.Equal(t, msg8, plaintext8)
}
