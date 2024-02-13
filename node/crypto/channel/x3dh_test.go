package channel_test

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"source.quilibrium.com/quilibrium/monorepo/nekryptology/pkg/core/curves"
	"source.quilibrium.com/quilibrium/monorepo/node/crypto/channel"
)

func TestX3DHMatches(t *testing.T) {
	x448SendingIdentityPrivateKey := curves.ED448().Scalar.Random(rand.Reader)
	x448SendingEphemeralPrivateKey := curves.ED448().Scalar.Random(rand.Reader)
	x448ReceivingIdentityPrivateKey := curves.ED448().Scalar.Random(rand.Reader)
	x448ReceivingSignedPrePrivateKey := curves.ED448().Scalar.Random(rand.Reader)
	x448SendingIdentityKey := curves.ED448().NewGeneratorPoint().Mul(x448SendingIdentityPrivateKey)
	x448SendingEphemeralKey := curves.ED448().NewGeneratorPoint().Mul(x448SendingEphemeralPrivateKey)
	x448ReceivingIdentityKey := curves.ED448().NewGeneratorPoint().Mul(x448ReceivingIdentityPrivateKey)
	x448ReceivingSignedPreKey := curves.ED448().NewGeneratorPoint().Mul(x448ReceivingSignedPrePrivateKey)

	result := channel.SenderX3DH(
		x448SendingIdentityPrivateKey,
		x448SendingEphemeralPrivateKey,
		x448ReceivingIdentityKey,
		x448ReceivingSignedPreKey,
		32,
	)

	compare := channel.ReceiverX3DH(
		x448ReceivingIdentityPrivateKey,
		x448ReceivingSignedPrePrivateKey,
		x448SendingIdentityKey,
		x448SendingEphemeralKey,
		32,
	)

	require.Equal(t, result, compare)
}
