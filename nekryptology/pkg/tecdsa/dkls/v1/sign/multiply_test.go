//
// Copyright Coinbase, Inc. All Rights Reserved.
// Copyright Quilibrium, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package sign

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"source.quilibrium.com/quilibrium/monorepo/nekryptology/pkg/core/curves"
	"source.quilibrium.com/quilibrium/monorepo/nekryptology/pkg/ot/base/simplest"
	"source.quilibrium.com/quilibrium/monorepo/nekryptology/pkg/ot/ottest"
)

func TestMultiply(t *testing.T) {
	curve := curves.K256()
	hashKeySeed := [simplest.DigestSize]byte{}
	_, err := rand.Read(hashKeySeed[:])
	require.NoError(t, err)

	baseOtSenderOutput, baseOtReceiverOutput, err := ottest.RunSimplestOT(curve, 256, hashKeySeed)
	require.NoError(t, err)

	sender, err := NewMultiplySender(256, 80, baseOtReceiverOutput, curve, hashKeySeed)
	require.NoError(t, err)
	receiver, err := NewMultiplyReceiver(256, 80, baseOtSenderOutput, curve, hashKeySeed)
	require.NoError(t, err)

	alpha := curve.Scalar.Random(rand.Reader)
	beta := curve.Scalar.Random(rand.Reader)

	round1Output, err := receiver.Round1Initialize(beta)
	require.Nil(t, err)
	round2Output, err := sender.Round2Multiply(alpha, round1Output)
	require.Nil(t, err)
	err = receiver.Round3Multiply(round2Output)
	require.Nil(t, err)

	product := alpha.Mul(beta)
	sum := sender.OutputAdditiveShare.Add(receiver.OutputAdditiveShare)
	require.Equal(t, product, sum)
}

// Verify: mul == add for g1 and g2, and squared add MP e(add * G1, add * G2) == e(add^2 * G1, G2)
func TestMultiplyBLS48(t *testing.T) {
	curve := curves.BLS48581G1()
	hashKeySeed := [simplest.DigestSize]byte{}
	_, err := rand.Read(hashKeySeed[:])
	require.NoError(t, err)

	baseOtSenderOutput, baseOtReceiverOutput, err := ottest.RunSimplestOT(curve, 584, hashKeySeed)
	require.NoError(t, err)

	sender, err := NewMultiplySender(584, 160, baseOtReceiverOutput, curve, hashKeySeed)
	require.NoError(t, err)
	receiver, err := NewMultiplyReceiver(584, 160, baseOtSenderOutput, curve, hashKeySeed)
	require.NoError(t, err)

	sender2, err := NewMultiplySender(584, 160, baseOtReceiverOutput, curve, hashKeySeed)
	require.NoError(t, err)
	receiver2, err := NewMultiplyReceiver(584, 160, baseOtSenderOutput, curve, hashKeySeed)
	require.NoError(t, err)

	alpha := curve.Scalar.Random(rand.Reader)
	beta := curve.Scalar.Random(rand.Reader)
	alpha2 := alpha.Mul(alpha)
	beta2 := beta.Mul(beta)

	round1Output, err := receiver.Round1Initialize(beta)
	require.Nil(t, err)
	round2Output, err := sender.Round2Multiply(alpha, round1Output)
	require.Nil(t, err)
	err = receiver.Round3Multiply(round2Output)
	require.Nil(t, err)
	round1Output2, err := receiver2.Round1Initialize(beta2)
	require.Nil(t, err)
	round2Output2, err := sender2.Round2Multiply(alpha2, round1Output2)
	require.Nil(t, err)
	err = receiver2.Round3Multiply(round2Output2)
	require.Nil(t, err)

	generator := alpha.Point().Generator()
	product := generator.Mul(alpha).Mul(beta)
	sum := generator.Mul(sender.OutputAdditiveShare).Add(generator.Mul(receiver.OutputAdditiveShare))

	g2generator := curves.BLS48581G2().NewGeneratorPoint()
	g2product := g2generator.Mul(alpha).Mul(beta)
	g2sum := g2generator.Mul(sender.OutputAdditiveShare).Add(g2generator.Mul(receiver.OutputAdditiveShare))

	product2 := generator.Mul(alpha2).Mul(beta2)
	sum2 := generator.Mul(sender2.OutputAdditiveShare).Add(generator.Mul(receiver2.OutputAdditiveShare))
	sum2Neg := sum2.Neg()

	result := product.(*curves.PointBls48581G1).MultiPairing(
		sum.(curves.PairingPoint),
		g2sum.(curves.PairingPoint),
		sum2Neg.(curves.PairingPoint),
		g2generator.(curves.PairingPoint),
	).(*curves.ScalarBls48581Gt).Value
	fmt.Printf("%+v\n", result.Isunity())
	require.Equal(t, true, product.Equal(sum))
	require.Equal(t, true, product2.Equal(sum2))
	require.Equal(t, true, g2product.Equal(g2sum))
	require.Equal(t, true, result.Isunity())
}
