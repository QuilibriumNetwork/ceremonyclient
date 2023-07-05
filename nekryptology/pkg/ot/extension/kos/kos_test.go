package kos

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"source.quilibrium.com/quilibrium/monorepo/nekryptology/pkg/core/curves"
	"source.quilibrium.com/quilibrium/monorepo/nekryptology/pkg/ot/base/simplest"
	"source.quilibrium.com/quilibrium/monorepo/nekryptology/pkg/ot/ottest"
)

func TestBinaryMult(t *testing.T) {
	for i := 0; i < 100; i++ {
		temp := make([]byte, 32)
		_, err := rand.Read(temp)
		require.NoError(t, err)
		expected := make([]byte, 32)
		copy(expected, temp)
		// this test is based on Fermat's little theorem.
		// the multiplicative group of units of a finite field has order |F| - 1
		// (in fact, it's necessarily cyclic; see e.g. https://math.stackexchange.com/a/59911, but this test doesn't rely on that fact)
		// thus raising any element to the |F|th power should yield that element itself.
		// this is a good test because it relies on subtle facts about the field structure, and will fail if anything goes wrong.
		for j := 0; j < 256; j++ {
			expected = binaryFieldMul(expected, expected)
		}
		require.Equal(t, temp, expected)
	}
}

func TestCOTExtension(t *testing.T) {
	const (
		// below are the "cryptographic parameters", including computational and statistical,
		// as well as the cOT block size parameters, which depend on these in a pre-defined way.

		// Kappa is the computational security parameter.
		Kappa = 256

		// KappaBytes is same as Kappa // 8, but avoids cpu division.
		KappaBytes = Kappa >> 3

		s = 80 // statistical security parameter.

		// L is the batch size used in the cOT functionality.
		L = 2*Kappa + 2*s

		// COtBlockSizeBytes is same as L // 8, but avoids cpu division.
		COtBlockSizeBytes = L >> 3

		// OtWidth is the number of scalars processed per "slot" of the cOT. by definition of this parameter,
		// for each of the receiver's choice bits, the sender will provide `OTWidth` scalars.
		// in turn, both the sender and receiver will obtain `OTWidth` shares _per_ slot / bit of the cOT.
		// by definition of the cOT, these "vectors of" scalars will add (componentwise) to the sender's original scalars.
		OtWidth = 2

		kappaOT                   = Kappa + s
		lPrime                    = L + kappaOT // length of pseudorandom seed expansion, used within cOT protocol
		cOtExtendedBlockSizeBytes = lPrime >> 3
	)

	curveInstances := []*curves.Curve{
		curves.K256(),
		curves.P256(),
	}
	for _, curve := range curveInstances {
		uniqueSessionId := [simplest.DigestSize]byte{}
		_, err := rand.Read(uniqueSessionId[:])
		require.NoError(t, err)
		baseOtSenderOutput, baseOtReceiverOutput, err := ottest.RunSimplestOT(curve, Kappa, uniqueSessionId)
		require.NoError(t, err)
		for i := 0; i < Kappa; i++ {
			require.Equal(t, baseOtReceiverOutput.OneTimePadDecryptionKey[i], baseOtSenderOutput.OneTimePadEncryptionKeys[i][baseOtReceiverOutput.RandomChoiceBits[i]])
		}

		sender := NewCOtSender(Kappa, s, baseOtReceiverOutput, curve)
		receiver := NewCOtReceiver(Kappa, s, baseOtSenderOutput, curve)
		choice := [COtBlockSizeBytes]byte{} // receiver's input, namely choice vector. just random
		_, err = rand.Read(choice[:])
		require.NoError(t, err)
		input := make([][]curves.Scalar, L) // sender's input, namely integer "sums" in case w_j == 1.
		for i := 0; i < L; i++ {
			input[i] = make([]curves.Scalar, OtWidth)
			for j := 0; j < OtWidth; j++ {
				input[i][j] = curve.Scalar.Random(rand.Reader)
				require.NoError(t, err)
			}
		}
		firstMessage, err := receiver.Round1Initialize(uniqueSessionId, choice[:])
		require.NoError(t, err)
		responseTau, err := sender.Round2Transfer(uniqueSessionId, input, firstMessage)
		require.NoError(t, err)
		err = receiver.Round3Transfer(responseTau)
		require.NoError(t, err)
		for j := 0; j < L; j++ {
			bit := simplest.ExtractBitFromByteVector(choice[:], j) == 1
			for k := 0; k < OtWidth; k++ {
				temp := sender.OutputAdditiveShares[j][k].Add(receiver.OutputAdditiveShares[j][k])
				if bit {
					require.Equal(t, temp, input[j][k])
				} else {
					require.Equal(t, temp, curve.Scalar.Zero())
				}
			}
		}
	}
}

func TestCOTExtensionStreaming(t *testing.T) {
	const (
		// below are the "cryptographic parameters", including computational and statistical,
		// as well as the cOT block size parameters, which depend on these in a pre-defined way.

		// Kappa is the computational security parameter.
		Kappa = 256

		// KappaBytes is same as Kappa // 8, but avoids cpu division.
		KappaBytes = Kappa >> 3

		s = 80 // statistical security parameter.

		// L is the batch size used in the cOT functionality.
		L = 2*Kappa + 2*s

		// COtBlockSizeBytes is same as L // 8, but avoids cpu division.
		COtBlockSizeBytes = L >> 3

		// OtWidth is the number of scalars processed per "slot" of the cOT. by definition of this parameter,
		// for each of the receiver's choice bits, the sender will provide `OTWidth` scalars.
		// in turn, both the sender and receiver will obtain `OTWidth` shares _per_ slot / bit of the cOT.
		// by definition of the cOT, these "vectors of" scalars will add (componentwise) to the sender's original scalars.
		OtWidth = 2

		kappaOT                   = Kappa + s
		lPrime                    = L + kappaOT // length of pseudorandom seed expansion, used within cOT protocol
		cOtExtendedBlockSizeBytes = lPrime >> 3
	)
	curve := curves.K256()
	hashKeySeed := [simplest.DigestSize]byte{}
	_, err := rand.Read(hashKeySeed[:])
	require.NoError(t, err)
	baseOtReceiver, err := simplest.NewReceiver(curve, Kappa, hashKeySeed)
	require.NoError(t, err)
	sender := NewCOtSender(Kappa, s, baseOtReceiver.Output, curve)
	baseOtSender, err := simplest.NewSender(curve, Kappa, hashKeySeed)
	require.NoError(t, err)
	receiver := NewCOtReceiver(Kappa, s, baseOtSender.Output, curve)

	// first run the seed OT
	senderPipe, receiverPipe := simplest.NewPipeWrappers()
	errorsChannel := make(chan error, 2)
	go func() {
		errorsChannel <- simplest.SenderStreamOTRun(baseOtSender, senderPipe)
	}()
	go func() {
		errorsChannel <- simplest.ReceiverStreamOTRun(baseOtReceiver, receiverPipe)
	}()
	for i := 0; i < 2; i++ {
		require.Nil(t, <-errorsChannel)
	}
	for i := 0; i < Kappa; i++ {
		require.Equal(t, baseOtReceiver.Output.OneTimePadDecryptionKey[i], baseOtSender.Output.OneTimePadEncryptionKeys[i][baseOtReceiver.Output.RandomChoiceBits[i]])
	}

	// begin test of cOT extension. first populate both parties' inputs randomly
	choice := make([]byte, COtBlockSizeBytes) // receiver's input, namely choice vector. just random
	_, err = rand.Read(choice[:])
	require.NoError(t, err)
	input := make([][]curves.Scalar, L) // sender's input, namely integer "sums" in case w_j == 1. random for the test
	for i := 0; i < L; i++ {
		input[i] = make([]curves.Scalar, OtWidth)
		for j := 0; j < OtWidth; j++ {
			input[i][j] = curve.Scalar.Random(rand.Reader)
			require.NoError(t, err)
		}
	}

	// now actually run it, stream-wise
	go func() {
		errorsChannel <- SenderStreamCOtRun(sender, hashKeySeed, input, receiverPipe)
	}()
	go func() {
		errorsChannel <- ReceiverStreamCOtRun(receiver, hashKeySeed, choice, senderPipe)
	}()
	for i := 0; i < 2; i++ {
		require.Nil(t, <-errorsChannel)
	}
	for j := 0; j < L; j++ {
		bit := simplest.ExtractBitFromByteVector(choice[:], j) == 1
		for k := 0; k < OtWidth; k++ {
			temp := sender.OutputAdditiveShares[j][k].Add(receiver.OutputAdditiveShares[j][k])
			if bit {
				require.Equal(t, temp, input[j][k])
			} else {
				require.Equal(t, temp, curve.Scalar.Zero())
			}
		}
	}
}
