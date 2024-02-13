package application_test

import (
	"crypto/rand"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/syncmap"
	"source.quilibrium.com/quilibrium/monorepo/nekryptology/pkg/core/curves"
	bls48581 "source.quilibrium.com/quilibrium/monorepo/nekryptology/pkg/core/curves/native/bls48581"
	"source.quilibrium.com/quilibrium/monorepo/nekryptology/pkg/ot/base/simplest"
	"source.quilibrium.com/quilibrium/monorepo/node/crypto/channel"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/ceremony/application"
)

func TestPairings(t *testing.T) {
	a := []byte{0x01}
	b := []byte{0x02}
	c := []byte{0x03}
	d := []byte{0x04}
	e := []byte{0x05}
	f := []byte{0x06}
	g := []byte{0x07}
	h := []byte{0x08}

	peers := [][]byte{a, b, c, d, e, f, g, h}
	idks := []curves.Point{
		curves.ED448().Point.Generator(),
		curves.ED448().Point.Generator(),
		curves.ED448().Point.Generator(),
		curves.ED448().Point.Generator(),
		curves.ED448().Point.Generator(),
		curves.ED448().Point.Generator(),
		curves.ED448().Point.Generator(),
		curves.ED448().Point.Generator(),
	}

	a1pairing, _, isABob := application.GetPairings(a, 1, peers, idks)
	b1pairing, _, isBBob := application.GetPairings(b, 1, peers, idks)
	c1pairing, _, isCBob := application.GetPairings(c, 1, peers, idks)
	d1pairing, _, isDBob := application.GetPairings(d, 1, peers, idks)
	e1pairing, _, isEBob := application.GetPairings(e, 1, peers, idks)
	f1pairing, _, isFBob := application.GetPairings(f, 1, peers, idks)
	g1pairing, _, isGBob := application.GetPairings(g, 1, peers, idks)
	h1pairing, _, isHBob := application.GetPairings(h, 1, peers, idks)

	require.ElementsMatch(t, a1pairing, [][]byte{b})
	require.ElementsMatch(t, b1pairing, [][]byte{a})
	require.ElementsMatch(t, c1pairing, [][]byte{d})
	require.ElementsMatch(t, d1pairing, [][]byte{c})
	require.ElementsMatch(t, e1pairing, [][]byte{f})
	require.ElementsMatch(t, f1pairing, [][]byte{e})
	require.ElementsMatch(t, g1pairing, [][]byte{h})
	require.ElementsMatch(t, h1pairing, [][]byte{g})
	require.ElementsMatch(t,
		[]bool{isABob, isBBob, isCBob, isDBob, isEBob, isFBob, isGBob, isHBob},
		[]bool{false, true, false, true, false, true, false, true},
	)

	a2pairing, _, isABob := application.GetPairings(a, 2, peers, idks)
	b2pairing, _, isBBob := application.GetPairings(b, 2, peers, idks)
	c2pairing, _, isCBob := application.GetPairings(c, 2, peers, idks)
	d2pairing, _, isDBob := application.GetPairings(d, 2, peers, idks)
	e2pairing, _, isEBob := application.GetPairings(e, 2, peers, idks)
	f2pairing, _, isFBob := application.GetPairings(f, 2, peers, idks)
	g2pairing, _, isGBob := application.GetPairings(g, 2, peers, idks)
	h2pairing, _, isHBob := application.GetPairings(h, 2, peers, idks)

	require.ElementsMatch(t, a2pairing, [][]byte{c, d})
	require.ElementsMatch(t, b2pairing, [][]byte{c, d})
	require.ElementsMatch(t, c2pairing, [][]byte{a, b})
	require.ElementsMatch(t, d2pairing, [][]byte{a, b})
	require.ElementsMatch(t, e2pairing, [][]byte{g, h})
	require.ElementsMatch(t, f2pairing, [][]byte{g, h})
	require.ElementsMatch(t, g2pairing, [][]byte{e, f})
	require.ElementsMatch(t, h2pairing, [][]byte{e, f})
	require.ElementsMatch(t,
		[]bool{isABob, isBBob, isCBob, isDBob, isEBob, isFBob, isGBob, isHBob},
		[]bool{false, false, true, true, false, false, true, true},
	)

	a3pairing, _, isABob := application.GetPairings(a, 3, peers, idks)
	b3pairing, _, isBBob := application.GetPairings(b, 3, peers, idks)
	c3pairing, _, isCBob := application.GetPairings(c, 3, peers, idks)
	d3pairing, _, isDBob := application.GetPairings(d, 3, peers, idks)
	e3pairing, _, isEBob := application.GetPairings(e, 3, peers, idks)
	f3pairing, _, isFBob := application.GetPairings(f, 3, peers, idks)
	g3pairing, _, isGBob := application.GetPairings(g, 3, peers, idks)
	h3pairing, _, isHBob := application.GetPairings(h, 3, peers, idks)

	require.ElementsMatch(t, a3pairing, [][]byte{e, f, g, h})
	require.ElementsMatch(t, b3pairing, [][]byte{e, f, g, h})
	require.ElementsMatch(t, c3pairing, [][]byte{e, f, g, h})
	require.ElementsMatch(t, d3pairing, [][]byte{e, f, g, h})
	require.ElementsMatch(t, e3pairing, [][]byte{a, b, c, d})
	require.ElementsMatch(t, f3pairing, [][]byte{a, b, c, d})
	require.ElementsMatch(t, g3pairing, [][]byte{a, b, c, d})
	require.ElementsMatch(t, h3pairing, [][]byte{a, b, c, d})
	require.ElementsMatch(t,
		[]bool{isABob, isBBob, isCBob, isDBob, isEBob, isFBob, isGBob, isHBob},
		[]bool{false, false, false, false, true, true, true, true},
	)

	a4pairing, _, isABob := application.GetPairings(a, 4, peers, idks)
	b4pairing, _, isBBob := application.GetPairings(b, 4, peers, idks)
	c4pairing, _, isCBob := application.GetPairings(c, 4, peers, idks)
	d4pairing, _, isDBob := application.GetPairings(d, 4, peers, idks)
	e4pairing, _, isEBob := application.GetPairings(e, 4, peers, idks)
	f4pairing, _, isFBob := application.GetPairings(f, 4, peers, idks)
	g4pairing, _, isGBob := application.GetPairings(g, 4, peers, idks)
	h4pairing, _, isHBob := application.GetPairings(h, 4, peers, idks)

	require.ElementsMatch(t, a4pairing, [][]byte{})
	require.ElementsMatch(t, b4pairing, [][]byte{})
	require.ElementsMatch(t, c4pairing, [][]byte{})
	require.ElementsMatch(t, d4pairing, [][]byte{})
	require.ElementsMatch(t, e4pairing, [][]byte{})
	require.ElementsMatch(t, f4pairing, [][]byte{})
	require.ElementsMatch(t, g4pairing, [][]byte{})
	require.ElementsMatch(t, h4pairing, [][]byte{})
	require.ElementsMatch(t,
		[]bool{isABob, isBBob, isCBob, isDBob, isEBob, isFBob, isGBob, isHBob},
		[]bool{false, false, false, false, false, false, false, false},
	)
}

func TestProcessRound(t *testing.T) {
	a := []byte{0x01}
	aKey := curves.ED448().Scalar.Random(rand.Reader)
	aPoint := curves.ED448().Point.Generator().Mul(aKey)
	b := []byte{0x02}
	bKey := curves.ED448().Scalar.Random(rand.Reader)
	bPoint := curves.ED448().Point.Generator().Mul(bKey)
	c := []byte{0x03}
	cKey := curves.ED448().Scalar.Random(rand.Reader)
	cPoint := curves.ED448().Point.Generator().Mul(cKey)
	d := []byte{0x04}
	dKey := curves.ED448().Scalar.Random(rand.Reader)
	dPoint := curves.ED448().Point.Generator().Mul(dKey)
	e := []byte{0x05}
	eKey := curves.ED448().Scalar.Random(rand.Reader)
	ePoint := curves.ED448().Point.Generator().Mul(eKey)
	f := []byte{0x06}
	fKey := curves.ED448().Scalar.Random(rand.Reader)
	fPoint := curves.ED448().Point.Generator().Mul(fKey)
	g := []byte{0x07}
	gKey := curves.ED448().Scalar.Random(rand.Reader)
	gPoint := curves.ED448().Point.Generator().Mul(gKey)
	h := []byte{0x08}
	hKey := curves.ED448().Scalar.Random(rand.Reader)
	hPoint := curves.ED448().Point.Generator().Mul(hKey)

	peerKeys := []curves.Scalar{aKey, bKey, cKey, dKey, eKey, fKey, gKey, hKey}
	peerPoints := [][]byte{
		aPoint.ToAffineCompressed(),
		bPoint.ToAffineCompressed(),
		cPoint.ToAffineCompressed(),
		dPoint.ToAffineCompressed(),
		ePoint.ToAffineCompressed(),
		fPoint.ToAffineCompressed(),
		gPoint.ToAffineCompressed(),
		hPoint.ToAffineCompressed(),
	}
	idkPoints := []curves.Point{
		aPoint,
		bPoint,
		cPoint,
		dPoint,
		ePoint,
		fPoint,
		gPoint,
		hPoint,
	}

	peers := [][]byte{a, b, c, d, e, f, g, h}
	peerSecrets := [][]curves.Scalar{}
	originalPeerSecrets := [][]curves.Scalar{}

	for i := range peers {
		fmt.Printf("generating secrets for peer %d\n", i)
		x := curves.BLS48581G1().Scalar.Random(rand.Reader)
		xs := x.Clone()
		secrets := []curves.Scalar{x}
		originalSecrets := []curves.Scalar{x}
		fmt.Printf("secret %d(%d): %+x\n", i, 0, xs.Bytes())

		for j := 0; j < 1; j++ {
			xs = xs.Mul(x)
			secrets = append(secrets, xs)
			fmt.Printf("secret %d(%d): %+x\n", i, 1, xs.Bytes())
			originalSecrets = append(originalSecrets, xs)
		}

		peerSecrets = append(peerSecrets, secrets)
		originalPeerSecrets = append(originalPeerSecrets, originalSecrets)
	}

	messages := syncmap.Map{}
	send := func(peer []byte) func(seq int, dst, msg []byte) error {
		return func(seq int, dst, msg []byte) error {
			fmt.Printf("send %d bytes for seq %d to %+x\n", len(msg), seq, dst)

			b := byte(seq)
			dst = append(append(append([]byte{}, b), peer...), dst...)
			if msg == nil {
				msg = []byte{0x01}
			}
			messages.Store(string(dst), string(msg))
			return nil
		}
	}
	recv := func(peer []byte) func(seq int, src []byte) ([]byte, error) {
		return func(seq int, src []byte) ([]byte, error) {
			fmt.Printf("recv %d from %+x\n", seq, src)

			b := byte(seq)
			bsrc := append(append(append([]byte{}, b), src...), peer...)

			msg, ok := messages.LoadAndDelete(string(bsrc))
			for !ok {
				fmt.Printf("no message yet, waiting for recv %d from %+x\n", seq, src)

				time.Sleep(100 * time.Millisecond)
				msg, ok = messages.LoadAndDelete(string(bsrc))
			}

			return []byte(msg.(string)), nil
		}
	}

	for j := 1; j < 4; j++ {
		eg := errgroup.Group{}
		eg.SetLimit(8)
		for i := range peers {
			i := i
			eg.Go(func() error {
				fmt.Printf("running round %d for %d\n", j, i)

				newSecrets, err := application.ProcessRound(
					peerPoints[i],
					peerKeys[i],
					j,
					peerPoints,
					idkPoints,
					peerSecrets[i],
					curves.BLS48581G1(),
					send(peerPoints[i]),
					recv(peerPoints[i]),
					[]byte{0x01},
				)
				require.NoError(t, err)

				for s := range newSecrets {
					fmt.Printf("secret %d(%d): %+x\n", i, s, newSecrets[s].Bytes())
				}

				peerSecrets[i] = newSecrets
				return err
			})
		}

		err := eg.Wait()
		require.NoError(t, err)
	}

	checks := []curves.Point{}
	for i := 0; i < len(originalPeerSecrets[0]); i++ {
		mul := curves.BLS48581G1().Scalar.One()
		for j := 0; j < len(originalPeerSecrets); j++ {
			mul = mul.Mul(originalPeerSecrets[j][i])
		}
		checks = append(checks, curves.BLS48581G1().Point.Generator().Mul(mul))
	}

	result := []curves.Point{}
	for i := 0; i < len(peerSecrets[0]); i++ {
		var add curves.Point = nil
		for j := 0; j < len(peerSecrets); j++ {
			if add == nil {
				add = curves.BLS48581G1().Point.Generator().Mul(peerSecrets[j][i])
			} else {
				add = add.Add(
					curves.BLS48581G1().Point.Generator().Mul(peerSecrets[j][i]),
				)
			}
		}
		result = append(result, add)
	}

	for i := range checks {
		require.Equal(t, true, checks[i].Equal(result[i]))
	}
}

func TestCompositeConstructionOfBLS(t *testing.T) {
	// needed to verify signatures
	bls48581.Init()
	curve := curves.BLS48581G1()
	hashKeySeed := [simplest.DigestSize]byte{}
	_, err := rand.Read(hashKeySeed[:])
	require.NoError(t, err)

	alpha := curve.Scalar.Random(rand.Reader)
	beta := curve.Scalar.Random(rand.Reader)
	alpha2 := alpha.Mul(alpha)
	beta2 := beta.Mul(beta)

	sender := application.NewMultiplySender([]curves.Scalar{alpha, alpha2}, curve, hashKeySeed)
	receiver := application.NewMultiplyReceiver([]curves.Scalar{beta, beta2}, curve, hashKeySeed)

	var senderMsg []byte = nil
	var receiverMsg []byte = nil

	sErr := sender.Init()
	require.NoError(t, sErr)

	rErr := receiver.Init()
	require.NoError(t, rErr)

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

	drSender, err := channel.NewDoubleRatchetParticipant(
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

	drReceiver, err := channel.NewDoubleRatchetParticipant(
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

	for !sender.IsDone() && !receiver.IsDone() {
		senderMsg, err = sender.Next(receiverMsg)
		require.NoError(t, err)
		senderEnvelope, err := drSender.RatchetEncrypt(senderMsg)
		require.NoError(t, err)

		senderMsg, err = drReceiver.RatchetDecrypt(senderEnvelope)
		require.NoError(t, err)

		receiverMsg, err = receiver.Next(senderMsg)
		require.NoError(t, err)

		receiverEnvelope, err := drReceiver.RatchetEncrypt(receiverMsg)
		require.NoError(t, err)

		receiverMsg, err = drSender.RatchetDecrypt(receiverEnvelope)
		require.NoError(t, err)
	}

	senderPoints := sender.GetPoints()
	receiverPoints := receiver.GetPoints()

	generator := alpha.Point().Generator()
	product := generator.Mul(alpha).Mul(beta)
	sum := senderPoints[0].Add(receiverPoints[0])

	product2 := generator.Mul(alpha2).Mul(beta2)
	sum2 := senderPoints[1].Add(receiverPoints[1])
	fmt.Println(alpha.Bytes())
	fmt.Println(beta.Bytes())
	fmt.Println(curves.BLS48581G1().Point.Generator().ToAffineCompressed())

	fmt.Println(sum.ToAffineCompressed())
	fmt.Println(product.ToAffineCompressed())
	require.Equal(t, true, product.Equal(sum))
	require.Equal(t, true, product2.Equal(sum2))
	sendSig, err := sender.GetSignatureOfProverKey([]byte{0x01})
	require.NoError(t, err)
	require.Equal(t, len(sendSig), 74)
	recvSig, err := receiver.GetSignatureOfProverKey([]byte{0x02})
	require.NoError(t, err)
	require.Equal(t, len(recvSig), 74)
	require.NoError(t, application.VerifySignatureOfProverKey(
		[]byte{0x01},
		sendSig,
		curves.BLS48581G2().Point.Generator().Mul(
			sender.GetScalars()[0],
		),
	))
	require.NoError(t, application.VerifySignatureOfProverKey(
		[]byte{0x02},
		recvSig,
		curves.BLS48581G2().Point.Generator().Mul(
			receiver.GetScalars()[0],
		),
	))
	require.Error(t, application.VerifySignatureOfProverKey(
		[]byte{0x02},
		sendSig,
		curves.BLS48581G2().Point.Generator().Mul(
			sender.GetScalars()[0],
		),
	))
	require.Error(t, application.VerifySignatureOfProverKey(
		[]byte{0x01},
		recvSig,
		curves.BLS48581G2().Point.Generator().Mul(
			receiver.GetScalars()[0],
		),
	))
}
