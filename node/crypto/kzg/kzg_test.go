package kzg_test

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
	"source.quilibrium.com/quilibrium/monorepo/nekryptology/pkg/core/curves"
	"source.quilibrium.com/quilibrium/monorepo/nekryptology/pkg/core/curves/native/bls48581"
	"source.quilibrium.com/quilibrium/monorepo/node/crypto/kzg"
)

func TestMain(m *testing.M) {
	csBytes, err := os.ReadFile("./ceremony.json")
	if err != nil {
		panic(err)
	}

	cs := &kzg.CeremonyState{}
	if err := json.Unmarshal(csBytes, cs); err != nil {
		panic(err)
	}

	g1s := make([]curves.PairingPoint, 16)
	g2s := make([]curves.PairingPoint, 2)
	g1ffts := make([]curves.PairingPoint, 16)
	wg := sync.WaitGroup{}
	wg.Add(16)

	for i := 0; i < 16; i++ {
		i := i
		go func() {
			b, err := hex.DecodeString(cs.PowersOfTau.G1Affines[i][2:])
			if err != nil {
				panic(err)
			}
			g1, err := curves.BLS48581G1().NewGeneratorPoint().FromAffineCompressed(b)
			if err != nil {
				panic(err)
			}
			g1s[i] = g1.(curves.PairingPoint)

			f, err := hex.DecodeString(cs.PowersOfTau.G1FFT[i][2:])
			if err != nil {
				panic(err)
			}
			g1fft, err := curves.BLS48581G1().NewGeneratorPoint().FromAffineCompressed(f)
			if err != nil {
				panic(err)
			}
			g1ffts[i] = g1fft.(curves.PairingPoint)

			if i < 2 {
				b, err := hex.DecodeString(cs.PowersOfTau.G2Affines[i][2:])
				if err != nil {
					panic(err)
				}
				g2, err := curves.BLS48581G2().NewGeneratorPoint().FromAffineCompressed(
					b,
				)
				if err != nil {
					panic(err)
				}
				g2s[i] = g2.(curves.PairingPoint)
			}
			wg.Done()
		}()
	}

	wg.Wait()

	kzg.CeremonyBLS48581G1 = g1s
	kzg.CeremonyBLS48581G2 = g2s

	// Post-ceremony, precompute everything and put it in the finalized ceremony
	// state
	modulus := make([]byte, 73)
	bls48581.NewBIGints(bls48581.CURVE_Order).ToBytes(modulus)
	q := new(big.Int).SetBytes(modulus)
	sizes := []int64{16}

	wg.Add(len(sizes))
	root := make([]curves.PairingScalar, 1)
	roots := make([][]curves.PairingScalar, 1)
	reverseRoots := make([][]curves.PairingScalar, 1)
	ffts := make([][]curves.PairingPoint, 1)

	for idx, i := range sizes {
		i := i
		idx := idx
		go func() {
			exp := new(big.Int).Quo(
				new(big.Int).Sub(q, big.NewInt(1)),
				big.NewInt(i),
			)
			rootOfUnity := new(big.Int).Exp(big.NewInt(int64(37)), exp, q)
			roots[idx] = make([]curves.PairingScalar, i+1)
			reverseRoots[idx] = make([]curves.PairingScalar, i+1)
			wg2 := sync.WaitGroup{}
			wg2.Add(int(i))
			for j := int64(0); j < i; j++ {
				j := j
				go func() {
					rev := big.NewInt(int64(j))
					r := new(big.Int).Exp(
						rootOfUnity,
						rev,
						q,
					)
					scalar, _ := (&curves.ScalarBls48581{}).SetBigInt(r)

					if rev.Cmp(big.NewInt(1)) == 0 {
						root[idx] = scalar.(curves.PairingScalar)
					}

					roots[idx][j] = scalar.(curves.PairingScalar)
					reverseRoots[idx][i-j] = roots[idx][j]
					wg2.Done()
				}()
			}
			wg2.Wait()
			roots[idx][i] = roots[idx][0]
			reverseRoots[idx][0] = reverseRoots[idx][i]
			wg.Done()
		}()
	}
	wg.Wait()

	wg.Add(len(sizes))
	for i := range root {
		i := i
		kzg.RootOfUnityBLS48581[uint64(sizes[i])] = root[i]
		kzg.RootsOfUnityBLS48581[uint64(sizes[i])] = roots[i]
		kzg.ReverseRootsOfUnityBLS48581[uint64(sizes[i])] = reverseRoots[i]

		go func() {
			// We precomputed 65536, others are cheap and will be fully precomputed
			// post-ceremony
			if sizes[i] < 65536 {
				fftG1, err := kzg.FFTG1(
					kzg.CeremonyBLS48581G1[:sizes[i]],
					*curves.BLS48581(
						curves.BLS48581G1().NewGeneratorPoint(),
					),
					uint64(sizes[i]),
					true,
				)
				if err != nil {
					panic(err)
				}

				ffts[i] = fftG1
			} else {
				ffts[i] = g1ffts
			}
			wg.Done()
		}()
	}
	wg.Wait()

	for i := range root {
		kzg.FFTBLS48581[uint64(sizes[i])] = ffts[i]
	}
	code := m.Run()
	os.Exit(code)
}

func TestKzgBytesToPoly(t *testing.T) {
	modulus := make([]byte, 73)
	bls48581.NewBIGints(bls48581.CURVE_Order).ToBytes(modulus)
	q := new(big.Int).SetBytes(modulus)
	p := kzg.NewKZGProver(curves.BLS48581(curves.BLS48581G1().Point), sha3.New256, q)

	poly, err := p.BytesToPolynomial([]byte(
		"Did you ever hear the tragedy of Darth Plagueis The Wise? I thought not." +
			" It's not a story the Jedi would tell you. It's a Sith legend. Darth " +
			"Plagueis was a Dark Lord of the Sith, so powerful and so wise he could " +
			"use the Force to influence the midichlorians to create life… He had such" +
			" a knowledge of the dark side that he could even keep the ones he cared " +
			"about from dying. The dark side of the Force is a pathway to many " +
			"abilities some consider to be unnatural. He became so powerful… the only" +
			" thing he was afraid of was losing his power, which eventually, of " +
			"course, he did. Unfortunately, he taught his apprentice everything he " +
			"knew, then his apprentice killed him in his sleep. Ironic. He could " +
			"save others from death, but not himself."))
	require.NoError(t, err)

	t1, _ := hex.DecodeString("00000000000000000044696420796f7520657665722068656172207468652074726167656479206f6620446172746820506c6167756569732054686520576973653f20492074686f75")
	t2, _ := hex.DecodeString("000000000000000000676874206e6f742e2049742773206e6f7420612073746f727920746865204a65646920776f756c642074656c6c20796f752e204974277320612053697468206c")
	t3, _ := hex.DecodeString("0000000000000000006567656e642e20446172746820506c616775656973207761732061204461726b204c6f7264206f662074686520536974682c20736f20706f77657266756c2061")
	t4, _ := hex.DecodeString("0000000000000000006e6420736f207769736520686520636f756c64207573652074686520466f72636520746f20696e666c75656e636520746865206d69646963686c6f7269616e73")
	t5, _ := hex.DecodeString("00000000000000000020746f20637265617465206c696665e280a62048652068616420737563682061206b6e6f776c65646765206f6620746865206461726b20736964652074686174")
	t6, _ := hex.DecodeString("00000000000000000020686520636f756c64206576656e206b65657020746865206f6e65732068652063617265642061626f75742066726f6d206479696e672e20546865206461726b")
	t7, _ := hex.DecodeString("0000000000000000002073696465206f662074686520466f7263652069732061207061746877617920746f206d616e79206162696c697469657320736f6d6520636f6e736964657220")
	t8, _ := hex.DecodeString("000000000000000000746f20626520756e6e61747572616c2e20486520626563616d6520736f20706f77657266756ce280a620746865206f6e6c79207468696e672068652077617320")
	t9, _ := hex.DecodeString("000000000000000000616672616964206f6620776173206c6f73696e672068697320706f7765722c207768696368206576656e7475616c6c792c206f6620636f757273652c20686520")
	t10, _ := hex.DecodeString("0000000000000000006469642e20556e666f7274756e6174656c792c20686520746175676874206869732061707072656e746963652065766572797468696e67206865206b6e65772c")
	t11, _ := hex.DecodeString("000000000000000000207468656e206869732061707072656e74696365206b696c6c65642068696d20696e2068697320736c6565702e2049726f6e69632e20486520636f756c642073")
	t12, _ := hex.DecodeString("00000000000000000000000000000000000000000000000000000000000000000000617665206f74686572732066726f6d2064656174682c20627574206e6f742068696d73656c662e")
	target := [][]byte{t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11, t12}
	actual := [][]byte{}

	for _, p := range poly {
		actual = append(actual, p.Bytes())
		fmt.Println(hex.EncodeToString(p.Bytes()))
	}
	require.Equal(t, target, actual)
}

func TestPolynomialCommitment(t *testing.T) {
	modulus := make([]byte, 73)
	bls48581.NewBIGints(bls48581.CURVE_Order).ToBytes(modulus)
	q := new(big.Int).SetBytes(modulus)
	p := kzg.NewKZGProver(curves.BLS48581(curves.BLS48581G1().Point), sha3.New256, q)

	poly, err := p.BytesToPolynomial([]byte(
		"Did you ever hear the tragedy of Darth Plagueis The Wise? I thought not." +
			" It's not a story the Jedi would tell you. It's a Sith legend. Darth " +
			"Plagueis was a Dark Lord of the Sith, so powerful and so wise he could " +
			"use the Force to influence the midichlorians to create life… He had such" +
			" a knowledge of the dark side that he could even keep the ones he cared " +
			"about from dying. The dark side of the Force is a pathway to many " +
			"abilities some consider to be unnatural. He became so powerful… the only" +
			" thing he was afraid of was losing his power, which eventually, of " +
			"course, he did. Unfortunately, he taught his apprentice everything he " +
			"knew, then his apprentice killed him in his sleep. Ironic. He could " +
			"save others from death, but not himself."))
	for i := len(poly); i < 16; i++ {
		poly = append(poly, curves.BLS48581G1().NewScalar().(curves.PairingScalar))
	}
	require.NoError(t, err)
	evalPoly, err := kzg.FFT(
		poly,
		*curves.BLS48581(
			curves.BLS48581G1().NewGeneratorPoint(),
		),
		16,
		false,
	)
	require.NoError(t, err)

	require.NoError(t, err)
	commitByCoeffs, err := p.PointLinearCombination(
		kzg.CeremonyBLS48581G1[:16],
		poly,
	)
	require.NoError(t, err)
	commitByEval, err := p.PointLinearCombination(
		kzg.FFTBLS48581[16],
		evalPoly,
	)
	require.NoError(t, err)
	fmt.Println(commitByCoeffs.ToAffineCompressed())
	fmt.Println(commitByEval.ToAffineCompressed())
	require.True(t, commitByCoeffs.Equal(commitByEval))
}

func TestKZGProof(t *testing.T) {
	modulus := make([]byte, 73)
	bls48581.NewBIGints(bls48581.CURVE_Order).ToBytes(modulus)
	q := new(big.Int).SetBytes(modulus)
	p := kzg.NewKZGProver(curves.BLS48581(curves.BLS48581G1().Point), sha3.New256, q)

	poly, err := p.BytesToPolynomial([]byte(
		"Did you ever hear the tragedy of Darth Plagueis The Wise? I thought not." +
			" It's not a story the Jedi would tell you. It's a Sith legend. Darth " +
			"Plagueis was a Dark Lord of the Sith, so powerful and so wise he could " +
			"use the Force to influence the midichlorians to create life… He had such" +
			" a knowledge of the dark side that he could even keep the ones he cared " +
			"about from dying. The dark side of the Force is a pathway to many " +
			"abilities some consider to be unnatural. He became so powerful… the only" +
			" thing he was afraid of was losing his power, which eventually, of " +
			"course, he did. Unfortunately, he taught his apprentice everything he " +
			"knew, then his apprentice killed him in his sleep. Ironic. He could " +
			"save others from death, but not himself."))
	require.NoError(t, err)
	for i := len(poly); i < 16; i++ {
		poly = append(poly, curves.BLS48581G1().NewScalar().(curves.PairingScalar))
	}

	evalPoly, err := kzg.FFT(
		poly,
		*curves.BLS48581(
			curves.BLS48581G1().NewGeneratorPoint(),
		),
		16,
		true,
	)
	require.NoError(t, err)

	commit, err := p.Commit(poly)
	require.NoError(t, err)

	z := kzg.RootsOfUnityBLS48581[16][2]
	require.NoError(t, err)

	checky := evalPoly[len(poly)-1]
	for i := len(evalPoly) - 2; i >= 0; i-- {
		checky = checky.Mul(z).Add(evalPoly[i]).(curves.PairingScalar)
	}
	fmt.Printf("%+x\n", checky.Bytes())

	divisors := make([]curves.PairingScalar, 2)
	divisors[0] = (&curves.ScalarBls48581{}).Zero().Sub(z).(*curves.ScalarBls48581)
	divisors[1] = (&curves.ScalarBls48581{}).One().(*curves.ScalarBls48581)

	a := make([]curves.PairingScalar, len(evalPoly))
	for i := 0; i < len(a); i++ {
		a[i] = evalPoly[i].Clone().(*curves.ScalarBls48581)
	}

	// Adapted from Feist's amortized proofs:
	aPos := len(a) - 1
	bPos := len(divisors) - 1
	diff := aPos - bPos
	out := make([]curves.PairingScalar, diff+1, diff+1)
	for diff >= 0 {
		out[diff] = a[aPos].Div(divisors[bPos]).(*curves.ScalarBls48581)
		for i := bPos; i >= 0; i-- {
			a[diff+i] = a[diff+i].Sub(
				out[diff].Mul(divisors[i]),
			).(*curves.ScalarBls48581)
		}
		aPos -= 1
		diff -= 1
	}

	proof, err := p.PointLinearCombination(kzg.CeremonyBLS48581G1[:15], out)
	// proof, err := p.Prove(evalPoly, commit, z.(curves.PairingScalar))
	require.NoError(t, err)
	require.True(t, p.Verify(commit, z, checky, proof))

	commitments, err := p.CommitAggregate(
		[][]curves.PairingScalar{evalPoly},
	)
	require.NoError(t, err)
	proof, commitment, err := p.ProveAggregate(
		[][]curves.PairingScalar{evalPoly},
		commitments,
	)
	require.NoError(t, err)

	valid, err := p.VerifyAggregateProof(
		[][]curves.PairingScalar{evalPoly},
		commitments,
		commitment,
		proof,
	)
	require.False(t, proof.IsIdentity())
	require.NoError(t, err)
	require.False(t, valid)
}
