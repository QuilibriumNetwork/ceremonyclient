package kzg

import (
	_ "embed"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"math/big"
	"os"
	"sync"

	"github.com/pkg/errors"
	"golang.org/x/crypto/sha3"
	rbls48581 "source.quilibrium.com/quilibrium/monorepo/bls48581"
	"source.quilibrium.com/quilibrium/monorepo/nekryptology/pkg/core/curves"
	"source.quilibrium.com/quilibrium/monorepo/nekryptology/pkg/core/curves/native/bls48581"
)

type PowersOfTauJson struct {
	G1Affines []string `json:"G1Powers"`
	G2Affines []string `json:"G2Powers"`
	G1FFT     []string `json:"G1FFT"`
}

type ContributionJson struct {
	PowersOfTau   PowersOfTauJson `json:"powersOfTau"`
	PotPubKey     string          `json:"potPubKey"`
	Witness       Witness         `json:"witness"`
	VoucherPubKey string          `json:"voucherPubKey"`
}

type BatchContribution struct {
	Contribution Contribution
}

type PowersOfTau struct {
	G1Affines []*bls48581.ECP
	G2Affines []*bls48581.ECP8
	G1FFT     []*bls48581.ECP
}

type CeremonyState struct {
	PowersOfTau    PowersOfTauJson `json:"powersOfTau"`
	PotPubKey      string          `json:"potPubKey"`
	Witness        Witness         `json:"witness"`
	VoucherPubKeys []string        `json:"voucherPubKeys"`
}

type Witness struct {
	RunningProducts []string `json:"runningProducts"`
	PotPubKeys      []string `json:"potPubKeys"`
}

type Contribution struct {
	NumG1Powers int
	NumG2Powers int
	PowersOfTau PowersOfTau
	PotPubKey   *bls48581.ECP8
}

type KZGProver struct {
	bytesPerScalar int
	curve          *curves.PairingCurve
	hashFunc       func() hash.Hash
	orderBI        *big.Int
}

var RootOfUnityBLS48581 map[uint64]curves.PairingScalar = make(map[uint64]curves.PairingScalar)
var RootsOfUnityBLS48581 map[uint64][]curves.PairingScalar = make(map[uint64][]curves.PairingScalar)
var ReverseRootsOfUnityBLS48581 map[uint64][]curves.PairingScalar = make(map[uint64][]curves.PairingScalar)
var CeremonyBLS48581G1 []curves.PairingPoint
var CeremonyBLS48581G2 []curves.PairingPoint
var CeremonyRunningProducts []curves.PairingPoint
var CeremonyPotPubKeys []curves.PairingPoint
var CeremonySignatories []curves.Point
var FFTBLS48581 map[uint64][]curves.PairingPoint = make(map[uint64][]curves.PairingPoint)

func TestInit(file string) {
	// start with phase 1 ceremony:
	csBytes, err := os.ReadFile(file)
	if err != nil {
		panic(err)
	}

	bls48581.Init()

	cs := &CeremonyState{}
	if err := json.Unmarshal(csBytes, cs); err != nil {
		panic(err)
	}

	g1s := make([]curves.PairingPoint, 65536)
	g2s := make([]curves.PairingPoint, 257)
	g1ffts := make([]curves.PairingPoint, 65536)
	wg := sync.WaitGroup{}
	wg.Add(65536)

	for i := 0; i < 65536; i++ {
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

			if i < 257 {
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

	wg.Add(len(cs.Witness.RunningProducts))
	CeremonyRunningProducts = make([]curves.PairingPoint, len(cs.Witness.RunningProducts))
	for i, s := range cs.Witness.RunningProducts {
		i, s := i, s
		go func() {
			b, err := hex.DecodeString(s[2:])
			if err != nil {
				panic(err)
			}

			g1, err := curves.BLS48581G1().NewGeneratorPoint().FromAffineCompressed(b)
			if err != nil {
				panic(err)
			}
			CeremonyRunningProducts[i] = g1.(curves.PairingPoint)
			wg.Done()
		}()
	}
	wg.Wait()

	wg.Add(len(cs.Witness.PotPubKeys))
	CeremonyPotPubKeys = make([]curves.PairingPoint, len(cs.Witness.PotPubKeys))
	for i, s := range cs.Witness.PotPubKeys {
		i, s := i, s
		go func() {
			b, err := hex.DecodeString(s[2:])
			if err != nil {
				panic(err)
			}

			g2, err := curves.BLS48581G2().NewGeneratorPoint().FromAffineCompressed(b)
			if err != nil {
				panic(err)
			}
			CeremonyPotPubKeys[i] = g2.(curves.PairingPoint)
			wg.Done()
		}()
	}
	wg.Wait()

	wg.Add(len(cs.VoucherPubKeys))
	CeremonySignatories = make([]curves.Point, len(cs.VoucherPubKeys))
	for i, s := range cs.VoucherPubKeys {
		i, s := i, s
		go func() {
			b, err := hex.DecodeString(s[2:])
			if err != nil {
				panic(err)
			}

			CeremonySignatories[i], err = curves.ED448().Point.FromAffineCompressed(b)
			if err != nil {
				panic(err)
			}
			wg.Done()
		}()
	}
	wg.Wait()

	CeremonyBLS48581G1 = g1s
	CeremonyBLS48581G2 = g2s

	// Post-ceremony, precompute everything and put it in the finalized ceremony
	// state
	modulus := make([]byte, 73)
	bls48581.NewBIGints(bls48581.CURVE_Order, nil).ToBytes(modulus)
	q := new(big.Int).SetBytes(modulus)
	sizes := []int64{16, 32, 64, 128, 256, 512, 1024, 2048, 65536}

	wg.Add(len(sizes))
	root := make([]curves.PairingScalar, 9)
	roots := make([][]curves.PairingScalar, 9)
	reverseRoots := make([][]curves.PairingScalar, 9)
	ffts := make([][]curves.PairingPoint, 9)

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
		RootOfUnityBLS48581[uint64(sizes[i])] = root[i]
		RootsOfUnityBLS48581[uint64(sizes[i])] = roots[i]
		ReverseRootsOfUnityBLS48581[uint64(sizes[i])] = reverseRoots[i]

		go func() {
			// We precomputed 65536, others are cheap and will be fully precomputed
			// post-ceremony
			if sizes[i] < 65536 {
				fftG1, err := FFTG1(
					CeremonyBLS48581G1[:sizes[i]],
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
		FFTBLS48581[uint64(sizes[i])] = ffts[i]
	}
}

//go:embed ceremony.json
var csBytes []byte

func Init() {
	rbls48581.Init()
}

func NewKZGProver(
	curve *curves.PairingCurve,
	hashFunc func() hash.Hash,
	orderBI *big.Int,
) *KZGProver {
	if curve.Name != curves.BLS48581Name {
		// kzg ceremony transcript not available for any other curve
		return nil
	}

	return &KZGProver{
		bytesPerScalar: 64,
		curve:          curve,
		hashFunc:       hashFunc,
		orderBI:        orderBI,
	}
}

func DefaultKZGProver() *KZGProver {
	modulus := make([]byte, 73)
	bls48581.NewBIGints(bls48581.CURVE_Order, nil).ToBytes(modulus)
	q := new(big.Int).SetBytes(modulus)
	return NewKZGProver(
		curves.BLS48581(curves.BLS48581G1().Point),
		sha3.New256,
		q,
	)
}

func (p *KZGProver) BytesToPolynomial(
	bytes []byte,
) ([]curves.PairingScalar, error) {
	size := len(bytes) / p.bytesPerScalar
	truncLast := false
	if len(bytes)%p.bytesPerScalar > 0 {
		truncLast = true
	}

	poly := []curves.PairingScalar{}
	var i int
	for i = 0; i < size; i++ {
		scalar, err := p.curve.NewScalar().SetBytes(
			bytes[i*p.bytesPerScalar : (i+1)*p.bytesPerScalar],
		)
		if err != nil {
			return nil, errors.Wrap(err, "could not set bytes for scalar")
		}
		poly = append(
			poly,
			scalar.(curves.PairingScalar),
		)
	}

	if truncLast {
		scalar, err := p.curve.NewScalar().SetBytes(
			bytes[i*p.bytesPerScalar:],
		)
		if err != nil {
			return nil, errors.Wrap(err, "could not set bytes for scalar")
		}
		poly = append(
			poly,
			scalar.(curves.PairingScalar),
		)
	}

	return poly, nil
}

func (p *KZGProver) PointLinearCombination(
	points []curves.PairingPoint,
	scalars []curves.PairingScalar,
) (curves.PairingPoint, error) {
	if len(points) != len(scalars) {
		return nil, fmt.Errorf(
			"length mismatch between arguments, points: %d, scalars: %d",
			len(points),
			len(scalars),
		)
	}

	result := p.curve.NewG1IdentityPoint()
	for i, p := range points {
		result = result.Add(p.Mul(scalars[i])).(curves.PairingPoint)
	}

	return result, nil
}

func (p *KZGProver) PolynomialLinearCombination(
	polynomials [][]curves.PairingScalar,
	scalars []curves.PairingScalar,
) ([]curves.PairingScalar, error) {
	if len(polynomials) != len(scalars) {
		return nil, errors.New("length mismatch between arguments")
	}

	result := make([]curves.PairingScalar, len(polynomials[0]))
	for i := range polynomials[0] {
		result[i] = p.curve.NewScalar()
	}

	for j, ps := range polynomials {
		for i, p := range ps {
			result[i] = result[i].Add(p.Mul(scalars[j])).(curves.PairingScalar)
		}
	}

	return result, nil
}

func (p *KZGProver) EvaluateLagrangeForm(
	polynomial []curves.PairingScalar,
	x curves.PairingScalar,
	fftWidth uint64,
	scale uint8,
) (curves.PairingScalar, error) {
	if uint64(len(polynomial)) != fftWidth>>scale {
		return nil, errors.Wrap(
			errors.New("polynomial length does not match stride"),
			"evaluate lagrange form",
		)
	}

	width := p.curve.NewScalar().New(len(polynomial))

	y := p.curve.NewScalar()
	for i := 0; i < len(polynomial); i++ {
		numerator := polynomial[i].Mul(RootsOfUnityBLS48581[fftWidth][i<<scale])
		value := numerator.Div(x.Sub(
			RootsOfUnityBLS48581[fftWidth][i<<scale]))
		y = y.Add(value).(curves.PairingScalar)
	}

	xBI := x.BigInt()
	modulus := make([]byte, 73)
	bls48581.NewBIGints(bls48581.CURVE_Order, nil).ToBytes(modulus)
	q := new(big.Int).SetBytes(modulus)
	xBI.Exp(xBI, width.BigInt(), q)
	xBI.Sub(xBI, big.NewInt(1))
	value, err := p.curve.NewScalar().SetBigInt(xBI)
	value = value.Div(width)

	if err != nil {
		return nil, errors.Wrap(err, "evaluate lagrange form")
	}

	return y.Mul(value).(curves.PairingScalar), nil
}

func (p *KZGProver) ComputeChallenges(
	polynomials [][]curves.PairingScalar,
	commitments []curves.PairingPoint,
) ([]curves.PairingScalar, curves.Scalar, error) {
	l := len(polynomials)
	degree := len(polynomials[0])
	h := p.hashFunc()

	if _, err := h.Write([]byte("q_kzg_challenges")); err != nil {
		return nil, nil, errors.Wrap(err, "could not write to hash")
	}

	if _, err := h.Write(binary.BigEndian.AppendUint32(
		[]byte{},
		uint32(l),
	)); err != nil {
		return nil, nil, errors.Wrap(err, "could not write to hash")
	}

	if _, err := h.Write(binary.BigEndian.AppendUint32(
		[]byte{},
		uint32(degree),
	)); err != nil {
		return nil, nil, errors.Wrap(err, "could not write to hash")
	}

	for _, poly := range polynomials {
		for _, scalar := range poly {
			if _, err := h.Write(scalar.Bytes()); err != nil {
				return nil, nil, errors.Wrap(err, "could not write to hash")
			}
		}
	}

	for _, commitment := range commitments {
		if _, err := h.Write(commitment.ToAffineCompressed()); err != nil {
			return nil, nil, errors.Wrap(err, "could not write to hash")
		}
	}

	result := h.Sum(nil)

	powers := make([]curves.PairingScalar, len(commitments))
	resultPow := append([]byte{}, result...)
	resultPow = append(resultPow, 0x00)
	rs := p.curve.NewScalar().Hash(resultPow)

	eval := append([]byte{}, result...)
	eval = append(eval, 0x01)
	evalScalar := p.curve.NewScalar().Hash(eval)

	s, err := p.curve.NewScalar().SetBigInt(big.NewInt(1))
	if err != nil {
		return nil, nil, errors.Wrap(err, "could not set bytes")
	}

	for i := range powers {
		powers[i] = s.Clone().(curves.PairingScalar)
		s = s.Mul(rs)
	}

	return powers, evalScalar, nil
}

func (p *KZGProver) AggregatePolynomialCommitment(
	polynomials [][]curves.PairingScalar,
	commitments []curves.PairingPoint,
) ([]curves.PairingScalar, curves.PairingPoint, curves.PairingScalar, error) {
	powers, evalScalar, err := p.ComputeChallenges(
		polynomials,
		commitments,
	)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "aggregate polynomial commitment")
	}

	pairEval, ok := evalScalar.(curves.PairingScalar)
	if !ok {
		return nil, nil, nil, errors.Wrap(
			errors.New("invalid scalar"),
			"aggregate polynomial commitment",
		)
	}

	aggregatePolynomial, err := p.PolynomialLinearCombination(polynomials, powers)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "aggregate polynomial commitment")
	}

	aggregateCommitment, err := p.PointLinearCombination(commitments, powers)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "aggregate polynomial commitment")
	}

	return aggregatePolynomial, aggregateCommitment, pairEval, nil
}

func (p *KZGProver) Prove(
	polynomial []curves.PairingScalar,
	commitment curves.PairingPoint,
	z curves.PairingScalar,
) (
	curves.PairingPoint,
	error,
) {
	if nearestPowerOfTwo(uint64(len(polynomial))) != uint64(len(polynomial)) {
		return nil, errors.Wrap(
			errors.New("polynomial must be power of two"),
			"prove",
		)
	}

	y, err := p.EvaluateLagrangeForm(
		polynomial,
		z,
		uint64(len(polynomial)),
		0,
	)
	if err != nil {
		return nil, errors.Wrap(err, "prove")
	}

	quotient := make([]curves.PairingScalar, len(polynomial))
	for i := range quotient {
		shifted := polynomial[i].Sub(y).(curves.PairingScalar)
		if z.Cmp(RootsOfUnityBLS48581[uint64(len(polynomial))][i]) == 0 {
			return nil, errors.Wrap(
				errors.New("invalid challenge"),
				"prove",
			)
		}
		denominator := RootsOfUnityBLS48581[uint64(len(polynomial))][i].Sub(
			z,
		).(curves.PairingScalar)
		quotient[i] = shifted.Div(denominator).(curves.PairingScalar)
	}

	r, err := p.PointLinearCombination(
		FFTBLS48581[uint64(len(polynomial))],
		quotient,
	)
	return r, errors.Wrap(err, "prove")
}

func (p *KZGProver) Commit(
	polynomial []curves.PairingScalar,
) (curves.PairingPoint, error) {
	commitment, err := p.PointLinearCombination(
		FFTBLS48581[uint64(len(polynomial))],
		polynomial,
	)
	return commitment, errors.Wrap(err, "commit")
}

func (p *KZGProver) CommitAggregate(
	polynomials [][]curves.PairingScalar,
) ([]curves.PairingPoint, error) {
	commitments := make([]curves.PairingPoint, len(polynomials))
	for i, poly := range polynomials {
		if nearestPowerOfTwo(uint64(len(poly))) != uint64(len(poly)) {
			return nil, errors.Wrap(
				errors.New("polynomial must be power of two"),
				"prove aggregate",
			)
		}

		var err error
		commitments[i], err = p.Commit(poly)
		if err != nil {
			return nil, errors.Wrap(err, "commit aggregate")
		}
	}

	return commitments, nil
}

func (p *KZGProver) ProveAggregate(
	polynomials [][]curves.PairingScalar,
	commitments []curves.PairingPoint,
) (
	curves.PairingPoint,
	curves.PairingPoint,
	error,
) {
	poly, commitment, challenge, err := p.AggregatePolynomialCommitment(
		polynomials,
		commitments,
	)
	if err != nil {
		return nil, nil, errors.Wrap(err, "prove aggregate")
	}

	proof, err := p.Prove(poly, commitment, challenge)
	return proof, commitment, errors.Wrap(err, "prove aggregate")
}

func (p *KZGProver) Verify(
	commitment curves.PairingPoint,
	z curves.PairingScalar,
	y curves.PairingScalar,
	proof curves.PairingPoint,
) bool {
	z2 := p.curve.NewG2GeneratorPoint().Mul(z).(curves.PairingPoint)
	y1 := p.curve.NewG1GeneratorPoint().Mul(y).(curves.PairingPoint)
	xz := CeremonyBLS48581G2[1].Sub(z2).(curves.PairingPoint)
	cy := commitment.Sub(y1).(curves.PairingPoint)

	gt := xz.MultiPairing(
		proof,
		xz,
		cy.Neg().(curves.PairingPoint),
		p.curve.NewG2GeneratorPoint(),
	)
	return gt.IsOne()
}

func (p *KZGProver) VerifyAggregateProof(
	polynomials [][]curves.PairingScalar,
	commitments []curves.PairingPoint,
	commitment curves.PairingPoint,
	proof curves.PairingPoint,
) (bool, error) {
	aggregatedPolynomial, aggregatedCommitment, challenge, err :=
		p.AggregatePolynomialCommitment(polynomials, commitments)
	if err != nil {
		return false, errors.Wrap(err, "verify aggregate proof")
	}

	if !aggregatedCommitment.Equal(commitment) {
		return false, errors.Wrap(
			errors.New("aggregate commitment does not match"),
			"verify aggregate proof",
		)
	}

	y, err := p.EvaluateLagrangeForm(
		aggregatedPolynomial,
		challenge,
		uint64(len(aggregatedPolynomial)),
		0,
	)
	if err != nil {
		return false, errors.Wrap(err, "verify aggregate proof")
	}

	return p.Verify(
		aggregatedCommitment,
		challenge,
		y,
		proof,
	), nil
}
