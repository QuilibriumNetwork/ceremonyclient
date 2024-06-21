package channel

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"

	"github.com/pkg/errors"
	"source.quilibrium.com/quilibrium/monorepo/nekryptology/pkg/core/curves"
)

type Feldman struct {
	threshold                   int
	total                       int
	id                          int
	fragsForCounterparties      map[int][]byte
	fragsFromCounterparties     map[int]curves.Scalar
	zkpok                       curves.Scalar
	secret                      curves.Scalar
	scalar                      curves.Scalar
	generator                   curves.Point
	publicKey                   curves.Point
	point                       curves.Point
	randomCommitmentPoint       curves.Point
	round                       FeldmanRound
	zkcommitsFromCounterparties map[int][]byte
	pointsFromCounterparties    map[int]curves.Point
	curve                       curves.Curve
}

type FeldmanReveal struct {
	Point                 []byte
	RandomCommitmentPoint []byte
	ZKPoK                 []byte
}

var ErrWrongRound = errors.New("wrong round for feldman")

type FeldmanRound int

const (
	FELDMAN_ROUND_UNINITIALIZED = FeldmanRound(0)
	FELDMAN_ROUND_INITIALIZED   = FeldmanRound(1)
	FELDMAN_ROUND_COMMITTED     = FeldmanRound(2)
	FELDMAN_ROUND_REVEALED      = FeldmanRound(3)
	FELDMAN_ROUND_RECONSTRUCTED = FeldmanRound(4)
)

func NewFeldman(
	threshold, total, id int,
	secret curves.Scalar,
	curve curves.Curve,
	generator curves.Point,
) (*Feldman, error) {
	return &Feldman{
		threshold:                   threshold,
		total:                       total,
		id:                          id,
		fragsForCounterparties:      make(map[int][]byte),
		fragsFromCounterparties:     make(map[int]curves.Scalar),
		zkpok:                       nil,
		secret:                      secret,
		scalar:                      nil,
		generator:                   generator,
		publicKey:                   secret.Point().Generator(),
		point:                       secret.Point().Generator(),
		round:                       FELDMAN_ROUND_UNINITIALIZED,
		zkcommitsFromCounterparties: make(map[int][]byte),
		pointsFromCounterparties:    make(map[int]curves.Point),
		curve:                       curve,
	}, nil
}

func (f *Feldman) SamplePolynomial() error {
	if f.round != FELDMAN_ROUND_UNINITIALIZED {
		return errors.Wrap(ErrWrongRound, "sample polynomial")
	}

	coeffs := append([]curves.Scalar{}, f.secret)

	for i := 1; i < f.threshold; i++ {
		secret := f.curve.NewScalar()
		secret = secret.Random(rand.Reader)
		coeffs = append(coeffs, secret)
	}

	for i := 1; i <= f.total; i++ {
		result := coeffs[0].Clone()
		x := f.curve.Scalar.New(i)

		for j := 1; j < f.threshold; j++ {
			term := coeffs[j].Mul(x)
			result = result.Add(term)
			x = x.Mul(f.curve.Scalar.New(i))
		}

		if i == f.id {
			f.scalar = result
		} else {
			fragBytes := result.Bytes()
			f.fragsForCounterparties[i] = fragBytes
		}
	}

	f.round = FELDMAN_ROUND_INITIALIZED
	return nil
}

func (f *Feldman) Scalar() curves.Scalar {
	return f.scalar
}

func (f *Feldman) GetPolyFrags() (map[int][]byte, error) {
	if f.round != FELDMAN_ROUND_INITIALIZED {
		return nil, errors.Wrap(ErrWrongRound, "get poly frags")
	}

	return f.fragsForCounterparties, nil
}

func (f *Feldman) SetPolyFragForParty(id int, frag []byte) ([]byte, error) {
	if f.round != FELDMAN_ROUND_INITIALIZED {
		return nil, errors.Wrap(ErrWrongRound, "set poly frag for party")
	}

	var err error
	f.fragsFromCounterparties[id], err = f.curve.NewScalar().SetBytes(frag)
	if err != nil {
		return nil, errors.Wrap(err, "set poly frag for party")
	}

	if len(f.fragsFromCounterparties) == f.total-1 {
		for _, v := range f.fragsFromCounterparties {
			f.scalar = f.scalar.Add(v)
		}

		f.point = f.generator.Mul(f.scalar)

		randCommitment := f.curve.NewScalar().Random(rand.Reader)
		f.randomCommitmentPoint = f.generator.Mul(randCommitment)

		randCommitmentPointBytes := f.randomCommitmentPoint.ToAffineCompressed()
		publicPointBytes := f.point.ToAffineCompressed()

		challenge := sha256.Sum256(
			append(
				append([]byte{}, publicPointBytes...),
				randCommitmentPointBytes...,
			),
		)

		challengeBig, err := f.curve.NewScalar().SetBigInt(
			new(big.Int).SetBytes(challenge[:]),
		)
		if err != nil {
			return nil, errors.Wrap(err, "set poly frag for party")
		}

		f.zkpok = f.scalar.Mul(challengeBig).Add(randCommitment)

		zkpokBytes := f.zkpok.Bytes()
		zkcommit := sha256.Sum256(
			append(
				append([]byte{}, randCommitmentPointBytes...),
				zkpokBytes...,
			),
		)

		f.round = FELDMAN_ROUND_COMMITTED
		return zkcommit[:], nil
	}

	return []byte{}, nil
}

func (f *Feldman) ReceiveCommitments(
	id int,
	zkcommit []byte,
) (*FeldmanReveal, error) {
	if f.round != FELDMAN_ROUND_COMMITTED {
		return nil, errors.Wrap(ErrWrongRound, "receive commitments")
	}

	f.zkcommitsFromCounterparties[id] = zkcommit

	if len(f.zkcommitsFromCounterparties) == f.total-1 {
		publicPointBytes := f.point.ToAffineCompressed()
		randCommitmentPointBytes := f.randomCommitmentPoint.ToAffineCompressed()
		f.round = FELDMAN_ROUND_REVEALED
		zkpokBytes := f.zkpok.Bytes()

		return &FeldmanReveal{
			Point:                 publicPointBytes,
			RandomCommitmentPoint: randCommitmentPointBytes,
			ZKPoK:                 zkpokBytes,
		}, nil
	}

	return nil, nil
}

func (f *Feldman) Recombine(id int, reveal *FeldmanReveal) (bool, error) {
	if f.round != FELDMAN_ROUND_REVEALED {
		return false, errors.Wrap(ErrWrongRound, "recombine")
	}

	counterpartyPoint, err := f.curve.NewGeneratorPoint().FromAffineCompressed(
		reveal.Point,
	)
	if err != nil {
		return false, errors.Wrap(err, "recombine")
	}

	if counterpartyPoint.Equal(f.curve.NewGeneratorPoint()) ||
		counterpartyPoint.Equal(f.generator) {
		return false, errors.Wrap(errors.New("counterparty sent generator"), "recombine")
	}

	counterpartyRandomCommitmentPoint, err := f.curve.NewGeneratorPoint().
		FromAffineCompressed(reveal.RandomCommitmentPoint)
	if err != nil {
		return false, errors.Wrap(err, "recombine")
	}

	if counterpartyRandomCommitmentPoint.Equal(f.curve.NewGeneratorPoint()) ||
		counterpartyRandomCommitmentPoint.Equal(f.generator) {
		return false, errors.Wrap(errors.New("counterparty sent generator"), "recombine")
	}

	counterpartyZKPoK, err := f.curve.NewScalar().SetBytes(reveal.ZKPoK)
	if err != nil {
		return false, errors.Wrap(err, "recombine")
	}

	counterpartyZKCommit := f.zkcommitsFromCounterparties[id]

	challenge := sha256.Sum256(append(
		append([]byte{}, reveal.Point...),
		reveal.RandomCommitmentPoint...,
	))
	challengeBig, err := f.curve.NewScalar().SetBigInt(
		new(big.Int).SetBytes(challenge[:]),
	)
	if err != nil {
		return false, errors.Wrap(err, "recombine")
	}

	proof := f.generator.Mul(counterpartyZKPoK)
	counterpartyRandomCommitmentPoint = counterpartyRandomCommitmentPoint.Add(
		counterpartyPoint.Mul(challengeBig),
	)

	if !proof.Equal(counterpartyRandomCommitmentPoint) {
		return false, errors.Wrap(
			errors.New(fmt.Sprintf("invalid proof from %d", id)),
			"recombine",
		)
	}

	verifier := sha256.Sum256(append(
		append([]byte{}, reveal.RandomCommitmentPoint...),
		reveal.ZKPoK...,
	))
	if !bytes.Equal(counterpartyZKCommit, verifier[:]) {
		return false, errors.Wrap(
			errors.New(fmt.Sprintf("%d changed zkpok after commit", id)),
			"recombine",
		)
	}

	f.pointsFromCounterparties[id] = counterpartyPoint

	if len(f.pointsFromCounterparties) == f.total-1 {
		f.pointsFromCounterparties[f.id] = f.point

		for i := 1; i <= f.total-f.threshold+1; i++ {
			var reconstructedSum curves.Point = nil

			for j := i; j < f.threshold+i; j++ {
				num := f.curve.Scalar.One()
				den := f.curve.Scalar.One()

				for k := i; k < f.threshold+i; k++ {
					if j != k {
						j := f.curve.NewScalar().New(j)
						k := f.curve.NewScalar().New(k)

						num = num.Mul(k)
						den = den.Mul(k.Sub(j))
					}
				}

				den, _ = den.Invert()
				reconstructedFragment := f.pointsFromCounterparties[j].Mul(num.Mul(den))

				if reconstructedSum == nil {
					reconstructedSum = reconstructedFragment
				} else {
					reconstructedSum = reconstructedSum.Add(reconstructedFragment)
				}
			}

			if f.publicKey.Equal(f.curve.NewGeneratorPoint()) ||
				f.publicKey.Equal(f.generator) {
				f.publicKey = reconstructedSum
			} else if !f.publicKey.Equal(reconstructedSum) {
				return false, errors.Wrap(
					errors.New("recombination mismatch"),
					"recombine",
				)
			}
		}
		f.round = FELDMAN_ROUND_RECONSTRUCTED
	}

	return f.round == FELDMAN_ROUND_RECONSTRUCTED, nil
}

func (f *Feldman) PublicKey() curves.Point {
	return f.publicKey
}

func (f *Feldman) PublicKeyBytes() []byte {
	return f.publicKey.ToAffineCompressed()
}

func ReverseScalarBytes(inBytes []byte, length int) []byte {
	outBytes := make([]byte, length)

	for i, j := 0, len(inBytes)-1; j >= 0; i, j = i+1, j-1 {
		outBytes[i] = inBytes[j]
	}

	return outBytes
}
