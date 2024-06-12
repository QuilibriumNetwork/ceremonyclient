package crypto

import (
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"golang.org/x/crypto/sha3"
	"source.quilibrium.com/quilibrium/monorepo/nekryptology/pkg/core/curves"
	"source.quilibrium.com/quilibrium/monorepo/node/crypto/kzg"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
)

type KZGInclusionProver struct {
	prover *kzg.KZGProver
	logger *zap.Logger
}

func NewKZGInclusionProver(logger *zap.Logger) *KZGInclusionProver {
	return &KZGInclusionProver{
		prover: kzg.DefaultKZGProver(),
		logger: logger,
	}
}

// Commit implements InclusionProver.
func (k *KZGInclusionProver) Commit(
	data []byte,
	typeUrl string,
) (*InclusionCommitment, error) {
	if typeUrl == protobufs.IntrinsicExecutionOutputType {
		digest := sha3.NewShake256()
		_, err := digest.Write(data)
		if err != nil {
			k.logger.Error(
				"error converting key bundle to polynomial",
				zap.Error(err),
			)
			return nil, errors.Wrap(err, "prove aggregate")
		}

		expand := make([]byte, 1024)
		_, err = digest.Read(expand)
		if err != nil {
			k.logger.Error(
				"error converting key bundle to polynomial",
				zap.Error(err),
			)
			return nil, errors.Wrap(err, "prove aggregate")
		}

		poly, err := k.prover.BytesToPolynomial(expand)
		if err != nil {
			return nil, errors.Wrap(err, "commit")
		}

		k.logger.Debug("proving execution output for inclusion")
		polys, err := kzg.FFT(
			poly,
			*curves.BLS48581(
				curves.BLS48581G1().NewGeneratorPoint(),
			),
			16,
			false,
		)
		if err != nil {
			return nil, errors.Wrap(err, "prove")
		}

		k.logger.Debug("converted execution output chunk to evaluation form")

		k.logger.Debug("creating kzg commitment")
		points, err := k.prover.Commit(polys)
		if err != nil {
			return nil, errors.Wrap(err, "prove")
		}

		return &InclusionCommitment{
			TypeUrl:    typeUrl,
			Data:       data,
			Commitment: points.ToAffineCompressed(),
		}, nil
	}

	poly, err := k.prover.BytesToPolynomial(data)
	if err != nil {
		return nil, errors.Wrap(err, "commit")
	}

	points, err := k.prover.Commit(poly)
	if err != nil {
		return nil, errors.Wrap(err, "commit")
	}

	return &InclusionCommitment{
		TypeUrl:    typeUrl,
		Data:       data,
		Commitment: points.ToAffineCompressed(),
	}, nil
}

// ProveAggregate implements InclusionProver.
func (k *KZGInclusionProver) ProveAggregate(
	commits []*InclusionCommitment,
) (*InclusionAggregateProof, error) {
	polys := [][]curves.PairingScalar{}
	commitPoints := []curves.PairingPoint{}
	for _, commit := range commits {
		switch commit.TypeUrl {
		case protobufs.IntrinsicExecutionOutputType:
			k.logger.Debug("confirming inclusion in aggregate")
			digest := sha3.NewShake256()
			_, err := digest.Write(commit.Data)
			if err != nil {
				k.logger.Error(
					"error converting key bundle to polynomial",
					zap.Error(err),
				)
				return nil, errors.Wrap(err, "prove aggregate")
			}

			expand := make([]byte, 1024)
			_, err = digest.Read(expand)
			if err != nil {
				k.logger.Error(
					"error converting key bundle to polynomial",
					zap.Error(err),
				)
				return nil, errors.Wrap(err, "prove aggregate")
			}

			poly, err := k.prover.BytesToPolynomial(expand)
			if err != nil {
				k.logger.Error(
					"error converting key bundle to polynomial",
					zap.Error(err),
				)
				return nil, errors.Wrap(err, "prove aggregate")
			}

			evalPoly, err := kzg.FFT(
				poly,
				*curves.BLS48581(
					curves.BLS48581G1().NewGeneratorPoint(),
				),
				16,
				false,
			)
			if err != nil {
				k.logger.Error(
					"error performing fast fourier transform on key bundle",
					zap.Error(err),
				)
				return nil, errors.Wrap(err, "prove aggregate")
			}
			k.logger.Debug(
				"created fft of polynomial",
				zap.Int("poly_size", len(evalPoly)),
			)

			polys = append(polys, evalPoly)

			c, err := curves.BLS48581G1().NewGeneratorPoint().FromAffineCompressed(
				commit.Commitment,
			)
			if err != nil {
				return nil, errors.Wrap(err, "prove aggregate")
			}
			commitPoints = append(commitPoints, c.(curves.PairingPoint))
		default:
			k.logger.Debug("confirming inclusion in aggregate")
			poly, err := k.prover.BytesToPolynomial(commit.Data)
			if err != nil {
				k.logger.Error(
					"error converting key bundle to polynomial",
					zap.Error(err),
				)
				return nil, errors.Wrap(err, "prove aggregate")
			}

			for i := 0; i < 1024-len(poly); i++ {
				poly = append(
					poly,
					curves.BLS48581G1().Scalar.Zero().(curves.PairingScalar),
				)
			}

			evalPoly, err := kzg.FFT(
				poly,
				*curves.BLS48581(
					curves.BLS48581G1().NewGeneratorPoint(),
				),
				1024,
				false,
			)
			if err != nil {
				k.logger.Error(
					"error performing fast fourier transform on key bundle",
					zap.Error(err),
				)
				return nil, errors.Wrap(err, "prove aggregate")
			}
			k.logger.Debug(
				"created fft of polynomial",
				zap.Int("poly_size", len(evalPoly)),
			)

			polys = append(polys, evalPoly)

			c, err := curves.BLS48581G1().NewGeneratorPoint().FromAffineCompressed(
				commit.Commitment,
			)
			if err != nil {
				k.logger.Error("could not verify clock frame", zap.Error(err))
				return nil, errors.Wrap(err, "prove aggregate")
			}
			commitPoints = append(commitPoints, c.(curves.PairingPoint))
		}
	}

	proof, commitment, err := k.prover.ProveAggregate(
		polys,
		commitPoints,
	)
	if err != nil {
		return nil, errors.Wrap(err, "prove aggregate")
	}

	if proof.IsIdentity() {
		return nil, errors.Wrap(errors.New("invalid proof"), "prove aggregate")
	}

	return &InclusionAggregateProof{
		InclusionCommitments: commits,
		AggregateCommitment:  commitment.ToAffineCompressed(),
		Proof:                proof.ToAffineCompressed(),
	}, nil
}

// VerifyAggregate implements InclusionProver.
func (k *KZGInclusionProver) VerifyAggregate(
	proof *InclusionAggregateProof,
) (bool, error) {
	polys := [][]curves.PairingScalar{}
	commitPoints := []curves.PairingPoint{}
	for _, commit := range proof.InclusionCommitments {
		poly, err := k.prover.BytesToPolynomial(commit.Data)
		if err != nil {
			return false, errors.Wrap(err, "verify aggregate")
		}

		polys = append(polys, poly)

		point, err := curves.BLS48581G1().Point.FromAffineCompressed(
			commit.Commitment,
		)
		if err != nil {
			return false, errors.Wrap(err, "verify aggregate")
		}

		commitPoints = append(commitPoints, point.(curves.PairingPoint))
	}

	aggregate, err := curves.BLS48581G1().Point.FromAffineCompressed(
		proof.AggregateCommitment,
	)
	if err != nil {
		return false, errors.Wrap(err, "verify aggregate")
	}

	proofPoint, err := curves.BLS48581G1().Point.FromAffineCompressed(
		proof.Proof,
	)
	if err != nil {
		return false, errors.Wrap(err, "verify aggregate")
	}

	verify, err := k.prover.VerifyAggregateProof(
		polys,
		commitPoints,
		aggregate.(curves.PairingPoint),
		proofPoint.(curves.PairingPoint),
	)
	return verify, errors.Wrap(err, "verify aggregate")
}

func (k *KZGInclusionProver) VerifyFrame(
	frame *protobufs.ClockFrame,
) error {
	aggregateCommitments := []curves.PairingPoint{}
	for i := 0; i < (len(frame.Input)-516)/74; i++ {
		c, err := curves.BLS48581G1().NewGeneratorPoint().FromAffineCompressed(
			frame.Input[516+(i*74) : 516+(i*74)+74],
		)
		if err != nil {
			k.logger.Error("could not verify clock frame", zap.Error(err))
			return errors.Wrap(err, "verify frame")
		}
		aggregateCommitments = append(aggregateCommitments, c.(curves.PairingPoint))
	}

	if len(aggregateCommitments) != len(frame.AggregateProofs) {
		k.logger.Error(
			"commit length mismatched proof for frame",
			zap.Int("commit_length", len(aggregateCommitments)),
			zap.Int("proof_length", len(frame.AggregateProofs)),
		)
		return errors.Wrap(
			errors.New("commit length mismatched proof for frame"),
			"verify frame",
		)
	}

	for i, proof := range frame.AggregateProofs {
		aggregatePoly := [][]curves.PairingScalar{}
		commitments := []curves.PairingPoint{}

		for _, commit := range proof.GetInclusionCommitments() {
			switch commit.TypeUrl {
			case protobufs.IntrinsicExecutionOutputType:
				k.logger.Debug("confirming inclusion in aggregate")
				digest := sha3.NewShake256()
				_, err := digest.Write(commit.Data)
				if err != nil {
					k.logger.Error(
						"error converting key bundle to polynomial",
						zap.Error(err),
					)
					return errors.Wrap(err, "verify frame")
				}

				expand := make([]byte, 1024)
				_, err = digest.Read(expand)
				if err != nil {
					k.logger.Error(
						"error converting key bundle to polynomial",
						zap.Error(err),
					)
					return errors.Wrap(err, "verify frame")
				}

				poly, err := k.prover.BytesToPolynomial(expand)
				if err != nil {
					k.logger.Error(
						"error converting key bundle to polynomial",
						zap.Error(err),
					)
					return errors.Wrap(err, "verify frame")
				}

				evalPoly, err := kzg.FFT(
					poly,
					*curves.BLS48581(
						curves.BLS48581G1().NewGeneratorPoint(),
					),
					16,
					false,
				)
				if err != nil {
					k.logger.Error(
						"error performing fast fourier transform on key bundle",
						zap.Error(err),
					)
					return errors.Wrap(err, "verify frame")
				}
				k.logger.Debug(
					"created fft of polynomial",
					zap.Int("poly_size", len(evalPoly)),
				)

				aggregatePoly = append(aggregatePoly, evalPoly)

				c, err := curves.BLS48581G1().NewGeneratorPoint().FromAffineCompressed(
					commit.Commitment,
				)
				if err != nil {
					k.logger.Error("could not verify clock frame", zap.Error(err))
					return errors.Wrap(err, "verify frame")
				}
				commitments = append(commitments, c.(curves.PairingPoint))
			default:
				k.logger.Debug("confirming inclusion in aggregate")
				poly, err := k.prover.BytesToPolynomial(commit.Data)
				if err != nil {
					k.logger.Error(
						"error converting key bundle to polynomial",
						zap.Error(err),
					)
					return errors.Wrap(err, "verify frame")
				}

				for i := 0; i < 1024-len(poly); i++ {
					poly = append(
						poly,
						curves.BLS48581G1().Scalar.Zero().(curves.PairingScalar),
					)
				}

				evalPoly, err := kzg.FFT(
					poly,
					*curves.BLS48581(
						curves.BLS48581G1().NewGeneratorPoint(),
					),
					1024,
					false,
				)
				if err != nil {
					k.logger.Error(
						"error performing fast fourier transform on key bundle",
						zap.Error(err),
					)
					return errors.Wrap(err, "verify frame")
				}
				k.logger.Debug(
					"created fft of polynomial",
					zap.Int("poly_size", len(evalPoly)),
				)

				aggregatePoly = append(aggregatePoly, evalPoly)

				c, err := curves.BLS48581G1().NewGeneratorPoint().FromAffineCompressed(
					commit.Commitment,
				)
				if err != nil {
					k.logger.Error("could not verify clock frame", zap.Error(err))
					return errors.Wrap(err, "verify frame")
				}
				commitments = append(commitments, c.(curves.PairingPoint))
			}
		}

		p, err := curves.BLS48581G1().Point.FromAffineCompressed(
			proof.Proof,
		)
		if err != nil {
			k.logger.Error("could not verify clock frame", zap.Error(err))
			return errors.Wrap(err, "verify frame")
		}

		result, err := k.prover.VerifyAggregateProof(
			aggregatePoly,
			commitments,
			aggregateCommitments[i],
			p.(curves.PairingPoint),
		)
		if err != nil {
			k.logger.Error(
				"could not verify clock frame",
				zap.Error(err),
			)
			return errors.Wrap(err, "verify frame")
		}

		if !result {
			k.logger.Error("could not verify clock frame", zap.Error(err))
			return errors.Wrap(
				errors.New("invalid proof"),
				"verify frame",
			)
		}
	}

	return nil
}

func (k *KZGInclusionProver) CommitRaw(
	data []byte,
	polySize uint64,
) ([]byte, error) {
	poly, err := k.prover.BytesToPolynomial(data)
	if err != nil {
		return nil, errors.Wrap(err, "commit raw")
	}
	for i := len(poly); i < int(polySize); i++ {
		poly = append(poly, curves.BLS48581G1().NewScalar().(curves.PairingScalar))
	}

	commit, err := k.prover.Commit(poly)
	if err != nil {
		return nil, errors.Wrap(err, "commit raw")
	}

	return commit.ToAffineCompressed(), nil
}

func (k *KZGInclusionProver) ProveRaw(
	data []byte,
	index int,
	polySize uint64,
) ([]byte, error) {
	poly, err := k.prover.BytesToPolynomial(data)
	if err != nil {
		return nil, errors.Wrap(err, "prove raw")
	}
	for i := len(poly); i < int(polySize); i++ {
		poly = append(poly, curves.BLS48581G1().NewScalar().(curves.PairingScalar))
	}

	z := kzg.RootsOfUnityBLS48581[polySize][index]

	evalPoly, err := kzg.FFT(
		poly,
		*curves.BLS48581(
			curves.BLS48581G1().NewGeneratorPoint(),
		),
		polySize,
		true,
	)
	if err != nil {
		return nil, errors.Wrap(err, "prove raw")
	}

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

	proof, err := k.prover.PointLinearCombination(
		kzg.CeremonyBLS48581G1[:polySize-1],
		out,
	)

	if err != nil {
		return nil, errors.Wrap(err, "prove raw")
	}

	return proof.ToAffineCompressed(), nil
}

func (k *KZGInclusionProver) VerifyRaw(
	data []byte,
	commit []byte,
	index int,
	proof []byte,
	polySize uint64,
) (bool, error) {
	z := kzg.RootsOfUnityBLS48581[polySize][index]

	y, err := curves.BLS48581G1().NewScalar().SetBytes(data)
	if err != nil {
		return false, errors.Wrap(err, "verify raw")
	}

	c, err := curves.BLS48581G1().Point.FromAffineCompressed(commit)
	if err != nil {
		return false, errors.Wrap(err, "verify raw")
	}

	p, err := curves.BLS48581G1().Point.FromAffineCompressed(proof)
	if err != nil {
		return false, errors.Wrap(err, "verify raw")
	}

	return k.prover.Verify(
		c.(curves.PairingPoint),
		z,
		y.(curves.PairingScalar),
		p.(curves.PairingPoint),
	), nil
}

var _ InclusionProver = (*KZGInclusionProver)(nil)
