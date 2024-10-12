package crypto

import (
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"golang.org/x/crypto/sha3"
	rbls48581 "source.quilibrium.com/quilibrium/monorepo/bls48581"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
)

type KZGInclusionProver struct {
	logger *zap.Logger
}

func NewKZGInclusionProver(logger *zap.Logger) *KZGInclusionProver {
	return &KZGInclusionProver{
		logger: logger,
	}
}

func (k *KZGInclusionProver) VerifyFrame(
	frame *protobufs.ClockFrame,
) error {
	aggregateCommitments := [][]byte{}
	for i := 0; i < (len(frame.Input)-516)/74; i++ {
		c := frame.Input[516+(i*74) : 516+(i*74)+74]
		aggregateCommitments = append(aggregateCommitments, c)
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

	for _, proof := range frame.AggregateProofs {
		commitments := [][]byte{}
		expand := []byte{}

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

				expand = make([]byte, 1024)
				_, err = digest.Read(expand)
				if err != nil {
					k.logger.Error(
						"error converting key bundle to polynomial",
						zap.Error(err),
					)
					return errors.Wrap(err, "verify frame")
				}

				commitments = append(commitments, commit.Commitment)
			default:
				return errors.Wrap(errors.New("unsupported"), "verify frame")
			}
		}

		if len(commitments) != 1 {
			return errors.Wrap(errors.New("unsupported"), "verify frame")
		}

		result := rbls48581.VerifyRaw(
			expand,
			commitments[0],
			uint64(expand[0]%16),
			proof.Proof,
			16,
		)
		if !result {
			k.logger.Error(
				"could not verify clock frame",
				zap.Error(errors.New("invalid proof")),
			)
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
	return rbls48581.CommitRaw(data, polySize), nil
}

func (k *KZGInclusionProver) ProveRaw(
	data []byte,
	index int,
	polySize uint64,
) ([]byte, error) {
	return rbls48581.ProveRaw(data, uint64(index), polySize), nil
}

func (k *KZGInclusionProver) VerifyRaw(
	data []byte,
	commit []byte,
	index int,
	proof []byte,
	polySize uint64,
) (bool, error) {
	return rbls48581.VerifyRaw(data, commit, uint64(index), proof, polySize), nil
}

var _ InclusionProver = (*KZGInclusionProver)(nil)
