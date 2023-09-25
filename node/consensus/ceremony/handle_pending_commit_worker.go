package ceremony

import (
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/protobuf/types/known/anypb"
	"source.quilibrium.com/quilibrium/monorepo/nekryptology/pkg/core/curves"
	"source.quilibrium.com/quilibrium/monorepo/node/crypto"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
)

func (e *CeremonyDataClockConsensusEngine) handlePendingCommits(
	workerId int64,
) {
	for {
		msg := <-e.pendingCommits
		switch msg.TypeUrl {
		case protobufs.KeyBundleAnnouncementType:
			if err := e.includeKeyBundle(msg); err != nil {
				e.logger.Error(
					"failed to include key bundle",
					zap.Error(errors.Wrap(err, "handle pending commits")),
					zap.Int64("worker_id", workerId),
				)
			}
		}
	}
}

func (e *CeremonyDataClockConsensusEngine) includeKeyBundle(
	any *anypb.Any,
) error {
	poly, err := e.prover.BytesToPolynomial(any.Value)
	if err != nil {
		e.logger.Error(
			"error converting key bundle to polynomial",
			zap.Error(err),
		)
		return errors.Wrap(err, "include key bundle")
	}

	for i := 0; i < 128-len(poly); i++ {
		poly = append(
			poly,
			curves.BLS48581G1().Scalar.Zero().(curves.PairingScalar),
		)
	}

	evalPoly, err := crypto.FFT(
		poly,
		*curves.BLS48581(
			curves.BLS48581G1().NewGeneratorPoint(),
		),
		128,
		false,
	)
	if err != nil {
		e.logger.Error(
			"error performing fast fourier transform on key bundle",
			zap.Error(err),
		)
		return errors.Wrap(err, "include key bundle")
	}

	commitment, err := e.prover.Commit(evalPoly)
	if err != nil {
		e.logger.Error(
			"error creating kzg commitment",
			zap.Error(err),
		)
		return errors.Wrap(err, "include key bundle")
	}

	e.stagedKeyCommitsMx.Lock()
	e.stagedKeyCommits[commitment] = &protobufs.InclusionCommitment{
		Filter:     e.filter,
		TypeUrl:    any.TypeUrl,
		Data:       any.Value,
		Commitment: commitment.ToAffineCompressed(),
	}
	e.stagedKeyPolynomials[commitment] = evalPoly
	e.stagedKeyCommitsMx.Unlock()

	return nil
}
