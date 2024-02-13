package application

import (
	"bytes"
	"fmt"

	"github.com/pkg/errors"
	"source.quilibrium.com/quilibrium/monorepo/nekryptology/pkg/core/curves"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
)

func (a *CeremonyApplication) applyTranscriptShare(
	share *protobufs.CeremonyTranscriptShare,
) error {
	if len(share.AdditiveG1Powers) != len(a.LatestTranscript.G1Powers)-1 {
		return errors.Wrap(errors.New("invalid g1s"), "apply transcript share")
	}
	if len(share.AdditiveG2Powers) != len(a.LatestTranscript.G2Powers)-1 {
		return errors.Wrap(errors.New("invalid g2s"), "apply transcript share")
	}
	if share.AdditiveG1_256Witness == nil ||
		share.AdditiveG1_256Witness.KeyValue == nil {
		return errors.Wrap(
			errors.New("invalid g1 witness"),
			"apply transcript share",
		)
	}
	if _, err := curves.BLS48581G1().Point.FromAffineCompressed(
		share.AdditiveG1_256Witness.KeyValue,
	); err != nil {
		return errors.Wrap(
			errors.Wrap(err, "invalid g1 witness"),
			"apply transcript share",
		)
	}
	if share.AdditiveG2_256Witness == nil ||
		share.AdditiveG2_256Witness.KeyValue == nil {
		return errors.Wrap(
			errors.New("invalid g2 witness"),
			"apply transcript share",
		)
	}

	for _, s := range a.TranscriptShares {
		if bytes.Equal(
			s.AdditiveG1Powers[0].KeyValue,
			share.AdditiveG1Powers[0].KeyValue,
		) {
			return nil
		}
	}

	matchFound := false

	for _, c := range a.FinalCommits {
		if bytes.Equal(
			share.ProverSignature.PublicKey.KeyValue,
			c.ProverSignature.PublicKey.KeyValue,
		) {
			matchFound = true
			break
		}
	}

	if !matchFound {
		return errors.Wrap(
			errors.New(
				fmt.Sprintf(
					"no corresponding commit in commit set (size %d)",
					len(a.FinalCommits),
				),
			),
			"apply transcript share",
		)
	}

	if err := share.VerifySignature(); err != nil {
		return errors.Wrap(err, "apply transcript share")
	}

	for i, g1 := range a.LatestTranscript.G1Powers {
		i := i
		g1 := g1
		if _, err := curves.BLS48581G1().Point.FromAffineCompressed(
			g1.KeyValue,
		); err != nil {
			return errors.Wrap(
				errors.Wrap(err, fmt.Sprintf("invalid g1 at position %d", i)),
				"apply transcript share",
			)
		}
	}

	for i, g2 := range a.LatestTranscript.G2Powers {
		i := i
		g2 := g2
		if _, err := curves.BLS48581G2().Point.FromAffineCompressed(
			g2.KeyValue,
		); err != nil {
			return errors.Wrap(
				errors.Wrap(err, fmt.Sprintf("invalid g2 at position %d", i)),
				"apply transcript share",
			)
		}
	}

	exists := false
	for _, s := range a.TranscriptShares {
		exists = bytes.Equal(
			s.ProverSignature.Signature,
			share.ProverSignature.Signature,
		)
		if exists {
			break
		}
	}

	if !exists {
		a.TranscriptShares = append(a.TranscriptShares, share)
	}

	return nil
}

func (a *CeremonyApplication) finalizeTranscript() error {
	a.UpdatedTranscript = &protobufs.CeremonyTranscript{
		G1Powers: make(
			[]*protobufs.BLS48581G1PublicKey,
			len(a.LatestTranscript.G1Powers),
		),
		G2Powers: make(
			[]*protobufs.BLS48581G2PublicKey,
			len(a.LatestTranscript.G2Powers),
		),
		RunningG1_256Witnesses: a.LatestTranscript.RunningG1_256Witnesses,
		RunningG2_256Powers:    a.LatestTranscript.RunningG2_256Powers,
	}

	a.UpdatedTranscript.G1Powers[0] = a.LatestTranscript.G1Powers[0]
	a.UpdatedTranscript.G2Powers[0] = a.LatestTranscript.G2Powers[0]

	for i := range a.UpdatedTranscript.G1Powers[1:] {
		g1, err := curves.BLS48581G1().Point.FromAffineCompressed(
			a.TranscriptShares[0].AdditiveG1Powers[i].KeyValue,
		)
		if err != nil {
			return errors.Wrap(err, "finalize transcript")
		}

		if len(a.TranscriptShares) > 1 {
			for _, share := range a.TranscriptShares[1:] {
				ag1, err := curves.BLS48581G1().Point.FromAffineCompressed(
					share.AdditiveG1Powers[i].KeyValue,
				)
				if err != nil {
					return errors.Wrap(err, "finalize transcript")
				}

				g1 = g1.Add(ag1)
			}
		}

		if !g1.IsOnCurve() || g1.IsIdentity() {
			return errors.Wrap(
				errors.New("invalid g1 power"),
				"finalize transcript",
			)
		}

		a.UpdatedTranscript.G1Powers[i+1] = &protobufs.BLS48581G1PublicKey{
			KeyValue: g1.ToAffineCompressed(),
		}
	}

	for i := range a.UpdatedTranscript.G2Powers[1:] {
		g2, err := curves.BLS48581G2().Point.FromAffineCompressed(
			a.TranscriptShares[0].AdditiveG2Powers[i].KeyValue,
		)
		if err != nil {
			return errors.Wrap(err, "finalize transcript")
		}

		if len(a.TranscriptShares) > 1 {
			for _, share := range a.TranscriptShares[1:] {
				ag2, err := curves.BLS48581G2().Point.FromAffineCompressed(
					share.AdditiveG2Powers[i].KeyValue,
				)
				if err != nil {
					return errors.Wrap(err, "finalize transcript")
				}

				g2 = g2.Add(ag2)
			}
		}

		if !g2.IsOnCurve() || g2.IsIdentity() {
			return errors.Wrap(
				errors.New("invalid g2 power"),
				"finalize transcript",
			)
		}

		a.UpdatedTranscript.G2Powers[i+1] = &protobufs.BLS48581G2PublicKey{
			KeyValue: g2.ToAffineCompressed(),
		}
	}

	g1Witness, err := curves.BLS48581G1().Point.FromAffineCompressed(
		a.TranscriptShares[0].AdditiveG1_256Witness.KeyValue,
	)
	if err != nil {
		return errors.Wrap(err, "finalize transcript")
	}

	if len(a.TranscriptShares) > 1 {
		for _, share := range a.TranscriptShares[1:] {
			ag1, err := curves.BLS48581G1().Point.FromAffineCompressed(
				share.AdditiveG1_256Witness.KeyValue,
			)
			if err != nil {
				return errors.Wrap(err, "finalize transcript")
			}

			g1Witness = g1Witness.Add(ag1)
		}
	}

	if !g1Witness.IsOnCurve() || g1Witness.IsIdentity() {
		return errors.Wrap(
			errors.New("invalid witness"),
			"finalize transcript",
		)
	}

	a.UpdatedTranscript.RunningG1_256Witnesses = append(
		a.UpdatedTranscript.RunningG1_256Witnesses,
		&protobufs.BLS48581G1PublicKey{
			KeyValue: g1Witness.ToAffineCompressed(),
		},
	)

	a.UpdatedTranscript.RunningG2_256Powers = append(
		a.UpdatedTranscript.RunningG2_256Powers,
		a.UpdatedTranscript.G2Powers[len(a.UpdatedTranscript.G2Powers)-1],
	)

	return nil
}
