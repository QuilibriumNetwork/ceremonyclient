package application

import (
	"bytes"

	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"
	"source.quilibrium.com/quilibrium/monorepo/nekryptology/pkg/core/curves"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
)

func (a *CeremonyApplication) applyTranscript(
	transcript *protobufs.CeremonyTranscript,
) error {
	if len(a.UpdatedTranscript.G1Powers) != len(transcript.G1Powers) {
		return errors.Wrap(errors.New("invalid g1s"), "apply transcript")
	}
	if len(a.UpdatedTranscript.G2Powers) != len(transcript.G2Powers) {
		return errors.Wrap(errors.New("invalid g2s"), "apply transcript")
	}
	if len(a.UpdatedTranscript.RunningG1_256Witnesses) !=
		len(transcript.RunningG1_256Witnesses) ||
		len(transcript.RunningG1_256Witnesses) !=
			len(a.LatestTranscript.RunningG1_256Witnesses)+1 {
		return errors.Wrap(
			errors.New("invalid witnesses"),
			"apply transcript",
		)
	}
	if len(a.UpdatedTranscript.RunningG2_256Powers) !=
		len(transcript.RunningG2_256Powers) ||
		len(transcript.RunningG2_256Powers) !=
			len(a.LatestTranscript.RunningG2_256Powers)+1 {
		return errors.Wrap(
			errors.New("invalid g2^256 powers"),
			"apply transcript",
		)
	}

	g1s := make([]*curves.PointBls48581G1, len(a.UpdatedTranscript.G1Powers))
	eg := errgroup.Group{}
	eg.SetLimit(100)

	for i := range a.UpdatedTranscript.G1Powers {
		i := i
		eg.Go(func() error {
			if !bytes.Equal(
				a.UpdatedTranscript.G1Powers[i].KeyValue,
				transcript.G1Powers[i].KeyValue,
			) {
				return errors.Wrap(errors.New("invalid g1s"), "apply transcript")
			}

			g1 := &curves.PointBls48581G1{}
			x, err := g1.FromAffineCompressed(a.UpdatedTranscript.G1Powers[i].KeyValue)
			if err != nil {
				return errors.Wrap(err, "apply transcript")
			}
			g1, _ = x.(*curves.PointBls48581G1)

			g1s[i] = g1

			return nil
		})
	}

	g2s := make([]*curves.PointBls48581G2, len(a.UpdatedTranscript.G2Powers))
	for i := range a.UpdatedTranscript.G2Powers {
		i := i
		eg.Go(func() error {
			if !bytes.Equal(
				a.UpdatedTranscript.G2Powers[i].KeyValue,
				transcript.G2Powers[i].KeyValue,
			) {
				return errors.Wrap(errors.New("invalid g2s"), "apply transcript")
			}

			g2 := &curves.PointBls48581G2{}
			x, err := g2.FromAffineCompressed(a.UpdatedTranscript.G2Powers[i].KeyValue)
			if err != nil {
				return errors.Wrap(err, "apply transcript")
			}
			g2, _ = x.(*curves.PointBls48581G2)

			g2s[i] = g2

			return nil
		})
	}

	if err := eg.Wait(); err != nil {
		return err
	}

	g1Witnesses := []*curves.PointBls48581G1{}
	for i := range a.UpdatedTranscript.RunningG1_256Witnesses {
		if !bytes.Equal(
			a.UpdatedTranscript.RunningG1_256Witnesses[i].KeyValue,
			transcript.RunningG1_256Witnesses[i].KeyValue,
		) {
			return errors.Wrap(errors.New("invalid g1 witnesses"), "apply transcript")
		}

		g1w := &curves.PointBls48581G1{}
		w, err := g1w.FromAffineCompressed(
			a.UpdatedTranscript.RunningG1_256Witnesses[i].KeyValue,
		)
		if err != nil {
			return errors.Wrap(err, "apply transcript")
		}
		g1w, _ = w.(*curves.PointBls48581G1)

		g1Witnesses = append(g1Witnesses, g1w)
	}

	g2Powers := []*curves.PointBls48581G2{}
	for i := range a.UpdatedTranscript.RunningG2_256Powers {
		if !bytes.Equal(
			a.UpdatedTranscript.RunningG2_256Powers[i].KeyValue,
			transcript.RunningG2_256Powers[i].KeyValue,
		) {
			return errors.Wrap(
				errors.New("invalid g2^256 powers"),
				"apply transcript",
			)
		}

		g2w := &curves.PointBls48581G2{}
		w, err := g2w.FromAffineCompressed(
			a.UpdatedTranscript.RunningG2_256Powers[i].KeyValue,
		)
		if err != nil {
			return errors.Wrap(err, "apply transcript")
		}
		g2w, _ = w.(*curves.PointBls48581G2)

		g2Powers = append(g2Powers, g2w)
	}

	if !g2Powers[len(g2Powers)-1].Equal(g2s[len(g2s)-1]) {
		return errors.Wrap(
			errors.New("invalid running g2^256 power"),
			"apply transcript",
		)
	}

	for i := 0; i < len(a.LatestTranscript.RunningG1_256Witnesses); i++ {
		if !bytes.Equal(
			a.LatestTranscript.RunningG1_256Witnesses[i].KeyValue,
			a.UpdatedTranscript.RunningG1_256Witnesses[i].KeyValue,
		) {
			return errors.Wrap(
				errors.New("running witness mismatch"),
				"apply transcript",
			)
		}
	}

	for i := 0; i < len(a.LatestTranscript.RunningG2_256Powers); i++ {
		if !bytes.Equal(
			a.LatestTranscript.RunningG2_256Powers[i].KeyValue,
			a.UpdatedTranscript.RunningG2_256Powers[i].KeyValue,
		) {
			return errors.Wrap(
				errors.New("running g2^256 power mismatch"),
				"apply transcript",
			)
		}
	}

	mp := []curves.PairingPoint{}
	mpg2 := curves.BLS48581G2().Point.Generator().(curves.PairingPoint)
	mpg2n := g2s[1].Neg().(curves.PairingPoint)

	for i := 0; i < len(g1s)-1; i++ {
		mp = append(mp, g1s[i])
		mp = append(mp, mpg2n)
		mp = append(mp, g1s[i+1])
		mp = append(mp, mpg2)
	}

	mp2 := []curves.PairingPoint{}
	mpg1 := curves.BLS48581G1().Point.Generator().(curves.PairingPoint)
	mpg1n := g1s[1].Neg().(curves.PairingPoint)
	for i := 0; i < len(g2s)-1; i++ {
		mp2 = append(mp2, mpg1n)
		mp2 = append(mp2, g2s[i])
		mp2 = append(mp2, mpg1)
		mp2 = append(mp2, g2s[i+1])
	}

	l := g1s[0].MultiPairing(mp...)
	if !l.IsOne() {
		return errors.Wrap(
			errors.New("pairing check failed for g1s"),
			"apply transcript",
		)
	}

	l = g1s[0].MultiPairing(mp2...)
	if !l.IsOne() {
		return errors.Wrap(
			errors.New("pairing check failed for g2s"),
			"apply transcript",
		)
	}

	mp3 := []curves.PairingPoint{}
	for i := 0; i < len(g2Powers)-1; i++ {
		mp3 = append(mp3, g1Witnesses[i+1].Neg().(curves.PairingPoint))
		mp3 = append(mp3, g2Powers[i])
		mp3 = append(mp3, mpg1)
		mp3 = append(mp3, g2Powers[i+1])
	}

	l = g1s[0].MultiPairing(mp3...)
	if !l.IsOne() {
		return errors.Wrap(
			errors.New("pairing check failed for witnesses"),
			"apply transcript",
		)
	}

	a.LatestTranscript = a.UpdatedTranscript
	a.UpdatedTranscript = nil

	return nil
}
