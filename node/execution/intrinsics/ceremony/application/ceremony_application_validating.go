package application

import (
	"bytes"
	"crypto/rand"

	"github.com/pkg/errors"
	"source.quilibrium.com/quilibrium/monorepo/nekryptology/pkg/core/curves"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
)

func (a *CeremonyApplication) applyTranscript(
	transcript *protobufs.CeremonyTranscript,
) error {
	if a.UpdatedTranscript == nil {
		return errors.Wrap(errors.New("invalid transcript"), "apply transcript")
	}
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

	g1s := make([]curves.Point, len(a.UpdatedTranscript.G1Powers))

	for i := range a.UpdatedTranscript.G1Powers {
		i := i
		if !bytes.Equal(
			a.UpdatedTranscript.G1Powers[i].KeyValue,
			transcript.G1Powers[i].KeyValue,
		) {
			return errors.Wrap(errors.New("invalid g1s"), "apply transcript")
		}

		g1 := &curves.PointBls48581G1{}
		x, err := g1.FromAffineCompressed(
			a.UpdatedTranscript.G1Powers[i].KeyValue,
		)
		if err != nil {
			return errors.Wrap(err, "apply transcript")
		}

		g1s[i] = x
	}

	g2s := make([]curves.Point, len(a.UpdatedTranscript.G2Powers))
	for i := range a.UpdatedTranscript.G2Powers {
		i := i
		if !bytes.Equal(
			a.UpdatedTranscript.G2Powers[i].KeyValue,
			transcript.G2Powers[i].KeyValue,
		) {
			return errors.Wrap(errors.New("invalid g2s"), "apply transcript")
		}

		g2 := &curves.PointBls48581G2{}
		x, err := g2.FromAffineCompressed(
			a.UpdatedTranscript.G2Powers[i].KeyValue,
		)
		if err != nil {
			return errors.Wrap(err, "apply transcript")
		}

		g2s[i] = x
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

	mpg2 := curves.BLS48581G2().Point.Generator().(curves.PairingPoint)
	mpg2n := g2s[1].Neg().(curves.PairingPoint)

	mpg1 := curves.BLS48581G1().Point.Generator().(curves.PairingPoint)
	mpg1n := g1s[1].Neg().(curves.PairingPoint)

	randoms := []curves.Scalar{}
	sum := curves.BLS48581G1().Scalar.Zero()

	for i := 0; i < len(g1s)-1; i++ {
		randoms = append(randoms, curves.BLS48581G1().Scalar.Random(rand.Reader))
		sum = sum.Add(randoms[i])
	}

	g1CheckR := g1s[0].SumOfProducts(g1s[1:], randoms)
	g1CheckL := g1s[0].SumOfProducts(g1s[:len(g1s)-1], randoms)

	if !mpg2.MultiPairing(
		g1CheckL.(curves.PairingPoint),
		mpg2n.Mul(sum).(curves.PairingPoint),
		g1CheckR.(curves.PairingPoint),
		mpg2.Mul(sum).(curves.PairingPoint),
	).IsOne() {
		return errors.Wrap(
			errors.New("pairing check failed for g1s"),
			"apply transcript",
		)
	}

	var g2CheckL, g2CheckR curves.Point
	g2Sum := curves.BLS48581G1().Scalar.Zero()
	for i := 0; i < len(g2s)-1; i++ {
		g2Sum = g2Sum.Add(randoms[i])
		if g2CheckL == nil {
			g2CheckL = g2s[0].Mul(randoms[0])
			g2CheckR = g2s[1].Mul(randoms[0])
		} else {
			g2CheckL = g2CheckL.Add(g2s[i].Mul(randoms[i]))
			g2CheckR = g2CheckR.Add(g2s[i+1].Mul(randoms[i]))
		}
	}

	if !mpg2.MultiPairing(
		mpg1n.Mul(g2Sum).(curves.PairingPoint),
		g2CheckL.(curves.PairingPoint),
		mpg1.Mul(g2Sum).(curves.PairingPoint),
		g2CheckR.(curves.PairingPoint),
	).IsOne() {
		return errors.Wrap(
			errors.New("pairing check failed for g2s"),
			"apply transcript",
		)
	}

	mp3 := make([]curves.PairingPoint, (len(g2Powers)-1)*4)
	for i := 0; i < len(g2Powers)-1; i++ {
		i := i
		mp3[i*4+0] = g1Witnesses[i+1].Neg().(curves.PairingPoint)
		mp3[i*4+1] = g2Powers[i]
		mp3[i*4+2] = mpg1
		mp3[i*4+3] = g2Powers[i+1]
	}

	l := mp3[0].MultiPairing(mp3...)
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
