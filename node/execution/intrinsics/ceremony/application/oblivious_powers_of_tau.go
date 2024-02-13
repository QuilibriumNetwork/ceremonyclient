package application

import (
	"bytes"

	"github.com/pkg/errors"
	"golang.org/x/crypto/sha3"
	"golang.org/x/sync/errgroup"
	"source.quilibrium.com/quilibrium/monorepo/nekryptology/pkg/core/curves"
)

func ProcessRound(
	i []byte,
	idkKey curves.Scalar,
	round int,
	peers [][]byte,
	peerIdks []curves.Point,
	secrets []curves.Scalar,
	curve *curves.Curve,
	send func(int, []byte, []byte) error,
	recv func(int, []byte) ([]byte, error),
	seed []byte,
) ([]curves.Scalar, error) {
	roundPeers, roundIdks, isReceiver := GetPairings(i, round, peers, peerIdks)
	if roundPeers == nil {
		return nil, nil
	}

	var participants []Iterator
	if isReceiver {
		for _, roundIdk := range roundIdks {
			hashKeySeed := sha3.Sum256(
				append(
					roundIdk.Mul(idkKey).ToAffineCompressed(),
					seed...,
				),
			)
			participant := NewMultiplyReceiver(secrets, curve, hashKeySeed)
			participants = append(participants, participant)

			if err := participant.Init(); err != nil {
				return nil, errors.Wrap(err, "process round")
			}
		}
	} else {
		for _, roundIdk := range roundIdks {
			hashKeySeed := sha3.Sum256(
				append(
					roundIdk.Mul(idkKey).ToAffineCompressed(),
					seed...,
				),
			)
			participant := NewMultiplySender(secrets, curve, hashKeySeed)
			participants = append(participants, participant)

			if err := participant.Init(); err != nil {
				return nil, errors.Wrap(err, "process round")
			}
		}
	}

	eg := errgroup.Group{}
	eg.SetLimit(len(participants))

	for j := range participants {
		j := j
		eg.Go(func() error {
			var msg []byte
			seq := 0
			for !participants[j].IsDone() {
				var err error
				if isReceiver {
					msg, err = recv(seq, roundPeers[j])
					if err != nil {
						return err
					}
				}

				next, err := participants[j].Next(msg)
				if err != nil {
					return err
				}

				err = send(seq, roundPeers[j], next)
				if err != nil {
					return err
				}

				if !isReceiver {
					msg, err = recv(seq, roundPeers[j])
					if err != nil {
						return err
					}
				}
				seq++
			}

			return nil
		})
	}

	if err := eg.Wait(); err != nil {
		return nil, errors.Wrap(err, "process round")
	}

	sums := make([]curves.Scalar, len(secrets))
	for j := range sums {
		sums[j] = curve.Scalar.Zero()
	}

	for _, participant := range participants {
		scalars := participant.GetScalars()
		for j := range sums {
			sums[j] = sums[j].Add(scalars[j])
		}
	}

	return sums, nil
}

func GetPairings(i []byte, round int, peers [][]byte, peerIdks []curves.Point) (
	[][]byte,
	[]curves.Point,
	bool,
) {
	n := len(peers)
	index := -1

	for j := 0; j < n; j++ {
		if bytes.Equal([]byte(peers[j]), []byte(i)) {
			index = j + 1
			break
		}
	}

	if index < 1 || index > n {
		return nil, nil, false // invalid input
	}

	power := uint64(n) >> round
	if power == 0 {
		return nil, nil, false // rounds exceeded
	}

	// Find the size of the subset for this round
	subsetSize := 1 << (round - 1)

	// Determine the subset that i belongs to
	subsetIndex := (index - 1) / subsetSize

	// If subsetIndex is odd, i's pairings are in the subset before it
	// If subsetIndex is even, i's pairings are in the subset after it
	complementarySubsetStart := 0
	if subsetIndex%2 == 0 {
		complementarySubsetStart = (subsetIndex+1)*subsetSize + 1
	} else {
		complementarySubsetStart = subsetIndex*subsetSize - subsetSize + 1
	}

	// Generate the pairings
	pairings := make([][]byte, subsetSize)
	idks := make([]curves.Point, subsetSize)
	for j := 0; j < subsetSize; j++ {
		pairings[j] = peers[complementarySubsetStart+j-1]
		idks[j] = peerIdks[complementarySubsetStart+j-1]
	}

	return pairings, idks, (index - 1) < complementarySubsetStart
}
