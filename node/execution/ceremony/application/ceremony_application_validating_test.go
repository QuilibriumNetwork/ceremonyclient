package application

import (
	"crypto"
	"crypto/rand"
	"testing"

	"github.com/cloudflare/circl/sign/ed448"
	"github.com/stretchr/testify/require"
	"source.quilibrium.com/quilibrium/monorepo/nekryptology/pkg/core/curves"
	bls48581 "source.quilibrium.com/quilibrium/monorepo/nekryptology/pkg/core/curves/native/bls48581"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
)

func TestApplyTranscript(t *testing.T) {
	old := curves.BLS48581G1().Scalar.Random(rand.Reader)
	old2 := old.Mul(old)
	old3 := old2.Mul(old)
	tau := curves.BLS48581G1().Scalar.Random(rand.Reader)
	tau2 := tau.Mul(tau)
	tau3 := tau2.Mul(tau)
	tauPubG2 := curves.BLS48581G2().Point.Generator().Mul(tau)

	proverPubKey, proverKey, err := ed448.GenerateKey(rand.Reader)
	require.NoError(t, err)
	proverSig, err := proverKey.Sign(
		rand.Reader,
		tauPubG2.ToAffineCompressed(),
		crypto.Hash(0),
	)
	require.NoError(t, err)

	blsSignature := make([]byte, int(bls48581.MODBYTES)+1)
	key := tau.Bytes()

	for i, j := 0, len(key)-1; i < j; i, j = i+1, j-1 {
		key[i], key[j] = key[j], key[i]
	}

	if bls48581.Core_Sign(blsSignature, proverKey, key) != bls48581.BLS_OK {
		require.Fail(t, "could not sign")
	}

	blsSig := blsSignature[:]
	updatedTranscript := &protobufs.CeremonyTranscript{
		G1Powers: []*protobufs.BLS48581G1PublicKey{
			{
				KeyValue: curves.BLS48581G1().Point.Generator().ToAffineCompressed(),
			},
			{
				KeyValue: curves.BLS48581G1().Point.Generator().Mul(
					old,
				).Mul(tau).ToAffineCompressed(),
			},
			{
				KeyValue: curves.BLS48581G1().Point.Generator().Mul(
					old2,
				).Mul(tau2).ToAffineCompressed(),
			},
			{
				KeyValue: curves.BLS48581G1().Point.Generator().Mul(
					old3,
				).Mul(tau3).ToAffineCompressed(),
			},
		},
		G2Powers: []*protobufs.BLS48581G2PublicKey{
			{
				KeyValue: curves.BLS48581G2().Point.Generator().ToAffineCompressed(),
			},
			{
				KeyValue: curves.BLS48581G2().Point.Generator().Mul(
					old,
				).Mul(tau).ToAffineCompressed(),
			},
		},
		RunningG1_256Witnesses: []*protobufs.BLS48581G1PublicKey{
			{
				KeyValue: curves.BLS48581G1().Point.Generator().ToAffineCompressed(),
			},
			{
				KeyValue: curves.BLS48581G1().Point.Generator().Mul(
					tau,
				).ToAffineCompressed(),
			},
		},
		RunningG2_256Powers: []*protobufs.BLS48581G2PublicKey{
			{
				KeyValue: curves.BLS48581G2().Point.Generator().Mul(
					old,
				).ToAffineCompressed(),
			},
			{
				KeyValue: curves.BLS48581G2().Point.Generator().Mul(
					old,
				).Mul(tau).ToAffineCompressed(),
			},
		},
	}

	a := &CeremonyApplication{
		StateCount: 0,
		RoundCount: 0,
		LobbyState: CEREMONY_APPLICATION_STATE_VALIDATING,
		FinalCommits: []*protobufs.CeremonyTranscriptCommit{
			{
				ProverSignature: &protobufs.Ed448Signature{
					Signature: proverSig,
					PublicKey: &protobufs.Ed448PublicKey{
						KeyValue: proverPubKey,
					},
				},
				ContributionSignature: &protobufs.BLS48581Signature{
					Signature: blsSig,
					PublicKey: &protobufs.BLS48581G2PublicKey{
						KeyValue: tauPubG2.ToAffineCompressed(),
					},
				},
			},
		},
		LatestTranscript: &protobufs.CeremonyTranscript{
			G1Powers: []*protobufs.BLS48581G1PublicKey{
				{
					KeyValue: curves.BLS48581G1().Point.Generator().ToAffineCompressed(),
				},
				{
					KeyValue: curves.BLS48581G1().Point.Generator().Mul(
						old,
					).ToAffineCompressed(),
				},
				{
					KeyValue: curves.BLS48581G1().Point.Generator().Mul(
						old2,
					).ToAffineCompressed(),
				},
				{
					KeyValue: curves.BLS48581G1().Point.Generator().Mul(
						old3,
					).ToAffineCompressed(),
				},
			},
			G2Powers: []*protobufs.BLS48581G2PublicKey{
				{
					KeyValue: curves.BLS48581G2().Point.Generator().ToAffineCompressed(),
				},
				{
					KeyValue: curves.BLS48581G2().Point.Generator().Mul(
						old,
					).ToAffineCompressed(),
				},
			},
			RunningG1_256Witnesses: []*protobufs.BLS48581G1PublicKey{
				{
					KeyValue: curves.BLS48581G1().Point.Generator().ToAffineCompressed(),
				},
			},
			RunningG2_256Powers: []*protobufs.BLS48581G2PublicKey{
				{
					KeyValue: curves.BLS48581G2().Point.Generator().Mul(
						old,
					).ToAffineCompressed(),
				},
			},
		},
		UpdatedTranscript: updatedTranscript,
	}

	err = a.applyTranscript(updatedTranscript)
	require.NoError(t, err)
}

func TestApplyRewritingTranscriptFails(t *testing.T) {
	old := curves.BLS48581G1().Scalar.Random(rand.Reader)
	old2 := old.Mul(old)
	old3 := old2.Mul(old)
	tau := curves.BLS48581G1().Scalar.Random(rand.Reader)
	tau2 := tau.Mul(tau)
	tau3 := tau2.Mul(tau)
	tauPubG2 := curves.BLS48581G2().Point.Generator().Mul(tau)

	proverPubKey, proverKey, err := ed448.GenerateKey(rand.Reader)
	require.NoError(t, err)
	proverSig, err := proverKey.Sign(
		rand.Reader,
		tauPubG2.ToAffineCompressed(),
		crypto.Hash(0),
	)
	require.NoError(t, err)

	blsSignature := make([]byte, int(bls48581.MODBYTES)+1)
	key := tau.Bytes()

	for i, j := 0, len(key)-1; i < j; i, j = i+1, j-1 {
		key[i], key[j] = key[j], key[i]
	}

	if bls48581.Core_Sign(blsSignature, proverKey, key) != bls48581.BLS_OK {
		require.Fail(t, "could not sign")
	}

	blsSig := blsSignature[:]
	updatedTranscript := &protobufs.CeremonyTranscript{
		G1Powers: []*protobufs.BLS48581G1PublicKey{
			{
				KeyValue: curves.BLS48581G1().Point.Generator().ToAffineCompressed(),
			},
			{
				KeyValue: curves.BLS48581G1().Point.Generator().Mul(
					tau,
				).ToAffineCompressed(),
			},
			{
				KeyValue: curves.BLS48581G1().Point.Generator().Mul(
					tau2,
				).ToAffineCompressed(),
			},
			{
				KeyValue: curves.BLS48581G1().Point.Generator().Mul(
					tau3,
				).ToAffineCompressed(),
			},
		},
		G2Powers: []*protobufs.BLS48581G2PublicKey{
			{
				KeyValue: curves.BLS48581G2().Point.Generator().ToAffineCompressed(),
			},
			{
				KeyValue: curves.BLS48581G2().Point.Generator().Mul(
					tau,
				).ToAffineCompressed(),
			},
		},
		// Pretend we're accumulating still
		RunningG1_256Witnesses: []*protobufs.BLS48581G1PublicKey{
			{
				KeyValue: curves.BLS48581G1().Point.Generator().ToAffineCompressed(),
			},
			{
				KeyValue: curves.BLS48581G1().Point.Generator().Mul(
					tau,
				).ToAffineCompressed(),
			},
		},
		RunningG2_256Powers: []*protobufs.BLS48581G2PublicKey{
			{
				KeyValue: curves.BLS48581G2().Point.Generator().Mul(
					old,
				).ToAffineCompressed(),
			},
			{
				KeyValue: curves.BLS48581G2().Point.Generator().Mul(
					old,
				).Mul(tau).ToAffineCompressed(),
			},
		},
	}

	a := &CeremonyApplication{
		StateCount: 0,
		RoundCount: 0,
		LobbyState: CEREMONY_APPLICATION_STATE_VALIDATING,
		FinalCommits: []*protobufs.CeremonyTranscriptCommit{
			{
				ProverSignature: &protobufs.Ed448Signature{
					Signature: proverSig,
					PublicKey: &protobufs.Ed448PublicKey{
						KeyValue: proverPubKey,
					},
				},
				ContributionSignature: &protobufs.BLS48581Signature{
					Signature: blsSig,
					PublicKey: &protobufs.BLS48581G2PublicKey{
						KeyValue: tauPubG2.ToAffineCompressed(),
					},
				},
			},
		},
		LatestTranscript: &protobufs.CeremonyTranscript{
			G1Powers: []*protobufs.BLS48581G1PublicKey{
				{
					KeyValue: curves.BLS48581G1().Point.Generator().ToAffineCompressed(),
				},
				{
					KeyValue: curves.BLS48581G1().Point.Generator().Mul(
						old,
					).ToAffineCompressed(),
				},
				{
					KeyValue: curves.BLS48581G1().Point.Generator().Mul(
						old2,
					).ToAffineCompressed(),
				},
				{
					KeyValue: curves.BLS48581G1().Point.Generator().Mul(
						old3,
					).ToAffineCompressed(),
				},
			},
			G2Powers: []*protobufs.BLS48581G2PublicKey{
				{
					KeyValue: curves.BLS48581G2().Point.Generator().ToAffineCompressed(),
				},
				{
					KeyValue: curves.BLS48581G2().Point.Generator().Mul(
						old,
					).ToAffineCompressed(),
				},
			},
			RunningG1_256Witnesses: []*protobufs.BLS48581G1PublicKey{
				{
					KeyValue: curves.BLS48581G1().Point.Generator().ToAffineCompressed(),
				},
			},
			RunningG2_256Powers: []*protobufs.BLS48581G2PublicKey{
				{
					KeyValue: curves.BLS48581G2().Point.Generator().Mul(
						old,
					).ToAffineCompressed(),
				},
			},
		},
		UpdatedTranscript: updatedTranscript,
	}

	err = a.applyTranscript(updatedTranscript)
	require.NoError(t, err)
}
