package application

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"testing"

	"github.com/cloudflare/circl/sign/ed448"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"source.quilibrium.com/quilibrium/monorepo/nekryptology/pkg/core/curves"
	bls48581 "source.quilibrium.com/quilibrium/monorepo/nekryptology/pkg/core/curves/native/bls48581"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/node/tries"
)

func TestCeremonyTransitions(t *testing.T) {
	bls48581.Init()
	old := curves.BLS48581G1().Scalar.Random(rand.Reader)
	old2 := old.Mul(old)
	old3 := old2.Mul(old)

	proverPubKey, proverKey, err := ed448.GenerateKey(rand.Reader)
	require.NoError(t, err)
	idk := curves.ED448().Scalar.Random(rand.Reader)
	idkPub := curves.ED448().Point.Generator().Mul(idk).ToAffineCompressed()
	spk := curves.ED448().Scalar.Random(rand.Reader)
	spkPub := curves.ED448().Point.Generator().Mul(spk).ToAffineCompressed()
	require.NoError(t, err)

	trie := &tries.RewardCritbitTrie{}

	a := &CeremonyApplication{
		RewardTrie: trie,
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
	}

	join := &protobufs.CeremonyLobbyJoin{
		FrameNumber: 0,
		IdentityKey: &protobufs.X448PublicKey{
			KeyValue: idkPub,
		},
		SignedPreKey: &protobufs.X448PublicKey{
			KeyValue: spkPub,
		},
		PeerId: []byte{},
	}
	sig, err := join.SignWithProverKey(proverKey)
	require.NoError(t, err)
	join.PublicKeySignatureEd448 = &protobufs.Ed448Signature{
		Signature: sig,
		PublicKey: &protobufs.Ed448PublicKey{
			KeyValue: proverPubKey,
		},
	}
	joinBytes, err := proto.Marshal(join)
	require.NoError(t, err)

	a, _, _, err = a.ApplyTransition(0, &protobufs.CeremonyLobbyStateTransition{
		TypeUrls:         []string{protobufs.CeremonyLobbyJoinType},
		TransitionInputs: [][]byte{joinBytes},
	}, false)
	require.NoError(t, err)
	require.Equal(t, a.LobbyState, CEREMONY_APPLICATION_STATE_OPEN)

	for i := uint64(0); i < 10; i++ {
		a, _, _, err = a.ApplyTransition(i+1, &protobufs.CeremonyLobbyStateTransition{
			TypeUrls:         []string{},
			TransitionInputs: [][]byte{},
		}, false)
		require.NoError(t, err)
		require.Equal(t, a.LobbyState, CEREMONY_APPLICATION_STATE_OPEN)
	}

	a, _, _, err = a.ApplyTransition(12, &protobufs.CeremonyLobbyStateTransition{
		TypeUrls:         []string{},
		TransitionInputs: [][]byte{},
	}, false)
	require.NoError(t, err)
	require.Equal(t, a.LobbyState, CEREMONY_APPLICATION_STATE_IN_PROGRESS)
	require.True(t, bytes.Equal(
		a.ActiveParticipants[0].PublicKeySignatureEd448.PublicKey.KeyValue,
		proverPubKey,
	))

	tau := curves.BLS48581G1().Scalar.Random(rand.Reader)
	tau2 := tau.Mul(tau)
	tau3 := tau2.Mul(tau)
	tauPubG2 := curves.BLS48581G2().Point.Generator().Mul(tau)

	proverSig, err := proverKey.Sign(
		rand.Reader,
		tauPubG2.ToAffineCompressed(),
		crypto.Hash(0),
	)
	require.NoError(t, err)

	blsSignature := make([]byte, int(bls48581.MODBYTES)+1)
	key := tau.Bytes()

	if bls48581.Core_Sign(blsSignature, proverPubKey, key) != bls48581.BLS_OK {
		require.Fail(t, "could not sign")
	}

	blsSig := blsSignature[:]

	advanceRound := &protobufs.CeremonyTranscriptCommit{
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
	}
	advanceRoundBytes, err := proto.Marshal(advanceRound)

	require.NoError(t, err)
	a, _, _, err = a.ApplyTransition(13, &protobufs.CeremonyLobbyStateTransition{
		TypeUrls:         []string{protobufs.CeremonyTranscriptCommitType},
		TransitionInputs: [][]byte{advanceRoundBytes},
	}, false)
	require.NoError(t, err)
	require.Equal(t, a.LobbyState, CEREMONY_APPLICATION_STATE_FINALIZING)

	g1 := curves.BLS48581G1().Point.Generator()
	g2 := curves.BLS48581G2().Point.Generator()
	transcriptShare := &protobufs.CeremonyTranscriptShare{
		AdditiveG1Powers: []*protobufs.BLS48581G1PublicKey{
			{
				KeyValue: g1.Mul(old.Mul(tau)).ToAffineCompressed(),
			},
			{
				KeyValue: g1.Mul(old2.Mul(tau2)).ToAffineCompressed(),
			},
			{
				KeyValue: g1.Mul(old3.Mul(tau3)).ToAffineCompressed(),
			},
		},
		AdditiveG2Powers: []*protobufs.BLS48581G2PublicKey{
			{
				KeyValue: g2.Mul(old.Mul(tau)).ToAffineCompressed(),
			},
		},
		AdditiveG1_256Witness: &protobufs.BLS48581G1PublicKey{
			KeyValue: g1.Mul(tau).ToAffineCompressed(),
		},
		AdditiveG2_256Witness: &protobufs.BLS48581G2PublicKey{
			KeyValue: g2.Mul(old.Mul(tau)).ToAffineCompressed(),
		},
	}
	sig, err = transcriptShare.SignWithProverKey(proverKey)
	require.NoError(t, err)
	transcriptShare.ProverSignature = &protobufs.Ed448Signature{
		Signature: sig,
		PublicKey: &protobufs.Ed448PublicKey{
			KeyValue: proverPubKey,
		},
	}
	shareBytes, err := proto.Marshal(transcriptShare)
	require.NoError(t, err)

	a, _, _, err = a.ApplyTransition(14, &protobufs.CeremonyLobbyStateTransition{
		TypeUrls:         []string{protobufs.CeremonyTranscriptShareType},
		TransitionInputs: [][]byte{shareBytes},
	}, false)
	require.NoError(t, err)
	require.Equal(t, a.LobbyState, CEREMONY_APPLICATION_STATE_VALIDATING)

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
	transcriptBytes, err := proto.Marshal(updatedTranscript)
	require.NoError(t, err)
	a, _, _, err = a.ApplyTransition(15, &protobufs.CeremonyLobbyStateTransition{
		TypeUrls:         []string{protobufs.CeremonyTranscriptType},
		TransitionInputs: [][]byte{transcriptBytes},
	}, false)
	require.NoError(t, err)
	require.Equal(t, a.LobbyState, CEREMONY_APPLICATION_STATE_OPEN)
	bi, err := poseidon.HashBytes(proverPubKey)
	require.NoError(t, err)
	addr := bi.FillBytes(make([]byte, 32))
	_, f, reward := a.RewardTrie.Get(addr)
	require.Equal(t, f, uint64(15))
	require.Equal(t, reward, uint64(161))
}
