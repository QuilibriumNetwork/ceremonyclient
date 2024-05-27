package crypto

import (
	"crypto"

	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
	"source.quilibrium.com/quilibrium/monorepo/node/tries"
)

type FrameProver interface {
	ProveMasterClockFrame(
		previousFrame *protobufs.ClockFrame,
		timestamp int64,
		difficulty uint32,
	) (*protobufs.ClockFrame, error)
	ProveDataClockFrame(
		previousFrame *protobufs.ClockFrame,
		commitments [][]byte,
		aggregateProofs []*protobufs.InclusionAggregateProof,
		provingKey crypto.Signer,
		timestamp int64,
		difficulty uint32,
	) (*protobufs.ClockFrame, error)
	CreateMasterGenesisFrame(
		filter []byte,
		seed []byte,
		difficulty uint32,
	) (*protobufs.ClockFrame, error)
	CreateDataGenesisFrame(
		filter []byte,
		origin []byte,
		difficulty uint32,
		inclusionProof *InclusionAggregateProof,
		proverKeys [][]byte,
		preDusk bool,
	) (*protobufs.ClockFrame, *tries.RollingFrecencyCritbitTrie, error)
	VerifyMasterClockFrame(
		frame *protobufs.ClockFrame,
	) error
	VerifyDataClockFrame(
		frame *protobufs.ClockFrame,
	) error
	GenerateWeakRecursiveProofIndex(
		frame *protobufs.ClockFrame,
	) (uint64, error)
	FetchRecursiveProof(
		frame *protobufs.ClockFrame,
	) []byte
	VerifyWeakRecursiveProof(
		frame *protobufs.ClockFrame,
		proof []byte,
		deepVerifier *protobufs.ClockFrame,
	) bool
	CalculateChallengeProof(
		challenge []byte,
		parallelism uint32,
		skew int64,
	) (int64, [][]byte, int64, error)
	VerifyChallengeProof(
		challenge []byte,
		timestamp int64,
		assertedDifficulty int64,
		proof [][]byte,
	) bool
}
