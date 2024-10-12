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
		aggregateProofs []*protobufs.InclusionAggregateProof,
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
	) (*protobufs.ClockFrame, []*tries.RollingFrecencyCritbitTrie, error)
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
		difficulty uint32,
	) ([]byte, error)
	VerifyChallengeProof(
		challenge []byte,
		difficulty uint32,
		proof []byte,
	) bool
	VerifyPreDuskChallengeProof(
		challenge []byte,
		increment uint32,
		core uint32,
		proof []byte,
	) bool
}
