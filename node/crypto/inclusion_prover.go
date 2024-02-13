package crypto

import "source.quilibrium.com/quilibrium/monorepo/node/protobufs"

type InclusionCommitment struct {
	TypeUrl    string
	Data       []byte
	Commitment []byte
}

type InclusionAggregateProof struct {
	InclusionCommitments []*InclusionCommitment
	AggregateCommitment  []byte
	Proof                []byte
}

type InclusionProver interface {
	Commit(
		data []byte,
		typeUrl string,
	) (*InclusionCommitment, error)
	ProveAggregate(commits []*InclusionCommitment) (
		*InclusionAggregateProof,
		error,
	)
	VerifyAggregate(proof *InclusionAggregateProof) (bool, error)
	VerifyFrame(frame *protobufs.ClockFrame) error
}
