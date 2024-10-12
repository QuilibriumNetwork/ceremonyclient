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
	VerifyFrame(frame *protobufs.ClockFrame) error
	CommitRaw(
		data []byte,
		polySize uint64,
	) ([]byte, error)
	ProveRaw(
		data []byte,
		index int,
		polySize uint64,
	) ([]byte, error)
	VerifyRaw(
		data []byte,
		commit []byte,
		index int,
		proof []byte,
		polySize uint64,
	) (bool, error)
}
