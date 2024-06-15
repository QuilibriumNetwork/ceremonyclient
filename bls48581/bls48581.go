package bls48581

import (
	generated "source.quilibrium.com/quilibrium/monorepo/bls48581/generated/bls48581"
)

//go:generate ./generate.sh

func Init() {
	generated.Init()
}

func CommitRaw(data []byte, polySize uint64) []byte {
	return generated.CommitRaw(data, polySize)
}

func ProveRaw(data []byte, index uint64, polySize uint64) []byte {
	return generated.ProveRaw(data, index, polySize)
}

func VerifyRaw(data []byte, commit []byte, index uint64, proof []byte, polySize uint64) bool {
	return generated.VerifyRaw(data, commit, index, proof, polySize)
}
