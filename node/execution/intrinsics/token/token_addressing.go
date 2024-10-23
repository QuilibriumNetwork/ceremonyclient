package token

import (
	"encoding/binary"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"source.quilibrium.com/quilibrium/monorepo/node/execution/intrinsics/token/application"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
)

func GetAddressOfCoin(
	coin *protobufs.Coin,
	frameNumber uint64,
	seqno uint64,
) ([]byte, error) {
	eval := []byte{}
	eval = append(eval, application.TOKEN_ADDRESS...)
	eval = binary.BigEndian.AppendUint64(eval, frameNumber)
	if frameNumber != 0 {
		eval = binary.BigEndian.AppendUint64(eval, seqno)
	}
	eval = append(eval, coin.Amount...)
	eval = append(eval, coin.Intersection...)
	eval = binary.BigEndian.AppendUint32(eval, 0)
	eval = append(eval, coin.Owner.GetImplicitAccount().Address...)
	addressBI, err := poseidon.HashBytes(eval)
	if err != nil {
		return nil, err
	}

	return addressBI.FillBytes(make([]byte, 32)), nil
}

func GetAddressOfPreCoinProof(
	proof *protobufs.PreCoinProof,
) ([]byte, error) {
	eval := []byte{}
	eval = append(eval, application.TOKEN_ADDRESS...)
	eval = append(eval, proof.Amount...)
	eval = binary.BigEndian.AppendUint32(eval, proof.Index)
	eval = append(eval, proof.IndexProof...)
	eval = append(eval, proof.Commitment...)
	eval = append(eval, proof.Proof...)
	eval = binary.BigEndian.AppendUint32(eval, proof.Parallelism)
	eval = binary.BigEndian.AppendUint32(eval, proof.Difficulty)
	eval = binary.BigEndian.AppendUint32(eval, 0)
	eval = append(eval, proof.Owner.GetImplicitAccount().Address...)
	addressBI, err := poseidon.HashBytes(eval)
	if err != nil {
		return nil, err
	}

	return addressBI.FillBytes(make([]byte, 32)), nil
}
