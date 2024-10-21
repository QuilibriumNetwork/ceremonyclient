package application

import (
	"bytes"

	"github.com/iden3/go-iden3-crypto/poseidon"
	pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"source.quilibrium.com/quilibrium/monorepo/node/p2p"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
)

func (a *TokenApplication) handleTransfer(
	currentFrameNumber uint64,
	lockMap map[string]struct{},
	t *protobufs.TransferCoinRequest,
) ([]*protobufs.TokenOutput, error) {
	payload := []byte("transfer")
	if t == nil || t.OfCoin == nil || t.OfCoin.Address == nil {
		return nil, ErrInvalidStateTransition
	}

	if _, touched := lockMap[string(t.OfCoin.Address)]; touched {
		return nil, ErrInvalidStateTransition
	}

	coin, err := a.CoinStore.GetCoinByAddress(nil, t.OfCoin.Address)
	if err != nil {
		return nil, ErrInvalidStateTransition
	}

	payload = append(payload, t.OfCoin.Address...)
	payload = append(
		payload,
		t.ToAccount.GetImplicitAccount().Address...,
	)

	if err := t.Signature.Verify(payload); err != nil {
		return nil, ErrInvalidStateTransition
	}

	addr, err := poseidon.HashBytes(t.Signature.PublicKey.KeyValue)
	if err != nil {
		return nil, ErrInvalidStateTransition
	}

	pk, err := pcrypto.UnmarshalEd448PublicKey(
		t.Signature.PublicKey.KeyValue,
	)
	if err != nil {
		return nil, ErrInvalidStateTransition
	}

	peerId, err := peer.IDFromPublicKey(pk)
	if err != nil {
		return nil, ErrInvalidStateTransition
	}

	altAddr, err := poseidon.HashBytes([]byte(peerId))
	if err != nil {
		return nil, ErrInvalidStateTransition
	}

	if !bytes.Equal(
		coin.Owner.GetImplicitAccount().Address,
		addr.FillBytes(make([]byte, 32)),
	) && !bytes.Equal(
		coin.Owner.GetImplicitAccount().Address,
		altAddr.FillBytes(make([]byte, 32)),
	) {
		return nil, ErrInvalidStateTransition
	}

	newIntersection := coin.Intersection
	for i, b := range p2p.GetBloomFilter(
		addr.FillBytes(make([]byte, 32)),
		1024,
		3,
	) {
		newIntersection[i] |= b
	}

	outputs := []*protobufs.TokenOutput{
		&protobufs.TokenOutput{
			Output: &protobufs.TokenOutput_Coin{
				Coin: &protobufs.Coin{
					Amount:       coin.Amount,
					Intersection: newIntersection,
					Owner:        t.ToAccount,
				},
			},
		},
		&protobufs.TokenOutput{
			Output: &protobufs.TokenOutput_DeletedCoin{
				DeletedCoin: t.OfCoin,
			},
		},
	}

	lockMap[string(t.OfCoin.Address)] = struct{}{}
	return outputs, nil
}
