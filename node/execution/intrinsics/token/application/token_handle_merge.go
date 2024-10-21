package application

import (
	"bytes"
	"math/big"

	"github.com/iden3/go-iden3-crypto/poseidon"
	pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
)

func (a *TokenApplication) handleMerge(
	currentFrameNumber uint64,
	lockMap map[string]struct{},
	t *protobufs.MergeCoinRequest,
) ([]*protobufs.TokenOutput, error) {
	newCoin := &protobufs.Coin{}
	newTotal := new(big.Int)
	newIntersection := make([]byte, 1024)
	payload := []byte("merge")
	if t == nil || t.Coins == nil || t.Signature == nil {
		return nil, ErrInvalidStateTransition
	}
	addresses := [][]byte{}
	for _, c := range t.Coins {
		if c.Address == nil {
			return nil, ErrInvalidStateTransition
		}

		if _, touched := lockMap[string(c.Address)]; touched {
			return nil, ErrInvalidStateTransition
		}

		for _, addr := range addresses {
			if bytes.Equal(addr, c.Address) {
				return nil, ErrInvalidStateTransition
			}
		}

		addresses = append(addresses, c.Address)
		payload = append(payload, c.Address...)
	}
	if t.Signature.PublicKey == nil ||
		t.Signature.Signature == nil {
		return nil, ErrInvalidStateTransition
	}
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

	owner := &protobufs.AccountRef{}
	deleted := []*protobufs.TokenOutput{}
	for _, c := range t.Coins {
		coin, err := a.CoinStore.GetCoinByAddress(nil, c.Address)
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

		newTotal.Add(newTotal, new(big.Int).SetBytes(coin.Amount))
		for i := range coin.Intersection {
			newIntersection[i] |= coin.Intersection[i]
		}
		owner = coin.Owner
		deleted = append(deleted, &protobufs.TokenOutput{
			Output: &protobufs.TokenOutput_DeletedCoin{
				DeletedCoin: c,
			},
		})
	}
	newCoin.Amount = newTotal.FillBytes(make([]byte, 32))
	newCoin.Intersection = newIntersection
	newCoin.Owner = owner
	outputs := []*protobufs.TokenOutput{
		&protobufs.TokenOutput{
			Output: &protobufs.TokenOutput_Coin{
				Coin: newCoin,
			},
		},
	}
	outputs = append(outputs, deleted...)

	for _, c := range t.Coins {
		lockMap[string(c.Address)] = struct{}{}
	}

	return outputs, nil
}
