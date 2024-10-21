package application

import (
	"bytes"
	"math/big"

	"github.com/iden3/go-iden3-crypto/poseidon"
	pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
)

func (a *TokenApplication) handleSplit(
	currentFrameNumber uint64,
	lockMap map[string]struct{},
	t *protobufs.SplitCoinRequest,
) ([]*protobufs.TokenOutput, error) {
	newCoins := []*protobufs.Coin{}
	newAmounts := []*big.Int{}
	payload := []byte{}
	if t.Signature.PublicKey == nil ||
		t.Signature.Signature == nil ||
		t.OfCoin == nil ||
		t.OfCoin.Address == nil {
		return nil, ErrInvalidStateTransition
	}
	coin, err := a.CoinStore.GetCoinByAddress(nil, t.OfCoin.Address)
	if err != nil {
		return nil, ErrInvalidStateTransition
	}

	if _, touched := lockMap[string(t.OfCoin.Address)]; touched {
		return nil, ErrInvalidStateTransition
	}

	payload = append(payload, []byte("split")...)
	payload = append(payload, t.OfCoin.Address...)
	for _, a := range t.Amounts {
		if len(a) > 32 {
			return nil, ErrInvalidStateTransition
		}
		payload = append(payload, a...)
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

	if !bytes.Equal(
		coin.Owner.GetImplicitAccount().Address,
		addr.FillBytes(make([]byte, 32)),
	) && !bytes.Equal(
		coin.Owner.GetImplicitAccount().Address,
		altAddr.FillBytes(make([]byte, 32)),
	) {
		return nil, ErrInvalidStateTransition
	}

	original := new(big.Int).SetBytes(coin.Amount)
	amounts := t.Amounts
	total := new(big.Int)
	for _, amount := range amounts {
		amountBI := new(big.Int).SetBytes(amount)
		if amountBI.Cmp(original) >= 0 {
			return nil, ErrInvalidStateTransition
		}

		newAmounts = append(newAmounts, amountBI)
		total.Add(total, amountBI)
		newCoins = append(newCoins, &protobufs.Coin{
			Amount:       amountBI.FillBytes(make([]byte, 32)),
			Owner:        coin.Owner,
			Intersection: coin.Intersection,
		})
	}
	if original.Cmp(total) != 0 {
		return nil, ErrInvalidStateTransition
	}

	outputs := []*protobufs.TokenOutput{}
	for _, c := range newCoins {
		outputs = append(outputs, &protobufs.TokenOutput{
			Output: &protobufs.TokenOutput_Coin{
				Coin: c,
			},
		})
	}

	outputs = append(
		outputs,
		&protobufs.TokenOutput{
			Output: &protobufs.TokenOutput_DeletedCoin{
				DeletedCoin: t.OfCoin,
			},
		},
	)

	lockMap[string(t.OfCoin.Address)] = struct{}{}

	return outputs, nil
}
