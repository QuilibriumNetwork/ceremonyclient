package store

import (
	"bytes"
	"encoding/binary"

	"github.com/cockroachdb/pebble"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
	"source.quilibrium.com/quilibrium/monorepo/node/protobufs"
)

type CoinStore interface {
	NewTransaction() (Transaction, error)
	GetCoinsForOwner(owner []byte) ([]uint64, []*protobufs.Coin, error)
	GetPreCoinProofsForOwner(owner []byte) (
		[]uint64,
		[]*protobufs.PreCoinProof,
		error,
	)
	GetCoinByAddress(address []byte) (*protobufs.Coin, error)
	GetPreCoinProofByAddress(address []byte) (*protobufs.PreCoinProof, error)
	PutCoin(
		txn Transaction,
		frameNumber uint64,
		address []byte,
		coin *protobufs.Coin,
	) error
	DeleteCoin(
		txn Transaction,
		address []byte,
		coin *protobufs.Coin,
	) error
	PutPreCoinProof(
		txn Transaction,
		frameNumber uint64,
		address []byte,
		preCoinProof *protobufs.PreCoinProof,
	) error
	DeletePreCoinProof(
		txn Transaction,
		address []byte,
		preCoinProof *protobufs.PreCoinProof,
	) error
}

var _ CoinStore = (*PebbleCoinStore)(nil)

type PebbleCoinStore struct {
	db     KVDB
	logger *zap.Logger
}

func NewPebbleCoinStore(
	db KVDB,
	logger *zap.Logger,
) *PebbleCoinStore {
	return &PebbleCoinStore{
		db,
		logger,
	}
}

const (
	COIN            = 0x05
	PROOF           = 0x06
	COIN_BY_ADDRESS = 0x00
	COIN_BY_OWNER   = 0x01
)

func coinKey(address []byte) []byte {
	key := []byte{COIN, COIN_BY_ADDRESS}
	key = append(key, address...)
	return key
}

func coinByOwnerKey(owner []byte, address []byte) []byte {
	key := []byte{COIN, COIN_BY_OWNER}
	key = append(key, owner...)
	key = append(key, address...)
	return key
}

func proofKey(address []byte) []byte {
	key := []byte{PROOF, COIN_BY_ADDRESS}
	key = append(key, address...)
	return key
}

func proofByOwnerKey(owner []byte, address []byte) []byte {
	key := []byte{PROOF, COIN_BY_OWNER}
	key = append(key, owner...)
	key = append(key, address...)
	return key
}

func (p *PebbleCoinStore) NewTransaction() (Transaction, error) {
	return p.db.NewBatch(), nil
}

func (p *PebbleCoinStore) GetCoinsForOwner(
	owner []byte,
) ([]uint64, []*protobufs.Coin, error) {
	iter, err := p.db.NewIter(
		coinByOwnerKey(owner, bytes.Repeat([]byte{0x00}, 32)),
		coinByOwnerKey(owner, bytes.Repeat([]byte{0xff}, 32)),
	)
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			err = ErrNotFound
			return nil, nil, err
		}
		err = errors.Wrap(err, "get coins for owner")
		return nil, nil, err
	}

	defer iter.Close()
	frameNumbers := []uint64{}
	coins := []*protobufs.Coin{}
	for iter.First(); iter.Valid(); iter.Next() {
		coinBytes := iter.Value()
		frameNumber := binary.BigEndian.Uint64(coinBytes[:8])
		coin := &protobufs.Coin{}
		err := proto.Unmarshal(coinBytes[8:], coin)
		if err != nil {
			return nil, nil, errors.Wrap(err, "get coins for owner")
		}
		frameNumbers = append(frameNumbers, frameNumber)
		coins = append(coins, coin)
	}

	return frameNumbers, coins, nil
}

func (p *PebbleCoinStore) GetPreCoinProofsForOwner(owner []byte) (
	[]uint64,
	[]*protobufs.PreCoinProof,
	error,
) {
	iter, err := p.db.NewIter(
		proofByOwnerKey(owner, bytes.Repeat([]byte{0x00}, 32)),
		proofByOwnerKey(owner, bytes.Repeat([]byte{0xff}, 32)),
	)
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			err = ErrNotFound
			return nil, nil, err
		}
		err = errors.Wrap(err, "get pre coin proofs for owner")
		return nil, nil, err
	}

	defer iter.Close()
	frameNumbers := []uint64{}
	proofs := []*protobufs.PreCoinProof{}
	for iter.First(); iter.Valid(); iter.Next() {
		proofBytes := iter.Value()
		frameNumber := binary.BigEndian.Uint64(proofBytes[:8])
		proof := &protobufs.PreCoinProof{}
		err := proto.Unmarshal(proofBytes[8:], proof)
		if err != nil {
			return nil, nil, errors.Wrap(err, "get pre coin proofs for owner")
		}
		frameNumbers = append(frameNumbers, frameNumber)
		proofs = append(proofs, proof)
	}

	return frameNumbers, proofs, nil
}

func (p *PebbleCoinStore) GetCoinByAddress(address []byte) (
	*protobufs.Coin,
	error,
) {
	coinBytes, closer, err := p.db.Get(coinKey(address))
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			err = ErrNotFound
			return nil, err
		}
		err = errors.Wrap(err, "get coin by address")
		return nil, err
	}

	defer closer.Close()

	coin := &protobufs.Coin{}
	err = proto.Unmarshal(coinBytes[:8], coin)
	if err != nil {
		return nil, errors.Wrap(err, "get coin by address")
	}

	return coin, nil
}

func (p *PebbleCoinStore) GetPreCoinProofByAddress(address []byte) (
	*protobufs.PreCoinProof,
	error,
) {
	preCoinProofBytes, closer, err := p.db.Get(proofKey(address))
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			err = ErrNotFound
			return nil, err
		}
		err = errors.Wrap(err, "get pre coin proof by address")
		return nil, err
	}

	defer closer.Close()

	proof := &protobufs.PreCoinProof{}
	err = proto.Unmarshal(preCoinProofBytes[:8], proof)
	if err != nil {
		return nil, errors.Wrap(err, "get pre coin proof by address")
	}

	return proof, nil
}

func (p *PebbleCoinStore) PutCoin(
	txn Transaction,
	frameNumber uint64,
	address []byte,
	coin *protobufs.Coin,
) error {
	coinBytes, err := proto.Marshal(coin)
	if err != nil {
		return errors.Wrap(err, "put coin")
	}

	data := []byte{}
	data = binary.BigEndian.AppendUint64(data, frameNumber)
	data = append(data, coinBytes...)
	err = txn.Set(
		coinByOwnerKey(coin.Owner.GetImplicitAccount().Address, address),
		data,
	)
	if err != nil {
		return errors.Wrap(err, "put coin")
	}

	err = txn.Set(
		coinKey(coin.Owner.GetImplicitAccount().Address),
		data,
	)
	if err != nil {
		return errors.Wrap(err, "put coin")
	}

	return nil
}

func (p *PebbleCoinStore) DeleteCoin(
	txn Transaction,
	address []byte,
	coin *protobufs.Coin,
) error {
	err := txn.Delete(coinKey(address))
	if err != nil {
		return errors.Wrap(err, "delete coin")
	}

	err = txn.Delete(
		coinByOwnerKey(coin.Owner.GetImplicitAccount().GetAddress(), address),
	)
	if err != nil {
		return errors.Wrap(err, "delete coin")
	}

	return nil
}

func (p *PebbleCoinStore) PutPreCoinProof(
	txn Transaction,
	frameNumber uint64,
	address []byte,
	preCoinProof *protobufs.PreCoinProof,
) error {
	proofBytes, err := proto.Marshal(preCoinProof)
	if err != nil {
		return errors.Wrap(err, "put pre coin proof")
	}

	data := []byte{}
	data = binary.BigEndian.AppendUint64(data, frameNumber)
	data = append(data, proofBytes...)
	err = txn.Set(
		proofByOwnerKey(preCoinProof.Owner.GetImplicitAccount().Address, address),
		data,
	)
	if err != nil {
		return errors.Wrap(err, "put pre coin proof")
	}

	err = txn.Set(
		proofKey(preCoinProof.Owner.GetImplicitAccount().Address),
		data,
	)
	if err != nil {
		return errors.Wrap(err, "put pre coin proof")
	}

	return nil
}

func (p *PebbleCoinStore) DeletePreCoinProof(
	txn Transaction,
	address []byte,
	preCoinProof *protobufs.PreCoinProof,
) error {
	err := txn.Delete(proofKey(address))
	if err != nil {
		return errors.Wrap(err, "delete pre coin proof")
	}

	err = txn.Delete(
		proofByOwnerKey(
			preCoinProof.Owner.GetImplicitAccount().GetAddress(),
			address,
		),
	)
	if err != nil {
		return errors.Wrap(err, "delete pre coin proof")
	}

	return nil
}
