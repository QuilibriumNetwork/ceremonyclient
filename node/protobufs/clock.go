package protobufs

import (
	"math/big"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/pkg/errors"
)

func (frame *ClockFrame) GetParentAndSelector() (
	*big.Int,
	*big.Int,
	error,
) {
	outputBytes := [516]byte{}
	copy(outputBytes[:], frame.Output[:516])

	selector, err := poseidon.HashBytes(outputBytes[:])
	if err != nil {
		return nil, nil, errors.Wrap(err, "get parent selector and distance")
	}

	if frame.FrameNumber == 0 {
		return big.NewInt(0), selector, nil
	}

	parentSelector := new(big.Int).SetBytes(frame.ParentSelector)

	return parentSelector, selector, nil
}

func (frame *ClockFrame) GetSelector() (*big.Int, error) {
	outputBytes := [516]byte{}
	copy(outputBytes[:], frame.Output[:516])

	selector, err := poseidon.HashBytes(outputBytes[:])
	if err != nil {
		return nil, errors.Wrap(err, "get selector")
	}

	return selector, nil
}

func (frame *ClockFrame) GetPublicKey() ([]byte, error) {
	if frame.FrameNumber == 0 {
		return make([]byte, 32), nil
	}
	var pubkey []byte
	ed448PublicKey := frame.GetPublicKeySignatureEd448()
	if ed448PublicKey != nil {
		pubkey = ed448PublicKey.PublicKey.KeyValue
	} else {
		return nil, errors.Wrap(
			errors.New("no valid signature provided"),
			"get address",
		)
	}

	return pubkey, nil
}

func (frame *ClockFrame) GetAddress() ([]byte, error) {
	if frame.FrameNumber == 0 {
		return make([]byte, 32), nil
	}
	var pubkey []byte
	ed448PublicKey := frame.GetPublicKeySignatureEd448()
	if ed448PublicKey != nil {
		pubkey = ed448PublicKey.PublicKey.KeyValue
	} else {
		return nil, errors.Wrap(
			errors.New("no valid signature provided"),
			"get address",
		)
	}

	address, err := poseidon.HashBytes(pubkey)
	if err != nil {
		return nil, errors.Wrap(err, "get parent selector and distance")
	}
	addressBytes := address.Bytes()
	addressBytes = append(make([]byte, 32-len(addressBytes)), addressBytes...)

	return addressBytes, nil
}
